# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""HTTP ingest API (Phase 1, live ingestion).

A single authenticated endpoint that accepts a raw log payload (the same text a
user would upload), runs it through the shared ingest pipeline, and returns the
batch summary as JSON. Auth is an API key presented as `X-API-Key: <key>` or
`Authorization: Bearer <key>`; only the sha256 of each key is stored.

    curl -X POST "http://host:8000/api/v1/ingest?format=auto&filename=fw.log" \
         -H "X-API-Key: lo_..." --data-binary @fw.log
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from starlette.concurrency import run_in_threadpool

from . import contentpack, db, ingest
from .config import settings
from .detect import detect_format
from .hec import router as hec_router          # re-exported; main.py mounts it on the app
from .loql import LoqlError, run_query
from .parsers import PARSERS
from .util import extract_api_key, gunzip_capped

log = logging.getLogger("logocean")
router = APIRouter(prefix="/api/v1", tags=["ingest"])

#: The Splunk HEC wire shim. Re-exported here (rather than included into `router`)
#: because its paths are ABSOLUTE — /services/collector/* — and nesting it under this
#: router's /api/v1 prefix would relocate them to /api/v1/services/collector, which no
#: HEC sender will ever call. `app/main.py` does `app.include_router(api.hec_router)`.
__all__ = ["router", "hec_router"]


def require_api_key(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
) -> dict:
    key = extract_api_key(x_api_key, authorization)
    if not key:
        raise HTTPException(status_code=401, detail="API key required")
    rec = db.verify_api_key(key)
    if rec is None:
        raise HTTPException(status_code=401, detail="invalid or disabled API key")
    return rec


async def _read_body_capped(request: Request, limit: int) -> Optional[bytes]:
    """Stream the request body in chunks, returning None if it exceeds `limit`.
    Bounds peak memory instead of buffering an arbitrarily large body first."""
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


@router.post("/ingest")
async def api_ingest(
    request: Request,
    format: str = Query("auto", description="format key, or 'auto' to detect"),
    filename: Optional[str] = Query(None, description="optional name, aids auto-detect"),
    key: dict = Depends(require_api_key),
):
    cap = settings.max_upload_mb * 1024 * 1024
    body = await _read_body_capped(request, cap)
    if body is None:
        raise HTTPException(status_code=413,
                            detail=f"payload exceeds the {settings.max_upload_mb} MB limit")
    # Transparently gunzip a gzip body (by magic bytes) under the same size budget.
    body = await run_in_threadpool(gunzip_capped, body, cap)
    if body is None:
        raise HTTPException(
            status_code=413,
            detail=f"gzip payload is corrupt or expands past the {settings.max_upload_mb} MB limit")
    content = body.decode("utf-8", "replace")
    if not content.strip():
        raise HTTPException(status_code=400, detail="empty payload")

    hint = filename[:-3] if (filename or "").endswith(".gz") else (filename or "")
    fmt = format
    if fmt == "auto":
        fmt = detect_format(hint, content)
        if fmt is None:
            raise HTTPException(status_code=422,
                                detail="could not auto-detect format; pass ?format=<key>")
    if fmt not in PARSERS:
        raise HTTPException(status_code=400, detail=f"unknown format: {fmt}")

    source_addr = request.client.host if request.client else None
    try:
        # Parsing + DB I/O is blocking and CPU-bound — keep it off the event loop.
        result = await run_in_threadpool(
            ingest.ingest, content, fmt,
            filename=filename, source_type="api", source_addr=source_addr)
    except Exception:  # noqa: BLE001
        log.exception("api ingest failed (key=%s, format=%s)", key.get("key_prefix"), fmt)
        raise HTTPException(status_code=500, detail="ingest failed; see server logs")
    return result


# --------------------------------------------------------------------------- #
#  Content packs — READ + DRY RUN only                                         #
# --------------------------------------------------------------------------- #
# WHY NO IMPORT/UNINSTALL HERE, against the builder's handoff. An `api_keys` row has
# no role: the table is (name, key_sha256, key_prefix, source_label, enabled) and
# `require_api_key` accepts any enabled key. A content pack installs DETECTION RULES
# and PARSERS, so exposing the write half on this router would let a key handed to a
# log forwarder for `POST /ingest` also rewrite the detection content — a real
# privilege escalation, and the /api/ prefix is deliberately exempt from the console's
# session auth, so RBAC could not reach it either. Writes therefore live on the
# console under `require_role("admin")`, next to /parsers and /rules, which is where
# every other content-authoring operation in this app already is. Everything
# side-effect-free is here, so CI can validate and diff a pack with an API key.


def _plan_json(plan) -> dict:
    """An ImportPlan as JSON — the same shape the console table renders."""
    return {
        "pack": plan.pack.name, "version": plan.pack.version,
        "summary": plan.summary(), "counts": plan.counts(),
        "applicable": plan.applicable, "restart_required": plan.restart_required,
        "problems": list(plan.problems),
        "conflicts": [c.describe() for c in plan.conflicts],
        "changes": [{"kind": c.kind, "ident": c.ident, "verb": c.verb,
                     "detail": c.detail, "owner": c.owner} for c in plan.changes],
    }


async def _pack_text(request: Request) -> str:
    """The request body as pack text, bounded by the pack size cap."""
    body = await _read_body_capped(request, contentpack.MAX_DOCUMENT_BYTES)
    if body is None:
        raise HTTPException(
            status_code=413,
            detail=f"pack exceeds the {contentpack.MAX_DOCUMENT_BYTES}-byte limit")
    text = body.decode("utf-8", "replace")
    if not text.strip():
        raise HTTPException(status_code=400, detail="empty pack document")
    return text


@router.post("/packs/validate")
async def api_pack_validate(request: Request, key: dict = Depends(require_api_key)):
    """Strict validation of an untrusted pack document. Nothing is read or written."""
    problems = contentpack.validate(await _pack_text(request))
    return {"ok": not problems, "problems": problems}


@router.post("/packs/plan")
async def api_pack_plan(request: Request, key: dict = Depends(require_api_key)):
    """The dry run: exactly what an import WOULD change. Always render this first."""
    text = await _pack_text(request)
    try:
        plan = await run_in_threadpool(contentpack.install, text, dry_run=True)
    except contentpack.PackError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _plan_json(plan)


@router.get("/packs")
async def api_packs(key: dict = Depends(require_api_key)):
    rows = await run_in_threadpool(db.list_content_packs)
    return [{"name": r["name"], "version": r["version"], "digest": r["digest"],
             "installed_at": r["installed_at"], "installed_by": r["installed_by"]}
            for r in rows]


@router.get("/packs/{name}/export", response_class=PlainTextResponse)
async def api_pack_export(name: str, key: dict = Depends(require_api_key)):
    rows = await run_in_threadpool(db.list_content_packs)
    row = next((r for r in rows if r["name"] == name), None)
    if row is None:
        raise HTTPException(status_code=404, detail=f"no installed pack named {name!r}")
    return PlainTextResponse(
        row["document"], media_type="application/yaml",
        headers={"Content-Disposition":
                 f'attachment; filename="{name}-{row["version"]}.yaml"'})


@router.post("/query")
async def api_query(body: dict, key: dict = Depends(require_api_key)):
    """Run a LOQL query (``{"query": "...", "limit": N}``) and return the result set.

    LOQL compiles to parameterized SQL under guardrails (statement timeout + row cap),
    so a malformed/hostile query is a clean 400 (never SQL injection or a 500).

    That includes the CIM source (``| datamodel Authentication`` /
    ``from datamodel:Authentication``): the model name is resolved at compile time
    against the registry, so an unknown or misplaced data model raises ``LoqlError``
    before a connection is taken and surfaces here as a 400 naming the known models —
    never an empty 200, which is what a silently-unresolved model would look like."""
    raw = body.get("query") if isinstance(body, dict) else None
    if raw is not None and not isinstance(raw, str):
        raise HTTPException(status_code=400, detail="'query' must be a string")
    q = (raw or "").strip()
    if not q:
        raise HTTPException(status_code=400, detail="missing 'query'")
    try:
        limit = int(body.get("limit") or settings.loql_default_limit)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="'limit' must be an integer")
    limit = max(1, min(limit, settings.loql_max_rows))
    try:
        return await run_in_threadpool(
            run_query, q, limit=limit, max_rows=settings.loql_max_rows,
            timeout_ms=settings.loql_timeout_ms)
    except LoqlError as e:
        raise HTTPException(status_code=400, detail=e.message)
