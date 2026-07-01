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
from starlette.concurrency import run_in_threadpool

from . import db, ingest
from .config import settings
from .detect import detect_format
from .parsers import PARSERS
from .util import extract_api_key, gunzip_capped

log = logging.getLogger("logocean")
router = APIRouter(prefix="/api/v1", tags=["ingest"])


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
