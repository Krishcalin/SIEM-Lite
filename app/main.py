"""LogOcean FastAPI application: dashboard, upload, search, event detail, admin."""
from __future__ import annotations

import csv
import io
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from . import db, ingest
from .config import settings
from .detect import detect_format
from .parsers import FORMAT_LABELS
from .util import parse_ts

log = logging.getLogger("logocean")
BASE = Path(__file__).resolve().parent


async def _read_capped(file: UploadFile, limit: int) -> Optional[bytes]:
    """Read an upload in 1 MB chunks, aborting once it exceeds `limit` bytes.

    Returns the bytes, or None if the file is over the limit. Bounds peak memory
    to ~limit + one chunk instead of buffering an arbitrarily large body first.
    """
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


# Leading characters a spreadsheet may interpret as a formula (CSV injection).
_CSV_FORMULA_LEAD = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value) -> str:
    """Neutralize spreadsheet formula injection in exported CSV cells."""
    s = "" if value is None else str(value)
    if s and s[0] in _CSV_FORMULA_LEAD:
        return "'" + s
    return s


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_schema()
    if settings.auto_purge:
        db.purge_older_than(settings.retention_years)
    yield


app = FastAPI(title="LogOcean", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")
templates.env.globals["format_labels"] = FORMAT_LABELS
templates.env.globals["retention_years"] = settings.retention_years


def _ctx(request: Request, **kw):
    return {"request": request, **kw}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", _ctx(request, stats=db.stats()))


# --------------------------------------------------------------------------- #
#  Upload                                                                      #
# --------------------------------------------------------------------------- #
@app.get("/upload", response_class=HTMLResponse)
def upload_form(request: Request):
    return templates.TemplateResponse("upload.html", _ctx(request, result=None, error=None))


@app.post("/upload", response_class=HTMLResponse)
async def upload(request: Request, file: UploadFile = File(...), fmt: str = Form("auto")):
    raw = await _read_capped(file, settings.max_upload_mb * 1024 * 1024)
    if raw is None:
        return templates.TemplateResponse("upload.html", _ctx(
            request, result=None,
            error=f"File exceeds the {settings.max_upload_mb} MB limit."))

    content = raw.decode("utf-8", "replace")
    chosen = fmt
    if fmt == "auto":
        chosen = detect_format(file.filename, content)
        if chosen is None:
            return templates.TemplateResponse("upload.html", _ctx(
                request, result=None,
                error="Could not auto-detect the format. Please pick one explicitly."))

    try:
        # Parsing + DB I/O is blocking and CPU-bound — keep it off the event loop.
        result = await run_in_threadpool(ingest.ingest, file.filename, content, chosen)
    except Exception:  # noqa: BLE001
        log.exception("ingest failed for %r (format=%s)", file.filename, chosen)
        return templates.TemplateResponse("upload.html", _ctx(
            request, result=None,
            error="Ingest failed. The file could not be processed — see server logs for details."))
    return templates.TemplateResponse("upload.html", _ctx(request, result=result, error=None))


# --------------------------------------------------------------------------- #
#  Search                                                                      #
# --------------------------------------------------------------------------- #
def _filters(request: Request) -> dict:
    q = request.query_params
    f = {
        "vendor": q.get("vendor") or None,
        "log_type": q.get("log_type") or None,
        "severity": q.get("severity") or None,
        "action": q.get("action") or None,
        "src_ip": q.get("src_ip") or None,
        "dst_ip": q.get("dst_ip") or None,
        "user": q.get("user") or None,
        "host": q.get("host") or None,
        "q": q.get("q") or None,
    }
    tf, tt = q.get("time_from"), q.get("time_to")
    f["time_from"] = parse_ts(tf) if tf else None
    f["time_to"] = parse_ts(tt) if tt else None
    return f


@app.get("/search", response_class=HTMLResponse)
def search(request: Request):
    f = _filters(request)
    try:
        page = max(int(request.query_params.get("page", "1")), 1)
    except ValueError:
        page = 1
    limit = settings.page_size
    rows, total = db.search(f, limit=limit, offset=(page - 1) * limit)
    pages = max((total + limit - 1) // limit, 1)
    base_qs = urlencode([(k, v) for k, v in request.query_params.multi_items()
                         if k != "page" and v])
    return templates.TemplateResponse("search.html", _ctx(
        request, rows=rows, total=total, page=page, pages=pages,
        params=request.query_params, base_qs=base_qs,
        vendors=db.distinct_values("vendor"), log_types=db.distinct_values("log_type")))


@app.get("/search.csv")
def search_csv(request: Request):
    f = _filters(request)
    cols = ["event_time", "vendor", "log_type", "severity", "action", "src_ip",
            "dst_ip", "src_port", "dst_port", "protocol", "app", "user_name",
            "host_name", "rule_name", "bytes_total", "message"]

    def gen():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(cols)
        yield buf.getvalue(); buf.seek(0); buf.truncate(0)
        for row in db.search_iter(f):
            w.writerow([_csv_safe(row.get(c, "")) for c in cols])
            yield buf.getvalue(); buf.seek(0); buf.truncate(0)

    return StreamingResponse(gen(), media_type="text/csv", headers={
        "Content-Disposition": "attachment; filename=logocean_export.csv"})


@app.get("/event/{event_id}", response_class=HTMLResponse)
def event_detail(request: Request, event_id: int):
    ev = db.get_event(event_id)
    if ev is None:
        return HTMLResponse("Event not found", status_code=404)
    return templates.TemplateResponse("event.html", _ctx(request, ev=ev))


# --------------------------------------------------------------------------- #
#  Admin / retention                                                           #
# --------------------------------------------------------------------------- #
@app.get("/admin", response_class=HTMLResponse)
def admin(request: Request, purged: Optional[str] = None):
    return templates.TemplateResponse("admin.html", _ctx(
        request, batches=db.recent_batches(100), stats=db.stats(),
        purged=purged.split(",") if purged else None))


@app.post("/admin/purge")
def admin_purge(years: int = Form(...)):
    years = max(years, settings.retention_years)  # never purge below the retention floor
    dropped = db.purge_older_than(years)
    qs = ("?purged=" + ",".join(dropped)) if dropped else "?purged="
    return RedirectResponse(url="/admin" + qs, status_code=303)
