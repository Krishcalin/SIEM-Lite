"""LogOcean FastAPI application: dashboard, upload, search, event detail, admin."""
from __future__ import annotations

import csv
import io
import logging
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode

from fastapi import Depends, FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from . import api, auth, collectors, compliance, db, ingest, notify, streaming
from .auth import require_role
from .config import settings
from .detect import detect_format
from .detection import correlation, runtime as detection_runtime
from .parsers import FORMAT_LABELS
from .receivers import syslog
from .response import engine as response_engine
from .threatintel import feeds as ti_feeds, matcher as ti_matcher, runtime as ti_runtime
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
    if settings.auth_enabled and db.count_users() == 0:
        pw = settings.admin_password or secrets.token_urlsafe(12)
        db.create_user(settings.admin_user, auth.hash_password(pw), "admin")
        if not settings.admin_password:
            log.warning("Bootstrapped admin user %r with generated password: %s",
                        settings.admin_user, pw)
    if settings.auto_purge:
        db.purge_older_than(settings.retention_years)
    correlator = None
    if settings.detection_enabled:
        detection_runtime.load_and_sync(BASE.parent / "rules")
        corr_rules = detection_runtime.get_correlation_rules()
        if corr_rules:
            correlator = correlation.CorrelationScheduler(
                corr_rules, settings.correlation_interval)

    dispatcher = None
    if settings.notify_enabled:
        dispatcher = notify.build_dispatcher()
        if dispatcher.channels:
            dispatcher.start()
            notify.set_dispatcher(dispatcher)
        else:
            log.warning("NOTIFY_ENABLED is set but no channels are configured")
            dispatcher = None

    responder = None
    if settings.response_enabled:
        responder = response_engine.build_engine(BASE.parent / "playbooks")
        if responder.playbooks:
            responder.start()
            response_engine.set_engine(responder)
        else:
            log.warning("RESPONSE_ENABLED is set but no playbooks were found")
            responder = None

    collector_sched = None
    if settings.collectors_enabled:
        built = collectors.build_collectors()
        if built:
            db.sync_collectors([c.name for c in built])
            collector_sched = collectors.CollectorScheduler(built, settings.collector_interval)
            collectors.set_scheduler(collector_sched)
        else:
            log.warning("COLLECTORS_ENABLED is set but no collector credentials are configured")

    ti_scheduler = None
    if settings.threatintel_enabled:
        feed_list = ti_feeds.split_feeds(settings.threatintel_feeds)
        if feed_list:
            ti_runtime.sync_feeds(feed_list, settings.threatintel_default_severity)
            interval = settings.threatintel_refresh_minutes * 60
            if interval > 0:
                ti_scheduler = ti_runtime.FeedScheduler(
                    feed_list, interval, settings.threatintel_default_severity)
                ti_runtime.set_scheduler(ti_scheduler)
        else:
            ti_runtime.reload_index()   # manual indicators only (no feeds configured)

    queue = streaming.IngestQueue(settings.ingest_queue_max, settings.ingest_workers,
                                  settings.ingest_flush_max, settings.ingest_flush_ms)
    await queue.start()
    streaming.set_queue(queue)
    receiver = syslog.SyslogReceiver(queue) if settings.syslog_enabled else None
    if receiver is not None:
        await receiver.start()
    if correlator is not None:
        await correlator.start()
    if collector_sched is not None:
        await collector_sched.start()
    if ti_scheduler is not None:
        await ti_scheduler.start()
    try:
        yield
    finally:
        if ti_scheduler is not None:
            await ti_scheduler.stop()
            ti_runtime.set_scheduler(None)
        if collector_sched is not None:
            await collector_sched.stop()
            collectors.set_scheduler(None)
        if correlator is not None:
            await correlator.stop()
        if receiver is not None:
            await receiver.stop()
        await queue.stop()
        streaming.set_queue(None)
        if dispatcher is not None:
            dispatcher.stop()
            notify.set_dispatcher(None)
        if responder is not None:
            responder.stop()
            response_engine.set_engine(None)


app = FastAPI(title="LogOcean", lifespan=lifespan)
app.include_router(api.router)  # POST /api/v1/ingest (HTTP live ingestion)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")
templates.env.globals["format_labels"] = FORMAT_LABELS
templates.env.globals["retention_years"] = settings.retention_years
templates.env.globals["auth_enabled"] = settings.auth_enabled

# Paths reachable without a session (login, static assets, health, and the
# API which authenticates with its own keys).
_AUTH_EXEMPT = ("/login", "/logout", "/health")


@app.middleware("http")
async def auth_guard(request: Request, call_next):
    """Populate request.state.user from the session cookie; redirect unauthenticated
    UI requests to /login. A no-op when AUTH_ENABLED is false."""
    request.state.user = None
    if not settings.auth_enabled:
        return await call_next(request)
    path = request.url.path
    exempt = path in _AUTH_EXEMPT or path.startswith(("/static", "/api/"))
    token = request.cookies.get("session")
    if token:
        request.state.user = await run_in_threadpool(db.get_session_user, token)
    if not exempt and request.state.user is None:
        return RedirectResponse(url="/login", status_code=303)
    return await call_next(request)


def _ctx(request: Request, **kw):
    return {"request": request, "user": getattr(request.state, "user", None), **kw}


def _audit(request: Request, action: str, detail: Optional[str] = None,
           username: Optional[str] = None) -> None:
    """Record a security-relevant action. `username` overrides the session user
    (e.g. a failed login where there is no session yet). Blocking; call directly
    from sync routes, or via run_in_threadpool from async ones."""
    user = getattr(request.state, "user", None)
    actor = username or (user.get("username") if user else None)
    ip = request.client.host if request.client else None
    db.add_audit(actor, action, detail, ip)


# --------------------------------------------------------------------------- #
#  Auth (login / logout)                                                       #
# --------------------------------------------------------------------------- #
@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", _ctx(request, error=None))


@app.post("/login", response_class=HTMLResponse)
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    user = await run_in_threadpool(db.get_user_by_name, username)
    if not (user and user["enabled"] and auth.verify_password(password, user["password_hash"])):
        await run_in_threadpool(_audit, request, "login.failed", None, username)
        return templates.TemplateResponse(
            "login.html", _ctx(request, error="Invalid username or password."),
            status_code=401)
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(hours=settings.session_ttl_hours)
    await run_in_threadpool(db.create_session, token, user["id"], expires)
    await run_in_threadpool(db.update_last_login, user["id"])
    await run_in_threadpool(_audit, request, "login", None, user["username"])
    resp = RedirectResponse(url="/", status_code=303)
    resp.set_cookie("session", token, httponly=True, samesite="lax",
                    secure=settings.session_cookie_secure,
                    max_age=settings.session_ttl_hours * 3600)
    return resp


@app.get("/logout")
def logout(request: Request):
    token = request.cookies.get("session")
    if token:
        _audit(request, "logout")
        db.delete_session(token)
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie("session")
    return resp


@app.get("/health")
def health():
    q = streaming.get_queue()
    d = notify.get_dispatcher()
    r = response_engine.get_engine()
    cs = collectors.get_scheduler()
    return {"status": "ok",
            "ingest_queue": q.stats.as_dict() if q else None,
            "notifications": d.stats() if d else None,
            "responses": r.stats() if r else None,
            "collectors": len(cs.collectors) if cs else None,
            "threatintel_indicators": len(ti_runtime.get_index())}


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", _ctx(
        request, stats=db.stats(), alert_counts=db.alert_severity_counts()))


# --------------------------------------------------------------------------- #
#  Upload                                                                      #
# --------------------------------------------------------------------------- #
@app.get("/upload", response_class=HTMLResponse)
def upload_form(request: Request):
    return templates.TemplateResponse("upload.html", _ctx(request, result=None, error=None))


@app.post("/upload", response_class=HTMLResponse)
async def upload(request: Request, file: UploadFile = File(...), fmt: str = Form("auto"),
                 _user=Depends(require_role("analyst"))):
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

    src = request.client.host if request.client else None
    try:
        # Parsing + DB I/O is blocking and CPU-bound — keep it off the event loop.
        result = await run_in_threadpool(
            ingest.ingest, content, chosen, filename=file.filename, source_addr=src)
    except Exception:  # noqa: BLE001
        log.exception("ingest failed for %r (format=%s)", file.filename, chosen)
        return templates.TemplateResponse("upload.html", _ctx(
            request, result=None,
            error="Ingest failed. The file could not be processed — see server logs for details."))
    await run_in_threadpool(
        _audit, request, "upload",
        f"{file.filename}: {result['inserted']} stored ({chosen})")
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
#  Alerts                                                                      #
# --------------------------------------------------------------------------- #
def _alert_filters(request: Request) -> dict:
    q = request.query_params
    return {"status": q.get("status") or None, "level": q.get("level") or None,
            "rule_id": q.get("rule_id") or None, "q": q.get("q") or None}


@app.get("/alerts", response_class=HTMLResponse)
def alerts(request: Request):
    f = _alert_filters(request)
    try:
        page = max(int(request.query_params.get("page", "1")), 1)
    except ValueError:
        page = 1
    limit = settings.page_size
    rows, total = db.recent_alerts(f, limit=limit, offset=(page - 1) * limit)
    pages = max((total + limit - 1) // limit, 1)
    base_qs = urlencode([(k, v) for k, v in request.query_params.multi_items()
                         if k != "page" and v])
    return templates.TemplateResponse("alerts.html", _ctx(
        request, rows=rows, total=total, page=page, pages=pages,
        params=request.query_params, base_qs=base_qs,
        counts=db.alert_severity_counts()))


@app.get("/alert/{alert_id}", response_class=HTMLResponse)
def alert_detail(request: Request, alert_id: int):
    a = db.get_alert(alert_id)
    if a is None:
        return HTMLResponse("Alert not found", status_code=404)
    event_id = db.event_id_for(a["dedup_hash"], a["event_time"])
    return templates.TemplateResponse("alert.html", _ctx(
        request, a=a, event_id=event_id, responses=db.responses_for_alert(alert_id)))


@app.post("/alert/{alert_id}/status")
def alert_set_status(request: Request, alert_id: int, status: str = Form(...),
                     _user=Depends(require_role("analyst"))):
    if status in ("open", "ack", "closed"):
        db.set_alert_status(alert_id, status)
        _audit(request, "alert.status", f"alert {alert_id} -> {status}")
    return RedirectResponse(url=f"/alert/{alert_id}", status_code=303)


@app.get("/responses", response_class=HTMLResponse)
def responses(request: Request):
    return templates.TemplateResponse("responses.html", _ctx(
        request, rows=db.recent_responses(200)))


@app.get("/compliance", response_class=HTMLResponse)
def compliance_view(request: Request):
    enabled_techniques: set[str] = set()
    for r in db.list_rules():
        if r["enabled"]:
            enabled_techniques.update(t.upper() for t in (r["techniques"] or []))
    report = compliance.build_report(enabled_techniques, db.alert_technique_counts(30))
    return templates.TemplateResponse("compliance.html", _ctx(
        request, report=report, frameworks=compliance.FRAMEWORKS))


# --------------------------------------------------------------------------- #
#  Admin / retention                                                           #
# --------------------------------------------------------------------------- #
def _render_admin(request: Request, *, purged=None, new_key=None, user_error=None,
                  ti_error=None):
    return templates.TemplateResponse("admin.html", _ctx(
        request, batches=db.recent_batches(100), stats=db.stats(),
        api_keys=db.list_api_keys(), rules=db.list_rules(),
        collectors=db.list_collectors(),
        users=db.list_users() if settings.auth_enabled else [],
        roles=auth.ROLES, audit=db.recent_audit(50),
        ti_enabled=settings.threatintel_enabled, ti_counts=db.ioc_counts(),
        ti_indicators=db.list_iocs(25), ti_index_size=len(ti_runtime.get_index()),
        ti_types=ti_matcher.VALID_TYPES,
        purged=purged, new_key=new_key, user_error=user_error, ti_error=ti_error))


@app.get("/admin", response_class=HTMLResponse)
def admin(request: Request, purged: Optional[str] = None,
          _user=Depends(require_role("admin"))):
    return _render_admin(request, purged=purged.split(",") if purged else None)


@app.post("/admin/purge")
def admin_purge(request: Request, years: int = Form(...),
                _user=Depends(require_role("admin"))):
    years = max(years, settings.retention_years)  # never purge below the retention floor
    dropped = db.purge_older_than(years)
    _audit(request, "purge", f"dropped {len(dropped)} partition(s) older than {years}y")
    qs = ("?purged=" + ",".join(dropped)) if dropped else "?purged="
    return RedirectResponse(url="/admin" + qs, status_code=303)


@app.post("/admin/api-keys", response_class=HTMLResponse)
def admin_create_api_key(request: Request, name: str = Form(...), source_label: str = Form(""),
                         _user=Depends(require_role("admin"))):
    # Render directly (no redirect) so the plaintext key is shown once and never
    # placed in a URL / browser history.
    created = db.create_api_key(name.strip() or "unnamed", source_label.strip() or None)
    _audit(request, "api_key.create", created["name"])
    return _render_admin(request, new_key=created)


@app.post("/admin/api-keys/{key_id}/toggle")
def admin_toggle_api_key(request: Request, key_id: int, enabled: str = Form(...),
                         _user=Depends(require_role("admin"))):
    on = enabled == "true"
    db.set_api_key_enabled(key_id, on)
    _audit(request, "api_key.toggle", f"key {key_id} -> {'enabled' if on else 'disabled'}")
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/rules/{rule_id}/toggle")
def admin_toggle_rule(request: Request, rule_id: str, enabled: str = Form(...),
                      _user=Depends(require_role("admin"))):
    on = enabled == "true"
    db.set_rule_enabled(rule_id, on)
    detection_runtime.refresh_enabled()   # apply to the in-memory engine immediately
    _audit(request, "rule.toggle", f"{rule_id} -> {'enabled' if on else 'disabled'}")
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/collectors/{name}/toggle")
def admin_toggle_collector(request: Request, name: str, enabled: str = Form(...),
                           _user=Depends(require_role("admin"))):
    on = enabled == "true"
    db.set_collector_enabled(name, on)
    _audit(request, "collector.toggle", f"{name} -> {'enabled' if on else 'disabled'}")
    return RedirectResponse(url="/admin", status_code=303)


# --------------------------------------------------------------------------- #
#  Threat intelligence (admin)                                                #
# --------------------------------------------------------------------------- #
@app.post("/admin/threatintel/reload", response_class=HTMLResponse)
def admin_ti_reload(request: Request, _user=Depends(require_role("admin"))):
    """Re-fetch the configured feeds (or just rebuild the index) and apply it live."""
    feed_list = ti_feeds.split_feeds(settings.threatintel_feeds)
    if feed_list:
        n = ti_runtime.sync_feeds(feed_list, settings.threatintel_default_severity)
    else:
        n = len(ti_runtime.reload_index())
    _audit(request, "threatintel.reload", f"{len(feed_list)} feed(s), {n} indicator(s)")
    return _render_admin(request)


@app.post("/admin/threatintel/add", response_class=HTMLResponse)
def admin_ti_add(request: Request, indicator: str = Form(...),
                 severity: str = Form("high"), description: str = Form(""),
                 _user=Depends(require_role("admin"))):
    ioc = ti_matcher.make_ioc(indicator.strip(), source="manual",
                              severity=severity.strip() or "high",
                              description=description.strip())
    if ioc is None:
        return _render_admin(request,
                             ti_error=f"Could not recognize {indicator!r} as an IP/CIDR/"
                                      "domain/hash/URL.")
    db.upsert_iocs([ioc])
    ti_runtime.reload_index()
    _audit(request, "threatintel.add", f"{ioc.indicator} ({ioc.ioc_type})")
    return _render_admin(request)


@app.post("/admin/threatintel/delete")
def admin_ti_delete(request: Request, indicator: str = Form(...), ioc_type: str = Form(...),
                    _user=Depends(require_role("admin"))):
    db.delete_ioc(indicator, ioc_type)
    ti_runtime.reload_index()
    _audit(request, "threatintel.delete", f"{indicator} ({ioc_type})")
    return RedirectResponse(url="/admin", status_code=303)


# --------------------------------------------------------------------------- #
#  User management (admin)                                                     #
# --------------------------------------------------------------------------- #
@app.post("/admin/users", response_class=HTMLResponse)
def admin_create_user(request: Request, username: str = Form(...), password: str = Form(...),
                      role: str = Form("viewer"), _user=Depends(require_role("admin"))):
    username, role = username.strip(), (role if role in auth.ROLES else "viewer")
    error = None
    if not username or not password:
        error = "Username and password are required."
    elif db.get_user_by_name(username):
        error = f"User {username!r} already exists."
    else:
        db.create_user(username, auth.hash_password(password), role)
        _audit(request, "user.create", f"{username} ({role})")
    return _render_admin(request, user_error=error)


@app.post("/admin/users/{user_id}/role")
def admin_set_user_role(request: Request, user_id: int, role: str = Form(...),
                        _user=Depends(require_role("admin"))):
    if role in auth.ROLES:
        db.set_user_role(user_id, role)
        _audit(request, "user.role", f"user {user_id} -> {role}")
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/users/{user_id}/toggle")
def admin_toggle_user(request: Request, user_id: int, enabled: str = Form(...),
                      _user=Depends(require_role("admin"))):
    on = enabled == "true"
    db.set_user_enabled(user_id, on)
    _audit(request, "user.toggle", f"user {user_id} -> {'enabled' if on else 'disabled'}")
    return RedirectResponse(url="/admin", status_code=303)
