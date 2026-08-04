# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""LogOcean FastAPI application: dashboard, upload, search, event detail, admin."""
from __future__ import annotations

import asyncio
import csv
import io
import logging
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlencode, urlparse

from fastapi import Depends, FastAPI, File, Form, Request, UploadFile
from fastapi.responses import (HTMLResponse, JSONResponse, PlainTextResponse,
                               RedirectResponse, StreamingResponse)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from . import (api, assets, auth, cim, collectors, compliance, contentpack, coverage,
               custom_parser, db, ingest, ingest_actions, killchain_runtime, navigator,
               notify, ot, saved, sourcehealth, streaming, vault, workbench)
from .copilot import client as copilot
from .auth import require_role
from .config import settings
from .detect import detect_format
from .detection import correlation, runtime as detection_runtime
from .loql import LoqlError, run_query
from .parsers import FORMAT_LABELS
from .receivers import netflow as netflow_receiver, syslog
from .response import engine as response_engine
from .response import revert as response_revert
from .threatintel import feeds as ti_feeds, matcher as ti_matcher, runtime as ti_runtime
from .triage import runtime as triage_runtime
from .util import DISPLAY_TZ_LABEL, fmt_ist, gunzip_capped, parse_ts, to_ist

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


def _csv_cell(value) -> str:
    """A CSV cell, with any timestamp rendered in the display timezone (IST) as an
    unambiguous, offset-bearing string (e.g. ``2026-06-01 17:30:00+05:30``)."""
    if isinstance(value, datetime):
        value = to_ist(value).isoformat(sep=" ")
    return _csv_safe(value)


# --------------------------------------------------------------------------- #
#  CIM data models: startup state + the background membership backfill        #
# --------------------------------------------------------------------------- #
# What the last startup made of the registry, so /datamodels and /health can report
# whether the model views are actually in the database instead of assuming they are.
# `registry_version` is set by `_require_cim_registry` and therefore populated even when
# CIM_ENABLED=false or the view DDL failed; `failed` lists the models whose view could
# not be rebuilt (see `db.init_cim`, which is resilient per model rather than all-or-
# nothing).
_cim_init: dict[str, Any] = {"applied": False, "views": [], "dropped": [], "failed": [],
                             "registry_version": None, "error": None}

# `db.backfill_cim` re-derives `events.cim_models` for rows already stored — the step
# that corrects HISTORY after a membership edit in models.yaml. It walks every
# partition in committed chunks, so on a three-year store it is minutes, not
# milliseconds. The admin route therefore STARTS it and returns, the way the
# schedulers work (an asyncio.Task doing its blocking work in a threadpool); this
# record is the progress view the admin page renders.
# `progress` is the running counters of the CURRENT pass, republished by `db.backfill_cim`
# after every committed chunk; `result` is only populated once the run returns. Both are
# needed: while the state is "running" the result is None by construction, so anything
# that wants the resume cursor mid-run (the shutdown handler) has to read `progress`.
_cim_backfill: dict[str, Any] = {"state": "idle", "started_at": None,
                                 "finished_at": None, "by": None, "result": None,
                                 "progress": None, "error": None}
# A strong reference to the in-flight task: asyncio only holds a weak one, so a
# fire-and-forget task can be garbage-collected mid-run without it.
_cim_backfill_task: Optional[asyncio.Task] = None


# The running NetFlow receiver, so /health can report its counters. Same
# singleton shape as `streaming.get_queue()` / `set_queue()`, and it exists for a
# specific reason: `unknown_drops` climbing without bound is the signature of an
# exporter whose periodic template refresh never reaches us (or an exporter/domain key
# mismatch), and `evicted` climbing is the signature of a source cycling template ids.
# `redefined` is the third: a template id whose SHAPE changed under a live exporter,
# which is what a spoofed Options Template Set looks like when it blackholes that
# exporter's flows (they route to `options_skipped`, which reads as healthy) or what a
# transposed field list looks like when it silently swaps src and dst on every flow.
# None of the three is visible anywhere else — the flows are simply not there, or wrong.
_flow_receiver: Any = None


def get_flow_receiver():
    return _flow_receiver


def set_flow_receiver(r) -> None:
    global _flow_receiver
    _flow_receiver = r


def _require_cim_registry() -> None:
    """Parse + validate app/cim/models.yaml, and REFUSE TO BOOT if it will not load.

    Fatal, unconditionally, and it runs before anything else in the lifespan — before
    the database is even touched. Three reasons, in order of how much they cost:

    * The registry is not optional. `events.cim_models` is stamped per row in Python at
      ingest whatever CIM_ENABLED says (that flag gates the `cim_<tag>` VIEWS only), so
      an unparseable models.yaml is a defect in the WRITE path, not in a reporting view.
    * models.yaml ships with the repo. A registry that does not parse is a deploy error,
      not an operating condition, and the YAML author's own error message at boot is the
      most useful thing this process can produce with it.
    * Every alternative is worse than refusing. Before this call existed the load was
      lazy and nothing triggered it at startup, so the app booted green and failed later:
      on the upload path as "Ingest failed", and on the LIVE path as total silent data
      loss — `streaming._flush` catches the exception, counts a flush error and DISCARDS
      the buffered batch, dropping every syslog and API event while /health said "ok".
      `db._cim_tags` now degrades that path so it can never happen again; this makes sure
      it does not have to.
    """
    try:
        reg = db.validate_cim_registry()
    except Exception as exc:  # noqa: BLE001 — re-raised; the log line is for the operator
        log.critical(
            "app/cim/models.yaml did not load, so LogOcean is refusing to start: %s. "
            "The CIM registry decides what every ingested event is tagged with, so "
            "booting without it would either drop events or store them untagged. Fix "
            "the YAML (or roll back to the previous revision) and start again", exc)
        raise
    _cim_init["registry_version"] = reg.version


def _init_cim() -> None:
    """Rebuild the per-model ``cim_<tag>`` views from the registry — log-and-continue.

    Deliberately NOT fatal, and the asymmetry with `_require_cim_registry` above is the
    point. These views are read-side only: `events.cim_models` is stamped in Python at
    ingest (`db._row`) and both detection and LOQL gate on that column, so a failed
    CREATE VIEW costs the `cim_<tag>` views and degrades nothing that stores or
    classifies an event. Refusing to boot a SIEM over a broken reporting view would
    trade a cosmetic outage for a real one — so this gets the same treatment as the
    notify/response/collector subsystems: complain loudly, keep serving.

    Two failure shapes are recorded rather than one. `db.init_cim` applies each model in
    its own transaction and returns the ones that failed, so `error` here summarises
    *those* (a dependent object, a bad `fields:` expression) while the views that did
    rebuild are still reported in `views`; an exception out of `init_cim` itself is the
    systemic case (no database, no `events` table) and sets `error` alone.

    The registry itself is already known to parse by the time this runs — that is
    `_require_cim_registry`'s job, and it is a boot failure, not a degradation.
    """
    if not settings.cim_enabled:
        log.info("CIM_ENABLED=false — skipping the CIM model views (events.cim_models "
                 "is still stamped at ingest, so detections and LOQL are unaffected)")
        return
    try:
        res = db.init_cim()
    except Exception as exc:  # noqa: BLE001 — read-side only; see the docstring
        _cim_init["error"] = str(exc)
        log.exception("CIM view DDL failed — `SELECT * FROM cim_<tag>` and /datamodels "
                      "are degraded until the cause is fixed and the app restarts; "
                      "ingest and detection are unaffected")
        return
    failed = res["failed"]
    _cim_init.update(applied=True, views=res["views"], dropped=res["dropped"],
                     failed=failed, registry_version=res["registry_version"],
                     error=None if not failed else "; ".join(
                         f"{f['view']}: {f['error']}" for f in failed))


@asynccontextmanager
async def lifespan(app: FastAPI):
    _require_cim_registry()                    # FIRST: a bad models.yaml never serves
    db.init_schema()
    # The registry is compiled and cached on the first call, which `_require_cim_registry`
    # just made — BEFORE `init_schema`, so the content-pack CIM overlay ran against a
    # database with no `content_packs` table and correctly found nothing. Re-load now
    # that the table exists, or a pack's membership clauses would never take effect and
    # the restart the operator was told to perform would change nothing. Cheap (one YAML
    # parse) and single-threaded here, before any worker can race it.
    cim.registry.reload()
    compliance.apply_pack_overlay()            # pack compliance controls -> the MAP
    _init_cim()                                # CIM model views (needs events.cim_models)
    # Asset & identity registry (Phase 3). Loaded HERE, after init_schema, for the same
    # reason the CIM reload above is: the tables have to exist. `get_index()` would
    # lazily load it on the first event anyway, but doing it explicitly means the stamp
    # is written and /health can answer "is a backfill owed?" before anything is
    # ingested rather than after. Never fatal — `reload()` keeps the previous index (an
    # empty one at boot) and logs, so an unreachable registry costs events their
    # context and never the boot.
    try:
        db.stamp_asset_registry(assets.reload())
    except Exception:                          # noqa: BLE001
        log.warning("asset registry could not be stamped at startup; events will "
                    "store no business context until it loads", exc_info=True)
    if settings.auth_enabled and db.count_users() == 0:
        pw = settings.admin_password or secrets.token_urlsafe(12)
        db.create_user(settings.admin_user, auth.hash_password(pw), "admin")
        if not settings.admin_password:
            log.warning("Bootstrapped admin user %r with generated password: %s",
                        settings.admin_user, pw)
    if settings.auto_purge:
        db.purge_older_than(settings.retention_years)
    custom_parser.reload()                     # console-authored field maps
    triage_runtime.reload_index()              # load suppression/allowlist rules
    # Ingest actions (drop / mask / route / sample). Never raises: a rule file that will
    # not load is collected into ActionIndex.load_errors, logged, and surfaced on /health
    # — which matters more here than anywhere else, because a rule that DROPS events
    # leaves no row behind to notice.
    ingest_actions.reload_index(settings.ingest_actions_dir)
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

    revert_sched = None
    if settings.response_enabled and settings.response_auto_revert:
        revert_sched = response_revert.RevertScheduler(settings.response_revert_interval)
        response_revert.set_scheduler(revert_sched)

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

    killchain_sched = None
    if settings.killchain_enabled and settings.killchain_autocreate:
        killchain_sched = killchain_runtime.KillChainScheduler(
            settings.killchain_interval, settings.killchain_min_severity)

    source_health_sched = None
    if settings.source_health_enabled:
        source_health_sched = sourcehealth.SourceHealthScheduler(settings.source_health_interval)
        sourcehealth.set_scheduler(source_health_sched)

    queue = streaming.IngestQueue(settings.ingest_queue_max, settings.ingest_workers,
                                  settings.ingest_flush_max, settings.ingest_flush_ms)
    await queue.start()
    streaming.set_queue(queue)
    receiver = syslog.SyslogReceiver(queue) if settings.syslog_enabled else None
    if receiver is not None:
        await receiver.start()
    # NetFlow v5/v9/IPFIX. Same shape as the syslog receiver: an asyncio datagram
    # protocol that submits to the shared IngestQueue, never to the database directly.
    # Host/ports are constructor args rather than settings reads, so the lifespan is
    # the only place configuration touches it.
    flow_receiver = netflow_receiver.NetflowReceiver(
        queue, settings.netflow_host, settings.netflow_udp_port,
        settings.netflow_tcp_port, settings.netflow_max_templates,
    ) if settings.netflow_enabled else None
    if flow_receiver is not None:
        await flow_receiver.start()
        set_flow_receiver(flow_receiver)
    if correlator is not None:
        await correlator.start()
    if revert_sched is not None:
        await revert_sched.start()
    if collector_sched is not None:
        await collector_sched.start()
    if ti_scheduler is not None:
        await ti_scheduler.start()
    if killchain_sched is not None:
        await killchain_sched.start()
    if source_health_sched is not None:
        await source_health_sched.start()
    try:
        yield
    finally:
        if _cim_backfill["state"] == "running":
            # Nothing to stop cleanly: the work is in a threadpool and dies with the
            # process. It commits per chunk, so say where to pick it up rather than
            # letting the next operator wonder whether history is half-corrected.
            #
            # Read `progress`, NOT `result`. This branch fires only while the state is
            # "running", and `result` is set to None when a run starts and filled in only
            # after `backfill_cim` returns — so the old `result.last_id` was None here by
            # construction and this line printed `start_id=0` every single time, telling
            # the operator to redo the entire table. `progress` is republished by the job
            # after every committed chunk.
            done = _cim_backfill.get("progress") or {}
            log.warning("shutting down during a CIM membership backfill — it is "
                        "chunk-committed; %s rows were corrected, resume with "
                        "db.backfill_cim(start_id=%s)",
                        done.get("updated", 0), done.get("last_id", 0))
        if source_health_sched is not None:
            await source_health_sched.stop()
            sourcehealth.set_scheduler(None)
        if killchain_sched is not None:
            await killchain_sched.stop()
        if ti_scheduler is not None:
            await ti_scheduler.stop()
            ti_runtime.set_scheduler(None)
        if collector_sched is not None:
            await collector_sched.stop()
            collectors.set_scheduler(None)
        if correlator is not None:
            await correlator.stop()
        if revert_sched is not None:
            await revert_sched.stop()
            response_revert.set_scheduler(None)
        if receiver is not None:
            await receiver.stop()
        if flow_receiver is not None:
            await flow_receiver.stop()
            set_flow_receiver(None)
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
# The Splunk HEC wire shim: POST /services/collector/*. Mounted on the APP, not nested
# under api.router — its paths are absolute, and api.router carries prefix="/api/v1",
# which would relocate them to /api/v1/services/collector where no HEC sender looks.
app.include_router(api.hec_router)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")
templates.env.filters["ist"] = fmt_ist          # render stored-UTC datetimes in IST
templates.env.globals["format_labels"] = FORMAT_LABELS
templates.env.globals["tz_label"] = DISPLAY_TZ_LABEL
templates.env.globals["retention_years"] = settings.retention_years
templates.env.globals["auth_enabled"] = settings.auth_enabled
templates.env.globals["copilot_enabled"] = settings.copilot_enabled
templates.env.globals["cim_backfill_chunk"] = settings.cim_backfill_chunk

# Paths reachable without a session (login, static assets, health, and the
# API which authenticates with its own keys).
_AUTH_EXEMPT = ("/login", "/logout", "/health")
_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Applied to every response (defence-in-depth; the UI is server-rendered so a
# strict-ish CSP with inline style/script is safe and doesn't break it).
_SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    ),
}


def _csrf_same_origin(host: str, origin: Optional[str], referer: Optional[str]) -> bool:
    """CSRF check for cookie-authed, state-changing requests: the Origin (or, if
    absent, Referer) host must match ours. If neither header is present (rare for a
    browser form POST) we allow it — the SameSite=Lax session cookie still applies."""
    for val in (origin, referer):
        if val:
            return urlparse(val).netloc == host
    return True


@app.middleware("http")
async def auth_guard(request: Request, call_next):
    """Always attaches security headers. When AUTH_ENABLED: resolves the session
    user, redirects unauthenticated UI requests to /login, and rejects cross-origin
    state-changing requests (CSRF). A near-no-op when AUTH_ENABLED is false."""
    request.state.user = None
    blocked = None
    if settings.auth_enabled:
        path = request.url.path
        # /services/collector/* is the HEC shim. It authenticates itself with
        # `Authorization: Splunk <key>` -> db.verify_api_key, exactly as /api/ does with
        # its own key, so what is bypassed here is only the session-cookie redirect —
        # without it every HEC POST 303s to /login and the sender reads an opaque failure.
        exempt = path in _AUTH_EXEMPT or path.startswith(
            ("/static", "/api/", "/services/collector"))
        token = request.cookies.get("session")
        if token:
            request.state.user = await run_in_threadpool(db.get_session_user, token)
        if not exempt and request.state.user is None:
            blocked = RedirectResponse(url="/login", status_code=303)
        elif request.method in _UNSAFE_METHODS and \
                not path.startswith(("/api/", "/services/collector")) and \
                not _csrf_same_origin(request.headers.get("host", ""),
                                      request.headers.get("origin"),
                                      request.headers.get("referer")):
            blocked = PlainTextResponse("CSRF validation failed (cross-origin request).",
                                        status_code=403)
    response = blocked or await call_next(request)
    for key, val in _SECURITY_HEADERS.items():
        response.headers.setdefault(key, val)
    return response


def _ctx(request: Request, **kw):
    return {"request": request, "user": getattr(request.state, "user", None), **kw}


def _owner(request: Request) -> str:
    """The saved-search owner: the logged-in username, or '' when auth is off."""
    user = getattr(request.state, "user", None)
    return (user.get("username") if user else "") or ""


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
    return templates.TemplateResponse(request, "login.html", _ctx(request, error=None))


@app.post("/login", response_class=HTMLResponse)
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    user = await run_in_threadpool(db.get_user_by_name, username)
    if not (user and user["enabled"] and auth.verify_password(password, user["password_hash"])):
        await run_in_threadpool(_audit, request, "login.failed", None, username)
        return templates.TemplateResponse(
            request, "login.html", _ctx(request, error="Invalid username or password."),
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


def _ingest_degraded(q) -> list[str]:
    """Reasons the live-ingest path is not healthy — events that never reached the store.

    Two different losses, reported separately because they have different fixes:

    * `events_lost` — buffered events DISCARDED because their flush failed
      (`streaming.IngestQueue._flush`). Usually the database was unreachable. These are
      gone: syslog has no upstream to replay from. This is the reason /health has to say
      so, because nothing else in the system will.
    * `dropped` — items refused at the door because the queue was full, i.e. sustained
      arrival faster than the writer drains. The fix is capacity, not recovery.

    Listed BEFORE the CIM reasons in /health: an event that was never stored outranks one
    stored without its model tags, which is recoverable with a backfill.
    """
    if q is None:
        return []
    s, out = q.stats, []
    if s.events_lost:
        out.append(f"ingest: {s.events_lost} event(s) were discarded by {s.flush_errors} "
                   "failed flush(es) and cannot be recovered — check the database and "
                   "the log for 'ingest flush failed'")
    if s.dropped:
        out.append(f"ingest: {s.dropped} item(s) rejected because the queue was full — "
                   "the writer is not keeping up with arrivals")
    return out


def _cim_health() -> tuple[dict[str, Any], list[str]]:
    """The CIM block of /health, plus the reasons (if any) it is not healthy.

    `untagged_events` is the one to watch: it counts events STORED without their model
    tags because the registry could not be evaluated at insert time (`db._cim_tags`).
    They are in the table and `db.backfill_cim` can re-derive them — nothing is dropped —
    but every data model under-reports until that runs, so it is a degradation and is
    reported as one. `views_failed` is read-side only: those models keep their previous
    view definition while the rest refreshed.
    """
    write = db.cim_write_state()
    block = {"enabled": settings.cim_enabled,
             "registry_version": _cim_init["registry_version"],
             "applied": _cim_init["applied"],
             "views": len(_cim_init["views"]),
             "views_failed": len(_cim_init["failed"]),
             "error": _cim_init["error"],
             "backfill": _cim_backfill["state"],
             "untagged_events": write["failures"],
             "write_error": write["error"]}
    reasons = []
    if write["failures"]:
        reasons.append(f"cim: {write['failures']} event(s) stored without model tags "
                       f"({write['error']}) — fix app/cim/models.yaml, then run the "
                       "membership backfill from /admin")
    if _cim_init["failed"]:
        reasons.append("cim: " + ", ".join(f["view"] for f in _cim_init["failed"]) +
                       " could not be rebuilt at startup; see /datamodels")
    elif settings.cim_enabled and _cim_init["error"]:
        reasons.append(f"cim: the model views were not applied ({_cim_init['error']})")
    return block, reasons


@app.get("/health")
def health():
    """Liveness plus a per-subsystem snapshot.

    `status` is "ok" only when nothing is degraded, and `degraded` names what is. It was
    previously the constant string "ok" whatever had failed, which is how a broken
    app/cim/models.yaml could sit there dropping every live-ingested event while this
    endpoint reported a healthy service. The HTTP status stays 200 either way: the
    process IS alive and answering, and a load balancer pulling it out of rotation for a
    reporting-view defect would turn a partial outage into a total one.
    """
    q = streaming.get_queue()
    d = notify.get_dispatcher()
    r = response_engine.get_engine()
    rv = response_revert.get_scheduler()
    cs = collectors.get_scheduler()
    sh = sourcehealth.get_scheduler()
    fr = get_flow_receiver()
    cim_block, degraded = _cim_health()
    degraded = _ingest_degraded(q) + degraded
    actions = ingest_actions.stats()
    # A rule that will not load and a rule that is deleting events are the two things an
    # operator cannot discover any other way — a dropped event leaves no row behind — so
    # both are promoted to `degraded` rather than sitting in a sub-block nobody reads.
    #
    # The message says "not filtering anything" rather than "the rule was REJECTED",
    # because `load_errors` now also carries a configured-but-absent rules directory.
    # That case matters most for a mask: `ingest_actions_dir` defaults to the RELATIVE
    # "ingest_actions", resolved against the process CWD, so a rule verified on a laptop
    # at the repo root loads nothing under a systemd unit with a different
    # WorkingDirectory — and it used to do so with an EMPTY load_errors, i.e. a PII
    # feed running unredacted while every check the docs prescribe still said ok.
    if actions.get("load_errors"):
        degraded = degraded + [
            "ingest_actions: " + "; ".join(actions["load_errors"][:3]) +
            " — that rule is NOT filtering anything"]

    # Asset & identity registry. Two separate failures, and only one of them is an
    # error: `failures` means events are being STORED WITH NO business context (a
    # resolver defect), while `backfill_due` means the registry has moved ahead of
    # stored history — expected right after an edit, and the operator's cue to run
    # the backfill. Both are invisible in the data itself: an event with no context
    # looks exactly like an event about an undeclared host.
    try:
        registry = db.asset_status()
    except Exception:                          # noqa: BLE001 — /health must answer
        registry = {"error": "unavailable"}
    ctx_state = db.asset_write_state()
    if ctx_state.get("failures"):
        degraded = degraded + [
            f"asset context: {ctx_state['failures']} event(s) stored with NO business "
            f"context ({ctx_state.get('error')}) — criticality-gated detections "
            "under-report them until db.backfill_assets() re-derives those rows"]
    if registry.get("backfill_due"):
        degraded = degraded + [
            "asset registry: the declared registry has changed since events were last "
            "derived under it — run db.backfill_assets() so stored history matches"]

    return {"status": "degraded" if degraded else "ok",
            "degraded": degraded or None,
            "ingest_queue": q.stats.as_dict() if q else None,
            "netflow": fr.status() if fr else None,
            "ingest_actions": actions,
            "asset_registry": {**registry, "write_state": ctx_state},
            "notifications": d.stats() if d else None,
            "responses": r.stats() if r else None,
            "reverts": rv.stats() if rv else None,
            "collectors": len(cs.collectors) if cs else None,
            "source_health": sh.stats() if sh else None,
            "threatintel_indicators": len(ti_runtime.get_index()),
            "cim": cim_block,
            # Never the key itself - only whether the vault is usable, which key
            # fingerprint is live, and how many secrets are sealed under it.
            "vault": dict(vault.status(), secrets=len(db.list_secrets())
                          if vault.status()["usable"] else 0),
            "copilot": {"enabled": settings.copilot_enabled,
                        "configured": copilot.is_configured(),
                        "model": settings.copilot_model} if settings.copilot_enabled else None}


def _alert_analytics(days: int) -> dict:
    """The alert/case metrics shared by the dashboard and the report page."""
    techs = db.alert_technique_counts(days)
    top_tech = sorted(techs.items(), key=lambda kv: kv[1], reverse=True)[:8]
    return {
        "days": days,
        "alert_counts": db.alert_severity_counts(),
        "status_counts": db.alert_status_counts(),
        "alerts_daily": db.alerts_over_time(days),
        "top_rules": db.top_rules(days),
        "top_alert_sources": db.top_alert_sources(days),
        "top_techniques": [{"label": t, "n": n} for t, n in top_tech],
        "case_counts": db.case_status_counts(),
    }


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    a = _alert_analytics(30)
    risk_users = db.top_risk_entities("user", 30, settings.risk_half_life_days, 5) \
        if settings.ueba_enabled else []
    return templates.TemplateResponse(request, "dashboard.html", _ctx(
        request, stats=db.stats(), top_event_sources=db.top_event_sources(7),
        ueba_enabled=settings.ueba_enabled, risk_users=risk_users,
        anomalies=db.anomaly_counts(24) if settings.ueba_enabled else {}, **a))


# --------------------------------------------------------------------------- #
#  Reports & exports                                                          #
# --------------------------------------------------------------------------- #
def _report_days(request: Request) -> int:
    try:
        return min(max(int(request.query_params.get("days", "30")), 1), 365)
    except ValueError:
        return 30


@app.get("/reports", response_class=HTMLResponse)
def reports(request: Request):
    days = _report_days(request)
    a = _alert_analytics(days)
    return templates.TemplateResponse(request, "report.html", _ctx(
        request, stats=db.stats(), top_event_sources=db.top_event_sources(min(days, 30)),
        generated=datetime.now(timezone.utc), **a))


@app.get("/reports/attack-navigator.json")
def reports_navigator(request: Request):
    days = _report_days(request)
    domain = "ics-attack" if request.query_params.get("domain", "").lower().startswith("ics") \
        else "enterprise-attack"
    layer = navigator.build_layer(db.alert_technique_counts(days), days=days, domain=domain)
    tag = "ics_" if domain == "ics-attack" else ""
    return JSONResponse(layer, headers={
        "Content-Disposition": f"attachment; filename=logocean_{tag}attack_{days}d.json"})


def _coverage_rules():
    """The loaded detection + correlation rules for the coverage scoreboard."""
    eng = detection_runtime.get_engine()
    det = list(eng.rules) if eng else []
    return det, list(detection_runtime.get_correlation_rules())


@app.get("/coverage", response_class=HTMLResponse)
def coverage_page(request: Request):
    det, corr = _coverage_rules()
    return templates.TemplateResponse(request, "coverage.html", _ctx(
        request, report=coverage.coverage_report(det, corr)))


@app.get("/coverage.json")
def coverage_report_json(request: Request):
    det, corr = _coverage_rules()
    return JSONResponse(coverage.coverage_report(det, corr))


@app.get("/coverage/attack-navigator.json")
def coverage_navigator(request: Request):
    det, corr = _coverage_rules()
    domain = "ics-attack" if request.query_params.get("domain", "").lower().startswith("ics") \
        else "enterprise-attack"
    layer = coverage.navigator_layer(det + corr, domain=domain)
    tag = "ics_" if domain == "ics-attack" else ""
    return JSONResponse(layer, headers={
        "Content-Disposition": f"attachment; filename=logocean_{tag}coverage.json"})


@app.get("/alerts.csv")
def alerts_csv(request: Request):
    f = _alert_filters(request)
    cols = ["id", "created_at", "event_time", "level", "status", "assignee", "case_id",
            "rule_id", "rule_title", "techniques", "vendor", "src_ip", "dst_ip",
            "user_name", "host_name", "message"]

    def gen():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(cols)
        yield buf.getvalue(); buf.seek(0); buf.truncate(0)
        for row in db.alerts_iter(f):
            w.writerow([_csv_cell(row.get(c, "")) for c in cols])
            yield buf.getvalue(); buf.seek(0); buf.truncate(0)

    return StreamingResponse(gen(), media_type="text/csv", headers={
        "Content-Disposition": "attachment; filename=logocean_alerts.csv"})


# --------------------------------------------------------------------------- #
#  UEBA: entity risk                                                          #
# --------------------------------------------------------------------------- #
@app.get("/risk", response_class=HTMLResponse)
def risk_page(request: Request):
    days, hl = settings.risk_window_days, settings.risk_half_life_days
    return templates.TemplateResponse(request, "risk.html", _ctx(
        request, enabled=settings.ueba_enabled, days=days,
        users=db.top_risk_entities("user", days, hl),
        hosts=db.top_risk_entities("host", days, hl),
        ips=db.top_risk_entities("ip", days, hl),
        new_entities=db.new_entities(24), new_associations=db.new_associations(24)))


@app.get("/sources", response_class=HTMLResponse)
def sources_page(request: Request):
    """Log-source health: every established source with its last-seen age and a
    healthy / silent status (a source that stopped sending is a visibility gap)."""
    now = datetime.now(timezone.utc)
    rows = db.source_activity(settings.source_health_learn_days)
    assessed = sourcehealth.assess(
        rows, now, silence_seconds=settings.source_health_silence_minutes * 60,
        min_events=settings.source_health_min_events)
    sources = [{"key": s.key, "vendor": s.vendor, "log_type": s.log_type,
                "last_seen": s.last_seen, "event_count": s.event_count,
                "age": sourcehealth.human_age(s.age_seconds), "status": s.status}
               for s in assessed]
    return templates.TemplateResponse(request, "sources.html", _ctx(
        request, enabled=settings.source_health_enabled, sources=sources,
        silent=sum(1 for s in sources if s["status"] == "silent"),
        silence_minutes=settings.source_health_silence_minutes,
        learn_days=settings.source_health_learn_days,
        min_events=settings.source_health_min_events))


# --------------------------------------------------------------------------- #
#  OT / ICS analytics                                                         #
# --------------------------------------------------------------------------- #
@app.get("/ot", response_class=HTMLResponse)
def ot_view(request: Request):
    days = _report_days(request)
    activity = db.ot_activity_summary(days)
    return templates.TemplateResponse(request, "ot.html", _ctx(
        request, days=days, protocols=ot.OT_PROTOCOLS,
        assets=db.ot_assets(days),
        conversations=ot.annotate_conversations(db.ot_conversations(days)),
        activity=activity, summary=ot.summarize_activity(activity)))


@app.get("/entity", response_class=HTMLResponse)
def entity_detail(request: Request, etype: str, value: str):
    if etype not in ("user", "host", "ip"):
        return HTMLResponse("Unknown entity type", status_code=404)
    return templates.TemplateResponse(request, "entity.html", _ctx(
        request, etype=etype, value=value, entity=db.get_entity(etype, value),
        associations=db.entity_associations(etype, value),
        alerts=db.entity_alerts(etype, value), activity=db.entity_activity(etype, value)))


# --------------------------------------------------------------------------- #
#  Kill-chain reconstruction                                                  #
# --------------------------------------------------------------------------- #
@app.get("/killchain", response_class=HTMLResponse)
def killchain_page(request: Request):
    q = request.query_params
    try:
        hours = max(int(q.get("hours", settings.killchain_window_hours)), 1)
    except ValueError:
        hours = settings.killchain_window_hours
    stories = []
    if settings.killchain_enabled:
        stories = killchain_runtime.reconstruct_recent(hours=hours)
    existing = db.open_kc_signatures()
    return templates.TemplateResponse(request, "killchain.html", _ctx(
        request, enabled=settings.killchain_enabled, stories=stories, hours=hours,
        window=settings.killchain_window_hours, autocreate=settings.killchain_autocreate,
        existing_signatures=existing))


@app.post("/killchain/create-case")
def killchain_create_case(request: Request, signature: str = Form(...),
                          hours: int = Form(0), _user=Depends(require_role("analyst"))):
    """Persist one reconstructed story (identified by its signature) as a case."""
    win = hours or settings.killchain_window_hours
    story = next((s for s in killchain_runtime.reconstruct_recent(hours=win)
                  if s["signature"] == signature), None)
    if story is None:
        return RedirectResponse(url="/killchain", status_code=303)
    user = getattr(request.state, "user", None)
    cid = db.create_case_from_story(story, created_by=user["username"] if user else None)
    _audit(request, "killchain.create_case",
           f"case {cid} from story ({story['tactic_count']} tactics, "
           f"{story['alert_count']} alerts)")
    return RedirectResponse(url=f"/case/{cid}", status_code=303)


# --------------------------------------------------------------------------- #
#  CIM data models (reference)                                                #
# --------------------------------------------------------------------------- #
# models.yaml states a deliberately-unpopulated model in prose, with this exact marker
# (Email and Vulnerability today). It is the only machine-readable hook the registry
# offers — `CimModel` has no `status:` field — and without it a reader would see a zero
# count next to eleven working models and conclude the detections were broken.
_CIM_AWAITING = "EMPTY BY DESIGN"


# The floor a single count query is still worth issuing at. Below this the remaining
# budget cannot produce an answer, so the model reports "—" instead of burning a round
# trip on a statement the server will cancel before it plans.
_CIM_COUNT_MIN_MS = 250


def _cim_source_text(source: cim.CimSource) -> str:
    """A CIM value source as an analyst reads it: `describe()` minus the `column:`
    prefix, which is noise on the normalized columns and only earns its keep on the
    `raw:` lookups it exists to distinguish."""
    text = source.describe()
    return text[len("column:"):] if source.kind == "column" else text


def _cim_model_view(model: cim.CimModel, count: Optional[int] = None) -> dict:
    """Flatten one CimModel for the template — membership rendered as an OR of clauses,
    each an AND of `<source> in (values)` terms, which is exactly how `match.tags_for`
    and the `cim_<tag>` view both evaluate it."""
    summary, awaiting = model.description, ""
    if _CIM_AWAITING in model.description.upper():
        head, _, tail = model.description.partition(_CIM_AWAITING)
        awaiting = tail.lstrip(":").strip()
        # The remainder is mid-sentence in the YAML; the page starts a sentence with it.
        summary, awaiting = head.strip(), awaiting[:1].upper() + awaiting[1:]
    return {
        "name": model.name, "tag": model.tag, "version": model.version,
        "description": summary, "awaiting": awaiting, "view": cim.view_name(model),
        "clauses": [[f"{_cim_source_text(t.source)} in ({', '.join(t.values)})"
                     for t in c.terms] for c in model.clauses],
        "fields": [{"name": f.name, "source": _cim_source_text(f.source),
                    "description": f.description} for f in model.fields],
        "count": count,
    }


def _cim_member_counts(reg: cim.CimRegistry, days: int) -> dict[str, Optional[int]]:
    """Live member count per model, or None for one that did not finish in budget.

    Counting is one aggregate per model over the indexed `cim_models @> ARRAY[tag]`
    predicate — cheap on a young store, a bitmap heap scan of most of the table on a
    three-year one. So it is never done on a plain page load: the page asks for it
    (`?counts=1`) and CIM_COUNT_DAYS bounds the window, which also lets the planner
    prune whole partitions.

    CIM_COUNT_TIMEOUT_MS is the budget for the WHOLE sweep, not per model: each query
    is given whatever is LEFT of it and models are counted in registry order until it
    runs out, so eleven data models on a starved database cost one budget instead of
    eleven timeouts stacked into a minute-long page load. Whatever the sweep did not
    reach reports None, rendered as an em dash — which is the honest signal that the
    store is too slow to count right now, not that the model is empty. (An even slice
    per model was the obvious alternative and is worse: with a tight budget every slice
    falls under the floor except the last, so only the final model would ever be
    counted, purely because of its position in the file.)

    The counts run through LOQL on purpose: `from datamodel:<tag> | stats count` is the
    very query this page teaches, so the number an analyst reads and the query they are
    being shown cannot drift apart.
    """
    counts: dict[str, Optional[int]] = {}
    deadline = time.monotonic() + settings.cim_count_timeout_ms / 1000
    for tag in reg.tags:
        budget = int(max(deadline - time.monotonic(), 0.0) * 1000)
        if budget < _CIM_COUNT_MIN_MS:
            counts[tag] = None
            continue
        try:
            res = run_query(f'from datamodel:{tag} _time >= "-{int(days)}d" | stats count',
                            limit=1, max_rows=1, timeout_ms=budget)
            counts[tag] = int(res["rows"][0]["count"]) if res["rows"] else 0
        except LoqlError as exc:      # a timeout, or the store is unreachable
            counts[tag] = None
            log.warning("CIM member count for %r did not complete: %s", tag, exc)
    return counts


def _cim_stamp() -> dict:
    """`db.cim_status()` that degrades instead of raising. The CIM tables are the
    newest thing in schema.sql, so a database that predates them must still be able to
    render this page and /admin — those are where an operator goes to find out why."""
    try:
        return db.cim_status()
    except Exception as exc:  # noqa: BLE001 — the stamp is diagnostics, not a feature
        log.warning("could not read the CIM registry stamp: %s", exc)
        return {"error": str(exc), "backfill_due": False, "current_tags": []}


def _cim_registry_or_error() -> tuple[Optional[cim.CimRegistry], Optional[str]]:
    """``(registry, None)``, or ``(None, message)`` when models.yaml will not load.

    The same treatment `_cim_stamp` gives the database, for the same reason: /datamodels
    and /admin are where an operator goes to find out what broke, so every fragile read
    behind them has to degrade into an explanation rather than a 500. This one was the
    exception — an unguarded `cim.get_registry()` on the first line of the page — so the
    page survived a database outage and died on precisely the registry defect it exists
    to explain, while its own docstring claimed it renders "from the registry alone".

    A running process should not normally reach the error branch at all: startup refuses
    to boot on a registry this cannot load. It is reachable after a live edit plus
    `cim.reload()`, and it is exactly then that someone needs the page.
    """
    try:
        return cim.get_registry(), None
    except Exception as exc:  # noqa: BLE001 — rendered, not raised; see the docstring
        log.exception("the CIM registry could not be loaded while rendering /datamodels")
        return None, f"app/cim/models.yaml could not be loaded: {exc}"


@app.get("/datamodels", response_class=HTMLResponse)
def datamodels_page(request: Request, _user=Depends(require_role("viewer"))):
    """The CIM registry as a reference page: every model with its membership rule, its
    fields, and how to query it. Renders from the registry alone, so it still explains
    the schema when the database is unreachable — and renders the reason, rather than a
    500, when it is the registry itself that is unreadable."""
    reg, reg_error = _cim_registry_or_error()
    days = settings.cim_count_days
    counting = reg is not None and request.query_params.get("counts") == "1" and days > 0
    counts = _cim_member_counts(reg, days) if counting else {}
    # `registry_error` and `init.error` are two different failures and the template now
    # renders them as two — an unloadable registry (nothing is tagged) ahead of, and
    # separately from, a view that would not rebuild (a reporting gap). They were briefly
    # merged into one slot only because the template rendered `init.error` and nothing
    # else; merging them also hid the registry error entirely under CIM_ENABLED=false,
    # where the "views are disabled" banner matched first.
    return templates.TemplateResponse(request, "datamodels.html", _ctx(
        request,
        models=[_cim_model_view(m, counts.get(m.tag)) for m in reg.models] if reg else [],
        registry_version=reg.version if reg else None,
        enabled=settings.cim_enabled, init=_cim_init, registry_error=reg_error,
        status=_cim_stamp(), counting=counting, count_days=days))


# --------------------------------------------------------------------------- #
#  Detection-engineering workbench                                            #
# --------------------------------------------------------------------------- #
_WORKBENCH_SAMPLE_RULE = """title: Encoded PowerShell
id: demo-encoded-powershell
level: high
logsource:
  product: windows
detection:
  sel:
    message|contains:
      - '-enc'
      - '-EncodedCommand'
  condition: sel
tags:
  - attack.execution
  - attack.t1059.001
"""
_WORKBENCH_SAMPLE_EVENT = ('{\n  "vendor": "microsoft",\n'
                           '  "host_name": "WS1",\n'
                           '  "user_name": "alice",\n'
                           '  "message": "powershell.exe -enc SQBFAFgA"\n}')


def _workbench_page(request: Request, *, result=None, rule_yaml=_WORKBENCH_SAMPLE_RULE,
                    event_json=_WORKBENCH_SAMPLE_EVENT, **extra):
    days = settings.workbench_window_days
    rules = db.rule_stats(days)
    return templates.TemplateResponse(request, "workbench.html", _ctx(
        request, days=days, coverage=workbench.coverage_map(rules),
        health=workbench.rule_health(rules, settings.workbench_noisy_threshold),
        rules=rules, result=result, rule_yaml=rule_yaml, event_json=event_json, **extra))


@app.get("/workbench", response_class=HTMLResponse)
def workbench_page(request: Request):
    return _workbench_page(request)


@app.post("/workbench/test", response_class=HTMLResponse)
def workbench_test(request: Request, rule_yaml: str = Form(""),
                   event_json: str = Form("")):
    result = workbench.test_rule(rule_yaml, event_json)
    return _workbench_page(request, result=result, rule_yaml=rule_yaml, event_json=event_json)


@app.post("/workbench/generate", response_class=HTMLResponse)
def workbench_generate(request: Request, description: str = Form(""),
                       event_json: str = Form(_WORKBENCH_SAMPLE_EVENT),
                       _user=Depends(require_role("analyst"))):
    """AI copilot: turn a natural-language description into a Sigma rule, pre-filled
    into the rule tester so the analyst can immediately test it (audited)."""
    if not description.strip():
        return _workbench_page(request, event_json=event_json,
                               ai_error="Describe the detection you want first.")
    if not copilot.is_configured():
        return _workbench_page(request, event_json=event_json,
                               ai_error="AI copilot is not configured (set COPILOT_ENABLED "
                                        "and an API key).")
    try:
        gen = copilot.generate_sigma(copilot.build_client(), description, event_json or None)
    except copilot.CopilotError as e:
        return _workbench_page(request, event_json=event_json, ai_error=str(e))
    _audit(request, "copilot.generate_sigma", description.strip()[:120])
    rule_yaml = gen["yaml"] or _WORKBENCH_SAMPLE_RULE
    note = ("Generated rule loaded below — review and test it before adding to rules/."
            if gen["yaml"] else "")
    err = None if gen["valid"] else (gen["error"] or "Generated rule may be invalid.")
    return _workbench_page(request, rule_yaml=rule_yaml, event_json=event_json,
                           ai_generated=note, ai_error=err, ai_description=description)


# --------------------------------------------------------------------------- #
#  Upload                                                                      #
# --------------------------------------------------------------------------- #
@app.get("/upload", response_class=HTMLResponse)
def upload_form(request: Request):
    return templates.TemplateResponse(
        request, "upload.html", _ctx(request, result=None, error=None))


@app.post("/upload", response_class=HTMLResponse)
async def upload(request: Request, file: UploadFile = File(...), fmt: str = Form("auto"),
                 _user=Depends(require_role("analyst"))):
    cap = settings.max_upload_mb * 1024 * 1024
    raw = await _read_capped(file, cap)
    if raw is None:
        return templates.TemplateResponse(request, "upload.html", _ctx(
            request, result=None,
            error=f"File exceeds the {settings.max_upload_mb} MB limit."))
    # Transparently gunzip a .gz upload (by magic bytes) under the same size budget.
    raw = await run_in_threadpool(gunzip_capped, raw, cap)
    if raw is None:
        return templates.TemplateResponse(request, "upload.html", _ctx(
            request, result=None,
            error=f"The gzip file is corrupt or expands past the {settings.max_upload_mb} MB limit."))

    content = raw.decode("utf-8", "replace")
    name = file.filename or ""
    hint = name[:-3] if name.endswith(".gz") else name
    chosen = fmt
    if fmt == "auto":
        chosen = detect_format(hint, content)
        if chosen is None:
            return templates.TemplateResponse(request, "upload.html", _ctx(
                request, result=None,
                error="Could not auto-detect the format. Please pick one explicitly."))

    src = request.client.host if request.client else None
    try:
        # Parsing + DB I/O is blocking and CPU-bound — keep it off the event loop.
        result = await run_in_threadpool(
            ingest.ingest, content, chosen, filename=file.filename, source_addr=src)
    except Exception:  # noqa: BLE001
        log.exception("ingest failed for %r (format=%s)", file.filename, chosen)
        return templates.TemplateResponse(request, "upload.html", _ctx(
            request, result=None,
            error="Ingest failed. The file could not be processed — see server logs for details."))
    await run_in_threadpool(
        _audit, request, "upload",
        f"{file.filename}: {result['inserted']} stored ({chosen})")
    return templates.TemplateResponse(
        request, "upload.html", _ctx(request, result=result, error=None))


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
    return templates.TemplateResponse(request, "search.html", _ctx(
        request, rows=rows, total=total, page=page, pages=pages,
        params=request.query_params, base_qs=base_qs,
        saved=db.list_saved_searches(_owner(request), "/search"),
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
            w.writerow([_csv_cell(row.get(c, "")) for c in cols])
            yield buf.getvalue(); buf.seek(0); buf.truncate(0)

    return StreamingResponse(gen(), media_type="text/csv", headers={
        "Content-Disposition": "attachment; filename=logocean_export.csv"})


@app.post("/searches")
def save_search(request: Request, name: str = Form(...), path: str = Form("/search"),
                query: str = Form(""), _user=Depends(require_role("viewer"))):
    if saved.is_valid(name, path):
        p = saved.normalize_path(path)
        db.add_saved_search(_owner(request), saved.clean_name(name), p, saved.clean_query(query))
        _audit(request, "saved_search.create", f"{saved.clean_name(name)} ({p})")
    return RedirectResponse(url=saved.target_url(path, query), status_code=303)


@app.post("/searches/{search_id}/delete")
def delete_search(request: Request, search_id: int, path: str = Form("/search"),
                  _user=Depends(require_role("viewer"))):
    db.delete_saved_search(search_id, _owner(request))
    _audit(request, "saved_search.delete", f"#{search_id}")
    return RedirectResponse(url=saved.normalize_path(path), status_code=303)


@app.get("/event/{event_id}", response_class=HTMLResponse)
def event_detail(request: Request, event_id: int):
    ev = db.get_event(event_id)
    if ev is None:
        return HTMLResponse("Event not found", status_code=404)
    return templates.TemplateResponse(request, "event.html", _ctx(request, ev=ev))


# --------------------------------------------------------------------------- #
#  Alerts                                                                      #
# --------------------------------------------------------------------------- #
def _alert_filters(request: Request) -> dict:
    q = request.query_params
    return {"status": q.get("status") or None, "level": q.get("level") or None,
            "rule_id": q.get("rule_id") or None, "assignee": q.get("assignee") or None,
            "q": q.get("q") or None}


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
    return templates.TemplateResponse(request, "alerts.html", _ctx(
        request, rows=rows, total=total, page=page, pages=pages,
        params=request.query_params, base_qs=base_qs,
        saved=db.list_saved_searches(_owner(request), "/alerts"),
        counts=db.alert_severity_counts()))


def _alert_page(request: Request, alert_id: int, **extra):
    """Build the alert-detail template response (shared by GET and the AI action)."""
    a = db.get_alert(alert_id)
    if a is None:
        return None
    event_id = db.event_id_for(a["dedup_hash"], a["event_time"])
    return templates.TemplateResponse(request, "alert.html", _ctx(
        request, a=a, event_id=event_id, responses=db.responses_for_alert(alert_id),
        notes=db.alert_notes(alert_id),
        users=db.list_users() if settings.auth_enabled else [],
        case=db.get_case(a["case_id"]) if a.get("case_id") else None,
        open_cases=db.open_cases(), **extra))


@app.get("/alert/{alert_id}", response_class=HTMLResponse)
def alert_detail(request: Request, alert_id: int):
    page = _alert_page(request, alert_id)
    return page if page is not None else HTMLResponse("Alert not found", status_code=404)


@app.post("/alert/{alert_id}/explain", response_class=HTMLResponse)
def alert_explain(request: Request, alert_id: int, _user=Depends(require_role("analyst"))):
    """Ask the AI copilot to explain and triage this alert (read-only, audited)."""
    a = db.get_alert(alert_id)
    if a is None:
        return HTMLResponse("Alert not found", status_code=404)
    if not copilot.is_configured():
        return _alert_page(request, alert_id,
                           ai_error="AI copilot is not configured (set COPILOT_ENABLED "
                                     "and an API key).")
    related = [r for r in db.related_alerts_for(alert_id, limit=8) if r["id"] != alert_id]
    try:
        text = copilot.explain_alert(copilot.build_client(), a, related)
        _audit(request, "copilot.explain_alert", f"alert {alert_id}")
        return _alert_page(request, alert_id, ai_explanation=text)
    except copilot.CopilotError as e:
        return _alert_page(request, alert_id, ai_error=str(e))


@app.post("/alert/{alert_id}/status")
def alert_set_status(request: Request, alert_id: int, status: str = Form(...),
                     _user=Depends(require_role("analyst"))):
    if status in ("open", "ack", "closed"):
        db.set_alert_status(alert_id, status)
        _audit(request, "alert.status", f"alert {alert_id} -> {status}")
    return RedirectResponse(url=f"/alert/{alert_id}", status_code=303)


@app.post("/alert/{alert_id}/assign")
def alert_assign(request: Request, alert_id: int, assignee: str = Form(""),
                 _user=Depends(require_role("analyst"))):
    db.set_alert_assignee(alert_id, assignee.strip() or None)
    _audit(request, "alert.assign", f"alert {alert_id} -> {assignee.strip() or 'unassigned'}")
    return RedirectResponse(url=f"/alert/{alert_id}", status_code=303)


@app.post("/alert/{alert_id}/note")
def alert_add_note(request: Request, alert_id: int, note: str = Form(...),
                   _user=Depends(require_role("analyst"))):
    text = note.strip()
    if text:
        user = getattr(request.state, "user", None)
        db.add_alert_note(alert_id, user["username"] if user else None, text[:4000])
        _audit(request, "alert.note", f"alert {alert_id}")
    return RedirectResponse(url=f"/alert/{alert_id}", status_code=303)


@app.post("/alert/{alert_id}/suppress")
def alert_suppress(request: Request, alert_id: int, fields: list[str] = Form([]),
                   reason: str = Form(""), _user=Depends(require_role("analyst"))):
    """Create an allowlist rule from the chosen attributes of this alert."""
    a = db.get_alert(alert_id)
    if a is None:
        return HTMLResponse("Alert not found", status_code=404)
    crit = {f: a.get(f) for f in ("rule_id", "src_ip", "user_name", "host_name", "vendor")
            if f in fields and a.get(f)}
    if not crit:
        return RedirectResponse(url=f"/alert/{alert_id}", status_code=303)
    user = getattr(request.state, "user", None)
    name = f"from alert #{alert_id}: " + ", ".join(f"{k}={v}" for k, v in crit.items())
    db.create_suppression(name[:200], reason=reason.strip() or None,
                          created_by=user["username"] if user else None, **crit)
    triage_runtime.reload_index()
    _audit(request, "suppression.create", name[:200])
    return RedirectResponse(url=f"/alert/{alert_id}", status_code=303)


@app.post("/alert/{alert_id}/case")
def alert_to_case(request: Request, alert_id: int, case_id: str = Form(...),
                  _user=Depends(require_role("analyst"))):
    """Attach an alert to an existing case, or seed a new case from it."""
    a = db.get_alert(alert_id)
    if a is None:
        return HTMLResponse("Alert not found", status_code=404)
    if case_id == "new":
        user = getattr(request.state, "user", None)
        cid = db.create_case(title=f"{a['rule_title']}"[:200], severity=a["level"],
                             created_by=user["username"] if user else None)
        _audit(request, "case.create", f"case {cid} from alert {alert_id}")
    else:
        cid = int(case_id)
    db.add_alert_to_case(alert_id, cid)
    _audit(request, "case.add_alert", f"alert {alert_id} -> case {cid}")
    return RedirectResponse(url=f"/case/{cid}", status_code=303)


# --------------------------------------------------------------------------- #
#  Cases / incidents                                                          #
# --------------------------------------------------------------------------- #
@app.get("/cases", response_class=HTMLResponse)
def cases(request: Request):
    q = request.query_params
    f = {"status": q.get("status") or None, "assignee": q.get("assignee") or None,
         "q": q.get("q") or None}
    try:
        page = max(int(q.get("page", "1")), 1)
    except ValueError:
        page = 1
    limit = settings.page_size
    rows, total = db.list_cases(f, limit=limit, offset=(page - 1) * limit)
    pages = max((total + limit - 1) // limit, 1)
    base_qs = urlencode([(k, v) for k, v in q.multi_items() if k != "page" and v])
    return templates.TemplateResponse(request, "cases.html", _ctx(
        request, rows=rows, total=total, page=page, pages=pages, params=q,
        base_qs=base_qs, counts=db.case_status_counts()))


def _case_page(request: Request, case_id: int, **extra):
    c = db.get_case(case_id)
    if c is None:
        return None
    return templates.TemplateResponse(request, "case.html", _ctx(
        request, c=c, alerts=db.case_alerts(case_id), notes=db.case_notes(case_id),
        related=db.related_open_alerts(case_id),
        users=db.list_users() if settings.auth_enabled else [], **extra))


@app.get("/case/{case_id}", response_class=HTMLResponse)
def case_detail(request: Request, case_id: int):
    page = _case_page(request, case_id)
    return page if page is not None else HTMLResponse("Case not found", status_code=404)


@app.post("/case/{case_id}/summarize", response_class=HTMLResponse)
def case_summarize(request: Request, case_id: int, _user=Depends(require_role("analyst"))):
    """Ask the AI copilot to summarize the case for a handoff / report (audited)."""
    c = db.get_case(case_id)
    if c is None:
        return HTMLResponse("Case not found", status_code=404)
    if not copilot.is_configured():
        return _case_page(request, case_id,
                          ai_error="AI copilot is not configured (set COPILOT_ENABLED "
                                    "and an API key).")
    try:
        text = copilot.summarize_case(
            copilot.build_client(), c, db.case_alerts(case_id), db.case_notes(case_id))
        _audit(request, "copilot.summarize_case", f"case {case_id}")
        return _case_page(request, case_id, ai_summary=text)
    except copilot.CopilotError as e:
        return _case_page(request, case_id, ai_error=str(e))


@app.post("/cases/new", response_class=HTMLResponse)
def case_create(request: Request, title: str = Form(...), summary: str = Form(""),
                severity: str = Form("medium"), _user=Depends(require_role("analyst"))):
    user = getattr(request.state, "user", None)
    cid = db.create_case(title.strip() or "untitled", summary.strip() or None,
                         severity=severity, created_by=user["username"] if user else None)
    _audit(request, "case.create", f"case {cid}")
    return RedirectResponse(url=f"/case/{cid}", status_code=303)


@app.post("/case/{case_id}/update")
def case_update(request: Request, case_id: int, title: str = Form(...),
                summary: str = Form(""), status: str = Form(...),
                severity: str = Form(...), assignee: str = Form(""),
                _user=Depends(require_role("analyst"))):
    st = status if status in ("open", "investigating", "closed") else "open"
    db.update_case(case_id, title=title.strip() or "untitled", summary=summary.strip(),
                   status=st, severity=severity, assignee=assignee.strip())
    _audit(request, "case.update", f"case {case_id} -> {st}")
    return RedirectResponse(url=f"/case/{case_id}", status_code=303)


@app.post("/case/{case_id}/note")
def case_add_note(request: Request, case_id: int, note: str = Form(...),
                  _user=Depends(require_role("analyst"))):
    text = note.strip()
    if text:
        user = getattr(request.state, "user", None)
        db.add_case_note(case_id, user["username"] if user else None, text[:4000])
        _audit(request, "case.note", f"case {case_id}")
    return RedirectResponse(url=f"/case/{case_id}", status_code=303)


@app.post("/case/{case_id}/add-alerts")
def case_add_alerts(request: Request, case_id: int, alert_ids: list[int] = Form([]),
                    _user=Depends(require_role("analyst"))):
    if alert_ids:
        db.add_alerts_to_case(case_id, alert_ids)
        _audit(request, "case.add_alert", f"{len(alert_ids)} alert(s) -> case {case_id}")
    return RedirectResponse(url=f"/case/{case_id}", status_code=303)


@app.post("/case/{case_id}/remove-alert")
def case_remove_alert(request: Request, case_id: int, alert_id: int = Form(...),
                      _user=Depends(require_role("analyst"))):
    db.remove_alert_from_case(alert_id)
    _audit(request, "case.remove_alert", f"alert {alert_id} from case {case_id}")
    return RedirectResponse(url=f"/case/{case_id}", status_code=303)


@app.get("/responses", response_class=HTMLResponse)
def responses(request: Request):
    return templates.TemplateResponse(request, "responses.html", _ctx(
        request, rows=db.recent_responses(200)))


@app.get("/compliance", response_class=HTMLResponse)
def compliance_view(request: Request):
    enabled_techniques: set[str] = set()
    for r in db.list_rules():
        if r["enabled"]:
            enabled_techniques.update(t.upper() for t in (r["techniques"] or []))
    report = compliance.build_report(enabled_techniques, db.alert_technique_counts(30))
    return templates.TemplateResponse(request, "compliance.html", _ctx(
        request, report=report, frameworks=compliance.FRAMEWORKS))


# --------------------------------------------------------------------------- #
#  Admin / retention                                                           #
# --------------------------------------------------------------------------- #
def _render_admin(request: Request, *, purged=None, new_key=None, user_error=None,
                  ti_error=None, vault_error=None, vault_notice=None):
    return templates.TemplateResponse(request, "admin.html", _ctx(
        request, batches=db.recent_batches(100), stats=db.stats(),
        api_keys=db.list_api_keys(), rules=db.list_rules(),
        collectors=db.list_collectors(),
        users=db.list_users() if settings.auth_enabled else [],
        roles=auth.ROLES, audit=db.recent_audit(50),
        ti_enabled=settings.threatintel_enabled, ti_counts=db.ioc_counts(),
        ti_indicators=db.list_iocs(25), ti_index_size=len(ti_runtime.get_index()),
        ti_types=ti_matcher.VALID_TYPES, suppressions=db.list_suppressions(),
        cim_status=_cim_stamp(), cim_init=_cim_init, cim_backfill=_cim_backfill,
        vault_status=vault.status(), vault_secrets=db.list_secrets(),
        vault_slots=collectors.runner.KNOWN_SLOTS,
        vault_error=vault_error, vault_notice=vault_notice,
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
#  CIM membership backfill (admin)                                            #
# --------------------------------------------------------------------------- #
async def _cim_backfill_job(actor: Optional[str], ip: Optional[str]) -> None:
    """Run one backfill off the event loop and record how it went.

    The completion entry goes to `db.add_audit` directly rather than through `_audit`:
    by the time it lands, the request that started it is long gone, so the actor and
    client address are the ones captured at the POST. Both halves are recorded because
    the interesting fact — how many rows changed tags — is only known at the end.
    """
    def _publish(snapshot: dict) -> None:
        """Republish the running counters after every committed chunk.

        Called from the threadpool worker, which is safe here: it is a single dict
        assignment, and everything that reads it (the /admin page, the shutdown handler)
        wants the latest snapshot rather than a consistent series. Without it `last_id`
        — the resume cursor for an interrupted run — is invisible until the run is over,
        which is the one moment nobody needs it.
        """
        _cim_backfill["progress"] = snapshot

    try:
        res = await run_in_threadpool(db.backfill_cim,
                                      chunk=settings.cim_backfill_chunk,
                                      progress=_publish)
        _cim_backfill.update(state="done", result=res, error=None,
                             finished_at=datetime.now(timezone.utc))
        detail = (f"scanned {res['scanned']}, retagged {res['updated']}, "
                  f"unchanged {res['unchanged']} in {res['seconds']}s")
    except Exception as exc:  # noqa: BLE001 — a background job must not die silently
        log.exception("CIM membership backfill failed")
        # `progress` is left as it stands on purpose: the run committed every chunk it
        # completed, so its last snapshot is the resume cursor for whoever retries.
        _cim_backfill.update(state="error", error=str(exc), result=None,
                             finished_at=datetime.now(timezone.utc))
        detail = f"failed: {exc}"[:300]
    await run_in_threadpool(db.add_audit, actor, "cim.backfill.finished", detail, ip)


@app.post("/admin/cim/backfill")
async def admin_cim_backfill(request: Request, _user=Depends(require_role("admin"))):
    """Start the membership backfill in the background and redirect straight back.

    It is UPDATE traffic across every partition of `events`, so holding the request
    open for it would tie up a worker for minutes and hand the operator a gateway
    timeout instead of an answer. One run at a time: a second click while one is in
    flight is refused (and audited) rather than doubling the write load.
    """
    global _cim_backfill_task
    if _cim_backfill["state"] == "running":
        await run_in_threadpool(_audit, request, "cim.backfill.denied",
                                "a backfill is already running")
        return RedirectResponse(url="/admin", status_code=303)
    user = getattr(request.state, "user", None)
    actor = user["username"] if user else None
    _cim_backfill.update(state="running", by=actor, result=None, progress=None,
                         error=None, started_at=datetime.now(timezone.utc),
                         finished_at=None)
    await run_in_threadpool(_audit, request, "cim.backfill",
                            f"started (chunk {settings.cim_backfill_chunk})")
    _cim_backfill_task = asyncio.create_task(
        _cim_backfill_job(actor, request.client.host if request.client else None))
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
#  Secrets vault (admin)                                                      #
# --------------------------------------------------------------------------- #
# NOTHING HERE EVER RENDERS OR LOGS A SECRET VALUE. The page reads `db.list_secrets`,
# which does not select the ciphertext at all, and the audit entries record the SLOT
# (integration/name), never the value — an audit log that leaks the credential it is
# auditing would be worse than no audit log.
@app.post("/admin/vault/secret", response_class=HTMLResponse)
def admin_vault_set(request: Request, integration: str = Form(...), name: str = Form(...),
                    value: str = Form(...), _user=Depends(require_role("admin"))):
    integration, name = integration.strip().lower(), name.strip().lower()
    try:
        vault.set_secret(integration, name, value, _owner(request))
    except vault.VaultError as e:
        _audit(request, "vault.set.failed", f"{integration}/{name}: {e}")
        return _render_admin(request, vault_error=str(e))
    _audit(request, "vault.set", f"{integration}/{name}")
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/vault/delete")
def admin_vault_delete(request: Request, integration: str = Form(...),
                       name: str = Form(...), _user=Depends(require_role("admin"))):
    removed = vault.delete_secret(integration.strip().lower(), name.strip().lower())
    _audit(request, "vault.delete",
           f"{integration}/{name}" + ("" if removed else " (not present)"))
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/vault/migrate", response_class=HTMLResponse)
def admin_vault_migrate(request: Request, _user=Depends(require_role("admin"))):
    """Import plaintext env-var credentials into the vault (idempotent)."""
    try:
        moved = collectors.runner.migrate_env_secrets(_owner(request))
    except vault.VaultError as e:
        _audit(request, "vault.migrate.failed", str(e))
        return _render_admin(request, vault_error=str(e))
    _audit(request, "vault.migrate", f"imported {len(moved)}: {', '.join(moved) or 'none'}")
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/vault/rotate", response_class=HTMLResponse)
def admin_vault_rotate(request: Request, new_key: str = Form(...),
                       _user=Depends(require_role("admin"))):
    """Re-seal every secret under a new master key.

    The operator must then put `new_key` into VAULT_KEY and restart — this process cannot
    edit its own environment. Until they do, the running process still holds the OLD key
    and every secret will fail to open, so the audit entry records the new key_id to
    check against the admin page after the restart.
    """
    try:
        result = vault.rotate_key(new_key.strip())
    except vault.VaultError as e:
        _audit(request, "vault.rotate.failed", str(e))
        return _render_admin(request, vault_error=str(e))
    _audit(request, "vault.rotate",
           f"re-sealed {result.rotated} secret(s) to key_id={result.to_key_id}")
    return _render_admin(
        request,
        vault_notice=(f"Re-sealed {result.rotated} secret(s) under key_id {result.to_key_id}. "
                "Set VAULT_KEY to the new key and restart — until you do, this process "
                "still holds the old key and cannot read them."))


# --------------------------------------------------------------------------- #
#  Suppressions / allowlists (admin)                                          #
# --------------------------------------------------------------------------- #
@app.post("/admin/suppressions", response_class=HTMLResponse)
def admin_suppression_add(request: Request, name: str = Form(...),
                          rule_id: str = Form(""), src_ip: str = Form(""),
                          user_name: str = Form(""), host_name: str = Form(""),
                          vendor: str = Form(""), reason: str = Form(""),
                          _user=Depends(require_role("admin"))):
    crit = {"rule_id": rule_id.strip(), "src_ip": src_ip.strip(),
            "user_name": user_name.strip(), "host_name": host_name.strip(),
            "vendor": vendor.strip()}
    if not any(crit.values()):
        return _render_admin(request,
                             ti_error="A suppression needs at least one condition "
                                      "(rule, src ip, user, host or vendor).")
    user = getattr(request.state, "user", None)
    db.create_suppression(name.strip() or "unnamed", reason=reason.strip() or None,
                          created_by=user["username"] if user else None,
                          **{k: v or None for k, v in crit.items()})
    triage_runtime.reload_index()
    _audit(request, "suppression.create", name.strip())
    return _render_admin(request)


@app.post("/admin/suppressions/{supp_id}/toggle")
def admin_suppression_toggle(request: Request, supp_id: int, enabled: str = Form(...),
                             _user=Depends(require_role("admin"))):
    on = enabled == "true"
    db.set_suppression_enabled(supp_id, on)
    triage_runtime.reload_index()
    _audit(request, "suppression.toggle", f"{supp_id} -> {'enabled' if on else 'disabled'}")
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/suppressions/{supp_id}/delete")
def admin_suppression_delete(request: Request, supp_id: int,
                             _user=Depends(require_role("admin"))):
    db.delete_suppression(supp_id)
    triage_runtime.reload_index()
    _audit(request, "suppression.delete", str(supp_id))
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
        if role != "admin" and db.is_last_admin(user_id):
            _audit(request, "user.role.denied",
                   f"blocked demoting the last enabled admin (user {user_id})")
        else:
            db.set_user_role(user_id, role)
            _audit(request, "user.role", f"user {user_id} -> {role}")
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/users/{user_id}/toggle")
def admin_toggle_user(request: Request, user_id: int, enabled: str = Form(...),
                      _user=Depends(require_role("admin"))):
    on = enabled == "true"
    if not on and db.is_last_admin(user_id):
        _audit(request, "user.toggle.denied",
               f"blocked disabling the last enabled admin (user {user_id})")
    else:
        db.set_user_enabled(user_id, on)
        _audit(request, "user.toggle", f"user {user_id} -> {'enabled' if on else 'disabled'}")
    return RedirectResponse(url="/admin", status_code=303)


# --------------------------------------------------------------------------- #
#  Content packs (import / export / uninstall)                                 #
# --------------------------------------------------------------------------- #
# These are the WRITE routes, and they live on the console rather than on /api/v1
# deliberately: an `api_keys` row carries no role, so a key issued to a log forwarder
# for POST /ingest would otherwise also be able to install detection rules and parsers.
# /api/v1 keeps the side-effect-free half (validate / plan / list / export) so CI can
# diff a pack without a session.

def _app_version() -> str:
    """The running LogOcean version, for a pack's `requires: {logocean: ">=x.y"}`."""
    from . import __version__
    return __version__


def _pack_key() -> str:
    """The HMAC signing key, resolved through the vault like a collector credential."""
    return vault.get("contentpack", "key", settings.content_pack_key)


def _installed_pack_rows() -> list[dict]:
    """Installed packs for the table, each with its signature verdict."""
    key = _pack_key()
    rows = []
    for row in db.list_content_packs():
        sig = None
        try:
            pack = contentpack.parse(str(row["document"]))
            if pack.signature is None:
                sig = "unsigned"
            elif key:
                sig = "valid" if contentpack.verify(pack, key) else "invalid"
        except Exception:  # noqa: BLE001 — a stored row must never break the page
            sig = None
        rows.append(dict(row, signature=sig))
    return rows


def _plan_ctx(plan) -> dict:
    """An ImportPlan flattened for the template (Jinja gets data, not objects)."""
    return {"pack": plan.pack.name, "version": plan.pack.version,
            "summary": plan.summary(), "applicable": plan.applicable,
            "restart_required": plan.restart_required,
            "problems": list(plan.problems),
            "conflicts": [c.describe() for c in plan.conflicts],
            "changes": [{"kind": c.kind, "ident": c.ident, "verb": c.verb,
                         "detail": c.detail, "owner": c.owner} for c in plan.changes]}


@app.get("/packs", response_class=HTMLResponse)
def packs_page(request: Request, _user=Depends(require_role("admin"))):
    return templates.TemplateResponse(request, "packs.html", _ctx(
        request, packs=_installed_pack_rows()))


@app.post("/packs/plan", response_class=HTMLResponse)
def packs_plan(request: Request, document: str = Form(...),
               _user=Depends(require_role("admin"))):
    """Dry run. Reads the DB to work out ownership; writes nothing."""
    plan = error = None
    try:
        plan = _plan_ctx(contentpack.install(document, dry_run=True,
                                             app_version=_app_version()))
    except contentpack.PackError as exc:
        error = str(exc)
    return templates.TemplateResponse(request, "packs.html", _ctx(
        request, packs=_installed_pack_rows(), plan=plan, error=error,
        document=document))


@app.post("/packs/import", response_class=HTMLResponse)
def packs_import(request: Request, document: str = Form(...),
                 overwrite: str = Form(""), _user=Depends(require_role("admin"))):
    message = error = None
    plan = None
    try:
        result = contentpack.install(document, overwrite=bool(overwrite), dry_run=False,
                                     app_version=_app_version(),
                                     installed_by=_owner(request))
    except contentpack.PackError as exc:
        error = str(exc)
    else:
        if isinstance(result, contentpack.ImportPlan):
            # `install` hands back the PLAN rather than applying when the pack has
            # problems or unresolved conflicts — show exactly why instead of a bare
            # "failed", which is the difference between a fixable and a mysterious error.
            plan = _plan_ctx(result)
            error = "Not imported. Resolve the problems below, or tick overwrite."
        else:
            _audit(request, "content_pack.import",
                   f"{result.pack.key} digest={contentpack.digest(result.pack)}")
            # Parsers and rules are hot-reloadable; CIM membership and compliance are
            # process-cached and honestly reported as needing a restart instead.
            custom_parser.reload()
            if settings.detection_enabled:
                detection_runtime.load_and_sync(BASE.parent / "rules")
            message = (f"Imported {result.pack.key}: "
                       + "; ".join(c.describe() for c in result.applied))
            if result.restart_required:
                message += (" — RESTART REQUIRED for the CIM/compliance half, then run "
                            "the membership backfill from Admin, in that order.")
    return templates.TemplateResponse(request, "packs.html", _ctx(
        request, packs=_installed_pack_rows(), plan=plan, message=message, error=error,
        document=document))


@app.post("/packs/uninstall", response_class=HTMLResponse)
def packs_uninstall(request: Request, name: str = Form(...),
                    _user=Depends(require_role("admin"))):
    message = error = None
    try:
        result = contentpack.uninstall(name, dry_run=False)
    except contentpack.PackError as exc:
        error = str(exc)
    else:
        _audit(request, "content_pack.uninstall", name)
        custom_parser.reload()
        if settings.detection_enabled:
            detection_runtime.load_and_sync(BASE.parent / "rules")
        removed = "; ".join(c.describe() for c in getattr(result, "applied", ()))
        message = f"Uninstalled {name}" + (f": {removed}" if removed else "")
    return templates.TemplateResponse(request, "packs.html", _ctx(
        request, packs=_installed_pack_rows(), message=message, error=error))


# --------------------------------------------------------------------------- #
#  Custom parsers (console-authored field maps)                                #
# --------------------------------------------------------------------------- #

def _parse_field_map(text: str) -> dict:
    """Parse the textarea form of a field map: one `raw_key -> column` per line."""
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for sep in ("->", "=>", "="):
            if sep in line:
                k, _, v = line.partition(sep)
                k, v = k.strip(), v.strip()
                if k and v:
                    out[k] = v
                break
    return out


def _field_map_text(fm: dict) -> str:
    return "\n".join(f"{k} -> {v}" for k, v in (fm or {}).items())


@app.get("/parsers", response_class=HTMLResponse)
def parsers_page(request: Request, _user=Depends(require_role("admin"))):
    rows = db.list_custom_parsers()
    for r in rows:
        r["field_map_text"] = _field_map_text(r.get("field_map"))
    return templates.TemplateResponse(request, "parsers.html", _ctx(
        request, parsers=rows, columns=sorted(custom_parser._ALLOWED)))


@app.post("/parsers/save")
def parsers_save(request: Request,
                 parser_id: str = Form(...), title: str = Form(...),
                 match_key: str = Form(...), match_value: str = Form(...),
                 field_map: str = Form(""), vendor: str = Form(""),
                 product: str = Form(""), kv_source: str = Form(""),
                 kv_sep: str = Form(""), enabled: str = Form("on"),
                 _user=Depends(require_role("admin"))):
    db.upsert_custom_parser(
        parser_id.strip(), title.strip(), match_key.strip(), match_value.strip(),
        _parse_field_map(field_map), vendor.strip() or None, product.strip() or None,
        enabled == "on", kv_source.strip() or None, kv_sep.strip() or None)
    custom_parser.reload()          # hot reload -- no restart needed
    _audit(request, "parser.save", parser_id)
    return RedirectResponse(url="/parsers", status_code=303)


@app.post("/parsers/delete")
def parsers_delete(request: Request, parser_id: str = Form(...),
                   _user=Depends(require_role("admin"))):
    db.delete_custom_parser(parser_id)
    custom_parser.reload()
    _audit(request, "parser.delete", parser_id)
    return RedirectResponse(url="/parsers", status_code=303)


@app.post("/parsers/test")
def parsers_test(request: Request, sample: str = Form(...),
                 match_key: str = Form(...), match_value: str = Form(...),
                 field_map: str = Form(""), vendor: str = Form(""),
                 product: str = Form(""), kv_source: str = Form(""),
                 kv_sep: str = Form(""), _user=Depends(require_role("admin"))):
    """Dry-run a definition against a pasted raw record. Nothing is stored."""
    import json as _json
    defn = {"parser_id": "(test)", "match_key": match_key.strip(),
            "match_value": match_value.strip(),
            "field_map": _parse_field_map(field_map),
            "vendor": vendor.strip() or None, "product": product.strip() or None,
            "kv_source": kv_source.strip() or None, "kv_sep": kv_sep.strip() or None}
    result: dict = {}
    try:
        rec = _json.loads(sample)
        if not isinstance(rec, dict):
            raise ValueError("sample must be a JSON object")
        matched = custom_parser.matches(defn, rec)
        result = {"matched": matched,
                  "mapped": custom_parser.map_fields(
                      defn, custom_parser.extract_kv(defn, rec)) if matched else {}}
    except Exception as exc:  # noqa: BLE001 -- surface the error to the author
        result = {"error": str(exc)}
    rows = db.list_custom_parsers()
    for r in rows:
        r["field_map_text"] = _field_map_text(r.get("field_map"))
    return templates.TemplateResponse(request, "parsers.html", _ctx(
        request, parsers=rows, columns=sorted(custom_parser._ALLOWED),
        test=result, draft=defn, sample=sample,
        draft_map_text=_field_map_text(defn.get("field_map"))))


# --------------------------------------------------------------------------- #
#  Rule builder (console-authored detection rules)                             #
# --------------------------------------------------------------------------- #

@app.get("/rules", response_class=HTMLResponse)
def rules_page(request: Request, _user=Depends(require_role("admin"))):
    return templates.TemplateResponse(request, "rules.html", _ctx(
        request, rules=db.list_custom_rules()))


@app.post("/rules/save")
def rules_save(request: Request, rule_id: str = Form(...), title: str = Form(...),
               yaml_text: str = Form(...), enabled: str = Form("on"),
               _user=Depends(require_role("admin"))):
    import yaml as _yaml
    err = None
    try:
        docs = [d for d in _yaml.safe_load_all(yaml_text) if isinstance(d, dict)]
        if not docs or not any(d.get("detection") for d in docs):
            err = "Rule must contain a `detection:` block."
    except Exception as exc:  # noqa: BLE001
        err = f"YAML error: {exc}"
    if err:
        return templates.TemplateResponse(request, "rules.html", _ctx(
            request, rules=db.list_custom_rules(), error=err,
            draft={"rule_id": rule_id, "title": title, "yaml_text": yaml_text}))
    db.upsert_custom_rule(rule_id.strip(), title.strip(), yaml_text,
                          enabled == "on")
    detection_runtime.load_and_sync(BASE.parent / "rules")   # hot reload
    _audit(request, "rule.save", rule_id)
    return RedirectResponse(url="/rules", status_code=303)


@app.post("/rules/delete")
def rules_delete(request: Request, rule_id: str = Form(...),
                 _user=Depends(require_role("admin"))):
    db.delete_custom_rule(rule_id)
    detection_runtime.load_and_sync(BASE.parent / "rules")
    _audit(request, "rule.delete", rule_id)
    return RedirectResponse(url="/rules", status_code=303)


@app.post("/rules/test")
def rules_test(request: Request, yaml_text: str = Form(...),
               rule_id: str = Form(""), title: str = Form(""),
               limit: int = Form(200), _user=Depends(require_role("admin"))):
    """Dry-run a rule against the most recent events. Nothing is stored and no
    alerts are raised -- this is how an author checks blast radius before enabling."""
    import yaml as _yaml
    from .detection.engine import flatten_event, match_rule, rule_from_dict
    from .models import NormalizedEvent
    result: dict = {}
    try:
        docs = [d for d in _yaml.safe_load_all(yaml_text)
                if isinstance(d, dict) and d.get("detection")]
        if not docs:
            raise ValueError("no document with a `detection:` block")
        rule = rule_from_dict(docs[0], "test")
        rows = db.recent_events_for_test(min(max(int(limit), 1), 1000))
        hits = []
        for r in rows:
            evt = NormalizedEvent(
                event_time=r.get("event_time"), vendor=r.get("vendor") or "",
                product=r.get("product"), log_type=r.get("log_type"),
                severity=r.get("severity"), action=r.get("action"),
                src_ip=r.get("src_ip"), dst_ip=r.get("dst_ip"),
                src_port=r.get("src_port"), dst_port=r.get("dst_port"),
                protocol=r.get("protocol"), app=r.get("app"),
                user_name=r.get("user_name"), host_name=r.get("host_name"),
                rule_name=r.get("rule_name"), message=r.get("message"),
                raw=r.get("raw") or {})
            # Pass `evt` as well as the flat view: CIM membership reads jsonb keys
            # byte-exact, while `flatten_event` lower-cases and dot-joins them. Without
            # it a rule bound to a model whose membership is `raw:`-sourced (the Windows
            # event_id clauses of Authentication/Endpoint/Change) would under-match here
            # and match in production — a dry-run that quietly disagrees with the
            # pipeline is worse than no dry-run.
            if match_rule(rule, flatten_event(evt), evt):
                hits.append({"event_time": r.get("event_time"),
                             "vendor": r.get("vendor"),
                             "user_name": r.get("user_name"),
                             "host_name": r.get("host_name"),
                             "message": (r.get("message") or "")[:160]})
        result = {"scanned": len(rows), "hits": hits[:25], "total_hits": len(hits),
                  "rule_title": rule.title, "level": rule.level}
    except Exception as exc:  # noqa: BLE001
        result = {"error": str(exc)}
    return templates.TemplateResponse(request, "rules.html", _ctx(
        request, rules=db.list_custom_rules(), test=result,
        draft={"rule_id": rule_id, "title": title, "yaml_text": yaml_text}))
