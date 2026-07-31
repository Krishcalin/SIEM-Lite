# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Log-source health monitoring: silent-source ("stopped sending") detection.

A SIEM is blind to what it stops receiving. If a log source that normally sends
events goes quiet, it may be a benign outage, a broken collector/forwarder, a
misconfigured device — or an attacker who has disabled logging to hide their
tracks (MITRE ATT&CK **T1562 Impair Defenses**). LogOcean already alerts on what
arrives; this closes the loop by alerting on what *stops* arriving.

A **source** is identified by ``(vendor, log_type)`` — the values every parser
stamps, so a source is always attributable without extra configuration. A source
is *established* when it produced at least ``min_events`` in a learning window,
and *silent* when its newest event is older than the silence threshold. The check
is stateless (derived from ``events`` each run) and the alert is deduped per
silence episode, so an ongoing outage notifies at most once per repeat period
rather than every cycle.

The classification, alerting, and human-formatting are PURE (no DB, no clock
side effect — ``now`` is injected), so they unit-test without a database. Only
``run_check`` and the scheduler touch the DB, mirroring ``correlation.run_rule``
and ``response.revert``.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from starlette.concurrency import run_in_threadpool

from . import alert_actions, db
from .config import settings
from .util import fmt_ist

log = logging.getLogger("logocean")

RULE_ID = "lo-source-silent"
RULE_TITLE = "Log source stopped sending"
TECHNIQUES = ["T1562"]              # Impair Defenses (loss of telemetry / disabled logging)
TACTICS = ["defense_evasion"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def source_key(vendor: Optional[str], log_type: Optional[str]) -> str:
    """Canonical source identity. ``vendor/log_type``; falls back gracefully so a
    partially-parsed source is still attributable and never an empty key."""
    v = (vendor or "").strip()
    lt = (log_type or "").strip()
    if v and lt:
        return f"{v}/{lt}"
    return v or lt or "unknown"


def human_age(seconds: float) -> str:
    """A compact human duration: 45s / 12m / 3h / 2d 4h."""
    s = int(max(0, seconds))
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        h, m = divmod(s // 60, 60)
        return f"{h}h" if m == 0 else f"{h}h {m}m"
    d, rem = divmod(s, 86400)
    h = rem // 3600
    return f"{d}d" if h == 0 else f"{d}d {h}h"


@dataclass(frozen=True)
class SourceHealth:
    key: str
    vendor: Optional[str]
    log_type: Optional[str]
    last_seen: Optional[datetime]
    event_count: int
    age_seconds: float
    status: str            # "healthy" | "silent"


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def assess(rows, now: Optional[datetime] = None, *, silence_seconds: int,
           min_events: int) -> list[SourceHealth]:
    """Classify every established source from ``db.source_activity`` rows
    ``{vendor, log_type, last_seen, n}``. A source is kept only when it has
    ``>= min_events`` in the learning window (so a one-off blip is not treated as
    an expected feed), and is ``silent`` when its newest event is older than
    ``silence_seconds``. Sorted silent-first, then oldest-first. PURE."""
    now = now or _now()
    out: list[SourceHealth] = []
    for r in rows:
        n = int(r.get("n") or 0)
        if n < max(1, min_events):
            continue
        last = _aware(r.get("last_seen"))
        age = (now - last).total_seconds() if last else float("inf")
        status = "silent" if age > silence_seconds else "healthy"
        out.append(SourceHealth(
            key=source_key(r.get("vendor"), r.get("log_type")),
            vendor=(r.get("vendor") or None), log_type=(r.get("log_type") or None),
            last_seen=last, event_count=n, age_seconds=age, status=status))
    out.sort(key=lambda s: (s.status != "silent", -s.age_seconds))
    return out


def silent_alert(sh: SourceHealth, now: Optional[datetime] = None, *,
                 level: str, repeat_seconds: int) -> dict:
    """Build one alert row for a silent source, shaped for ``db.insert_alerts``.

    The dedup hash folds a repeat-bucket (``now // repeat_seconds``) so a source
    that stays silent re-alerts at most once per repeat period instead of every
    scheduler cycle — and a source that recovers then goes silent again lands in a
    new bucket and alerts afresh. PURE."""
    now = now or _now()
    bucket = int(now.timestamp() // max(1, repeat_seconds))
    dedup = hashlib.sha256(f"srchealth|{sh.key}|{bucket}".encode("utf-8")).hexdigest()
    last_txt = (fmt_ist(sh.last_seen, "%Y-%m-%d %H:%M") + " IST") if sh.last_seen else "never"
    msg = (f"Log source '{sh.key}' has stopped sending — silent for "
           f"{human_age(sh.age_seconds)} (last event {last_txt}; "
           f"{sh.event_count} events in the learning window).")
    return {
        "event_time": now,
        "rule_id": RULE_ID, "rule_title": RULE_TITLE, "level": (level or "medium").lower(),
        "tactics": list(TACTICS), "techniques": list(TECHNIQUES),
        "vendor": sh.vendor, "src_ip": None, "dst_ip": None,
        "user_name": None, "host_name": None,
        "message": msg, "dedup_hash": dedup, "batch_id": None, "status": "open",
    }


def run_check(now: Optional[datetime] = None) -> int:
    """Evaluate source health once: read per-source activity, alert on every
    established source that has gone silent, and dispatch the newly-raised alerts
    to notify/response (after commit). Returns the number of new alerts. Mirrors
    ``correlation.run_rule``."""
    now = now or _now()
    rows = db.source_activity(settings.source_health_learn_days)
    silent = [s for s in assess(rows, now,
                                silence_seconds=settings.source_health_silence_minutes * 60,
                                min_events=settings.source_health_min_events)
              if s.status == "silent"]
    if not silent:
        return 0
    alerts = [silent_alert(s, now, level=settings.source_health_level,
                           repeat_seconds=settings.source_health_repeat_hours * 3600)
              for s in silent]
    with db.pool().connection() as conn:
        new = db.insert_alerts(conn, alerts, return_inserted=True)
        conn.commit()
    alert_actions.dispatch(new)
    return len(new)


class SourceHealthScheduler:
    """Runs the silent-source check on a fixed interval in the background."""

    def __init__(self, interval: int):
        self.interval = max(interval, 30)
        self.alerts = 0
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._loop())
        log.info("source-health scheduler started: every %ds", self.interval)

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _loop(self) -> None:
        while True:
            await asyncio.sleep(self.interval)
            try:
                self.alerts += await run_in_threadpool(run_check)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("source-health run failed")

    def stats(self) -> dict:
        return {"alerts": self.alerts, "interval": self.interval,
                "silence_minutes": settings.source_health_silence_minutes}


_scheduler: Optional[SourceHealthScheduler] = None


def get_scheduler() -> Optional[SourceHealthScheduler]:
    return _scheduler


def set_scheduler(s: Optional[SourceHealthScheduler]) -> None:
    global _scheduler
    _scheduler = s
