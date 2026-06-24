"""Scheduled correlation rules (Phase 2.5): multi-event / threshold detections.

A correlation rule aggregates *stored* events over a sliding time window and
raises one alert per group that crosses a threshold — e.g. ">=5 failed logons
from one source IP in 5 minutes" (brute force). Event filtering + aggregation
runs in SQL (`db.correlate`) for efficiency; a background scheduler evaluates the
rules every CORRELATION_INTERVAL seconds.

A correlation rule YAML looks like::

    title: Brute Force - Failed Logon Burst
    id: lo-corr-bruteforce-logon
    level: high
    correlation:
      match: { action: failed-logon }     # equality / list filter on normalized cols
      group_by: [src_ip]                   # entity to group on
      window: 5m                           # look-back window
      threshold: 5                         # >= N events in the window
    tags: [attack.t1110, attack.credential_access]
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml
from starlette.concurrency import run_in_threadpool

from .. import db
from .engine import _parse_tags

log = logging.getLogger("logocean")

_WINDOW_RE = re.compile(r"^\s*(\d+)\s*([smhd])\s*$", re.IGNORECASE)
_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def window_seconds(value) -> int:
    """Parse '5m' / '30s' / '1h' / '2d' (or a number) to seconds; default 300."""
    if isinstance(value, (int, float)):
        return int(value)
    m = _WINDOW_RE.match(str(value or ""))
    return int(m.group(1)) * _UNIT[m.group(2).lower()] if m else 300


@dataclass
class CorrelationRule:
    id: str
    title: str
    level: str
    description: str
    match: dict
    group_by: list[str]
    window: int           # seconds
    threshold: int
    tactics: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    source: str = ""
    enabled: bool = True


def load_correlation_rules(rules_dir) -> list[CorrelationRule]:
    rules: list[CorrelationRule] = []
    base = Path(rules_dir)
    if not base.is_dir():
        return rules
    for path in sorted(list(base.glob("*.yml")) + list(base.glob("*.yaml"))):
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            corr = doc.get("correlation") if isinstance(doc, dict) else None
            if not isinstance(corr, dict):
                continue
            tactics, techniques = _parse_tags(doc.get("tags"))
            rules.append(CorrelationRule(
                id=str(doc.get("id") or doc.get("title") or path.name),
                title=str(doc.get("title") or "untitled"),
                level=str(doc.get("level") or "medium").lower(),
                description=str(doc.get("description") or ""),
                match=corr.get("match") or {},
                group_by=list(corr.get("group_by") or []),
                window=window_seconds(corr.get("window") or corr.get("timespan")),
                threshold=int(corr.get("threshold") or 1),
                tactics=tactics, techniques=techniques, source=path.name))
    return rules


def correlation_alert(rule: CorrelationRule, row: dict, bucket: int) -> dict:
    """Build an alert row for one over-threshold group. `bucket` (a window index)
    is folded into the dedup hash so the same ongoing burst alerts once per window.
    Pure — DB-free."""
    gv = {c: row.get(c) for c in rule.group_by}
    ident = "|".join(f"{k}={gv[k]}" for k in sorted(gv))
    dedup = hashlib.sha256(f"corr|{rule.id}|{ident}|{bucket}".encode("utf-8")).hexdigest()
    parts = ", ".join(f"{k}={v}" for k, v in gv.items() if v is not None) or "—"
    return {
        "event_time": row.get("last_seen"),
        "rule_id": rule.id, "rule_title": rule.title, "level": rule.level,
        "tactics": rule.tactics, "techniques": rule.techniques, "vendor": None,
        "src_ip": gv.get("src_ip"), "dst_ip": gv.get("dst_ip"),
        "user_name": gv.get("user_name"), "host_name": gv.get("host_name"),
        "message": f"{row.get('n')} matching events ({parts}) within {rule.window}s",
        "dedup_hash": dedup, "batch_id": None,
    }


def run_rule(rule: CorrelationRule, now: Optional[float] = None) -> int:
    """Evaluate one correlation rule; insert+return the number of alerts raised."""
    rows = db.correlate(rule.match, rule.group_by, rule.window, rule.threshold)
    if not rows:
        return 0
    bucket = int((now if now is not None else time.time()) // rule.window)
    alerts = [correlation_alert(rule, r, bucket) for r in rows]
    with db.pool().connection() as conn:
        db.insert_alerts(conn, alerts)
        conn.commit()
    return len(alerts)


class CorrelationScheduler:
    """Runs the enabled correlation rules on a fixed interval in the background."""

    def __init__(self, rules: list[CorrelationRule], interval: int):
        self.rules = rules
        self.interval = max(interval, 5)
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._loop())
        log.info("correlation scheduler started: %d rules, every %ds",
                 len(self.rules), self.interval)

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
                await run_in_threadpool(self._run_all)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("correlation run failed")

    def _run_all(self) -> None:
        for r in self.rules:
            if not r.enabled:
                continue
            try:
                run_rule(r)
            except Exception:  # noqa: BLE001
                log.exception("correlation rule %s failed", r.id)
