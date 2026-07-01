"""Kill-chain reconstruction runtime (DB-backed).

Bridges the pure :mod:`app.killchain` reconstructor to the database: pulls the
recent un-cased alerts, builds attack stories, and — when enabled — auto-creates
investigation cases for the high-severity ones on a background schedule. Kept
separate from ``killchain.py`` so the reconstruction logic stays dependency-free
and unit-testable.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

from starlette.concurrency import run_in_threadpool

from . import db, killchain
from .config import settings
from .severity import severity_rank

log = logging.getLogger("logocean")


def reconstruct_recent(
    hours: Optional[int] = None,
    max_gap_minutes: Optional[int] = None,
    min_tactics: Optional[int] = None,
    cap: int = 5000,
) -> list[dict]:
    """Reconstruct attack stories from recent un-cased alerts (defaults from settings)."""
    hours = settings.killchain_window_hours if hours is None else hours
    gap_min = (settings.killchain_max_gap_minutes
               if max_gap_minutes is None else max_gap_minutes)
    min_tactics = settings.killchain_min_tactics if min_tactics is None else min_tactics
    alerts = db.recent_uncased_alerts(hours=hours, cap=cap)
    return killchain.reconstruct(
        alerts, max_gap_seconds=gap_min * 60, min_tactics=min_tactics)


def auto_create(min_severity: Optional[str] = None) -> int:
    """Create cases for reconstructed stories at/above `min_severity` that don't
    already have an open kill-chain case. Returns the number of cases created."""
    threshold = severity_rank(min_severity or settings.killchain_min_severity)
    existing = db.open_kc_signatures()
    created = 0
    for story in reconstruct_recent():
        if severity_rank(story["severity"]) < threshold:
            continue
        if story["signature"] in existing:
            continue
        cid = db.create_case_from_story(story, created_by="killchain")
        existing.add(story["signature"])
        created += 1
        log.info("kill-chain auto-created case %d (%s, %d tactics, %d alerts)",
                 cid, story["severity"], story["tactic_count"], story["alert_count"])
    return created


class KillChainScheduler:
    """Runs kill-chain auto-create on a fixed interval in the background."""

    def __init__(self, interval: int, min_severity: str):
        self.interval = max(interval, 30)
        self.min_severity = min_severity
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._loop())
        log.info("kill-chain scheduler started: every %ds (min severity %s)",
                 self.interval, self.min_severity)

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
                await run_in_threadpool(auto_create, self.min_severity)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("kill-chain auto-create failed")
