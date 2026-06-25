"""Collector orchestration: build configured collectors, run one (pull -> ingest
-> persist cursor), and a background scheduler that polls the enabled ones.

`run_collector` feeds the fetched text through the normal ingest path, so pulled
logs get the same parse -> detect -> alert -> notify/respond treatment as uploads.
"""
from __future__ import annotations

import asyncio
import logging

from starlette.concurrency import run_in_threadpool

from .. import db, ingest
from ..config import settings
from .base import Collector
from .sources import GitHubCollector, GitLabCollector, OktaCollector

log = logging.getLogger("logocean")


def build_collectors() -> list[Collector]:
    """Instantiate the collectors whose credentials are configured."""
    candidates = [
        OktaCollector(settings.okta_domain, settings.okta_token,
                      settings.collector_lookback_hours),
        GitHubCollector(settings.github_org, settings.github_token,
                        settings.collector_lookback_hours),
        GitLabCollector(settings.gitlab_url, settings.gitlab_token,
                        settings.collector_lookback_hours),
    ]
    return [c for c in candidates if c.configured()]


def run_collector(c: Collector) -> int:
    """Pull new records for one collector, ingest them, advance its cursor.
    Returns the number of records fetched. Blocking; runs in a threadpool."""
    state = db.get_collector(c.name) or {}
    cursor = state.get("cursor")
    try:
        result = c.fetch(cursor)
    except Exception as exc:  # noqa: BLE001
        db.update_collector(c.name, last_status="error", last_error=str(exc)[:300])
        log.exception("collector %s fetch failed", c.name)
        return 0
    if result.content and result.content.strip():
        try:
            ingest.ingest(result.content, c.fmt,
                          source_type="collector", source_addr=c.name)
        except Exception as exc:  # noqa: BLE001
            db.update_collector(c.name, last_status="error", last_error=str(exc)[:300])
            log.exception("collector %s ingest failed", c.name)
            return 0
    db.update_collector(c.name, cursor=result.cursor, last_status="ok",
                        last_count=result.count, last_error=None)
    return result.count


class CollectorScheduler:
    """Polls the enabled, configured collectors every `interval` seconds."""

    def __init__(self, collectors: list[Collector], interval: int):
        self.collectors = collectors
        self.interval = max(interval, 30)
        self._task = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._loop())
        log.info("collector scheduler started: %d collector(s), every %ds",
                 len(self.collectors), self.interval)

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
                log.exception("collector run failed")

    def _run_all(self) -> None:
        enabled = db.enabled_collector_names()
        for c in self.collectors:
            if c.name in enabled:
                try:
                    run_collector(c)
                except Exception:  # noqa: BLE001
                    log.exception("collector %s failed", c.name)


_scheduler = None


def get_scheduler():
    return _scheduler


def set_scheduler(s) -> None:
    global _scheduler
    _scheduler = s
