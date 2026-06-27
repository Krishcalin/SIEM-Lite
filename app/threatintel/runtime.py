"""Threat-intel runtime: hold the IOC index singleton, sync feeds into the DB,
and rebuild the index. A background scheduler refreshes remote feeds on a timer.

The ingest pipeline calls ``get_index()`` per event; the lifespan calls
``sync_feeds()`` / ``reload_index()`` at startup and the admin UI calls them
again after a manual reload or indicator add.
"""
from __future__ import annotations

import asyncio
import logging

from starlette.concurrency import run_in_threadpool

from .. import db
from . import feeds as feeds_mod
from .matcher import Ioc, IocIndex

log = logging.getLogger("logocean")

_index = IocIndex()


def get_index() -> IocIndex:
    return _index


def set_index(index: IocIndex) -> None:
    global _index
    _index = index


def reload_index() -> IocIndex:
    """Rebuild the in-memory index from the enabled, unexpired rows in `iocs`."""
    index = IocIndex()
    for row in db.enabled_iocs():
        index.add(Ioc(row["indicator"], row["ioc_type"], row["source"],
                      row["severity"], row.get("description") or ""))
    set_index(index)
    log.info("threat-intel index loaded: %d indicator(s) %s", len(index), index.counts())
    return index


def sync_feeds(feed_sources: list[str], default_severity: str = "high") -> int:
    """Fetch each feed, replace that source's indicators in `iocs`, then reindex.
    Returns the total indicator count now in the index. Blocking; run off-loop."""
    for src in feed_sources:
        try:
            text = feeds_mod.load_feed_source(src)
            iocs = feeds_mod.parse_feed(text, source=src, default_severity=default_severity)
            db.replace_source_iocs(src, iocs)
            log.info("threat-intel feed %s: %d indicator(s)", src, len(iocs))
        except Exception as exc:  # noqa: BLE001 — one bad feed must not break the rest
            log.warning("threat-intel feed %s failed: %s", src, exc)
    return len(reload_index())


class FeedScheduler:
    """Refreshes the configured feeds every `interval` seconds."""

    def __init__(self, feed_sources: list[str], interval: int, default_severity: str):
        self.feeds = feed_sources
        self.interval = max(interval, 60)
        self.default_severity = default_severity
        self._task = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._loop())
        log.info("threat-intel feed scheduler started: %d feed(s), every %ds",
                 len(self.feeds), self.interval)

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
                await run_in_threadpool(sync_feeds, self.feeds, self.default_severity)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("threat-intel feed refresh failed")


_scheduler = None


def get_scheduler():
    return _scheduler


def set_scheduler(s) -> None:
    global _scheduler
    _scheduler = s
