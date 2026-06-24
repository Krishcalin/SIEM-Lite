"""Async ingest queue with backpressure (Phase 1 live ingestion).

Live sources (the syslog receiver, and anything else that pushes continuously)
hand parsed events to a bounded in-memory queue instead of writing to Postgres
on the hot path. A small pool of writer tasks drains the queue, groups events by
source, and bulk-inserts them via the shared `pipeline`, batching by size or age
so each flush is one efficient transaction.

Backpressure: the queue is bounded. When it is full, `submit()` drops the item
and increments a counter rather than blocking the receiver (and `log()`s nothing
per-item to avoid log floods) — silent loss is surfaced via the dropped counter
on `/health`. Blocking DB work runs in a threadpool so it never stalls the loop.
"""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from starlette.concurrency import run_in_threadpool

from . import db, pipeline
from .models import NormalizedEvent

log = logging.getLogger("logocean")


@dataclass
class IngestItem:
    """One unit submitted to the queue: the events parsed from a single message,
    tagged with where they came from so writers can attribute the batch."""
    events: list[NormalizedEvent]
    fmt: str
    source_type: str
    source_addr: Optional[str] = None
    vendor: Optional[str] = None


@dataclass
class QueueStats:
    received: int = 0      # items accepted onto the queue
    dropped: int = 0       # items rejected because the queue was full
    written: int = 0       # rows actually stored (post-dedup)
    flush_errors: int = 0  # flushes that failed to commit

    def as_dict(self) -> dict:
        return {"received": self.received, "dropped": self.dropped,
                "written": self.written, "flush_errors": self.flush_errors}


def group_items(items: list[IngestItem]) -> dict[tuple, list[NormalizedEvent]]:
    """Group buffered events by (fmt, source_type, source_addr, vendor) so each
    group becomes one attributable batch. Pure — unit-tested without a DB."""
    groups: dict[tuple, list[NormalizedEvent]] = defaultdict(list)
    for item in items:
        key = (item.fmt, item.source_type, item.source_addr, item.vendor)
        groups[key].extend(item.events)
    return groups


def _write_group(events: list[NormalizedEvent], fmt: str, source_type: str,
                 source_addr: Optional[str], vendor: Optional[str]) -> int:
    """Insert one group as a single live batch. Blocking; runs in a threadpool.
    Returns the number of rows stored (post-dedup)."""
    batch_id = db.create_batch(None, None, vendor, fmt, source_type, source_addr)
    with db.pool().connection() as conn:
        try:
            total = pipeline.write_stream(conn, iter(events), batch_id)
            conn.commit()
        except Exception as exc:  # noqa: BLE001
            conn.rollback()
            db.update_batch(batch_id, status="error", notes=str(exc)[:500])
            raise
    inserted = db.count_batch_rows(batch_id)
    db.update_batch(batch_id, status="done", total_rows=total, inserted_rows=inserted,
                    duplicate_rows=max(total - inserted, 0), error_rows=0)
    return inserted


class IngestQueue:
    """A bounded asyncio queue with a pool of batching writer workers."""

    def __init__(self, maxsize: int, workers: int, flush_max: int, flush_ms: int):
        self._q: asyncio.Queue[IngestItem] = asyncio.Queue(maxsize=maxsize)
        self._workers = max(workers, 1)
        self._flush_max = max(flush_max, 1)
        self._flush_interval = max(flush_ms, 1) / 1000.0
        self._tasks: list[asyncio.Task] = []
        self.stats = QueueStats()

    def submit(self, item: IngestItem) -> bool:
        """Enqueue without blocking. Returns False (and counts a drop) if full."""
        try:
            self._q.put_nowait(item)
            self.stats.received += 1
            return True
        except asyncio.QueueFull:
            self.stats.dropped += 1
            return False

    async def start(self) -> None:
        self._tasks = [asyncio.create_task(self._worker(i)) for i in range(self._workers)]
        log.info("ingest queue started: %d workers, flush_max=%d, interval=%.2fs",
                 self._workers, self._flush_max, self._flush_interval)

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except asyncio.CancelledError:
                pass
        self._tasks = []

    async def _worker(self, n: int) -> None:
        buf: list[IngestItem] = []
        buffered_events = 0
        while True:
            try:
                timeout = self._flush_interval if buf else None
                item = await asyncio.wait_for(self._q.get(), timeout=timeout)
                buf.append(item)
                buffered_events += len(item.events)
                if buffered_events >= self._flush_max:
                    await self._flush(buf); buf, buffered_events = [], 0
            except asyncio.TimeoutError:
                if buf:
                    await self._flush(buf); buf, buffered_events = [], 0
            except asyncio.CancelledError:
                if buf:
                    await self._flush(buf)   # drain on shutdown
                raise

    async def _flush(self, items: list[IngestItem]) -> None:
        for (fmt, st, addr, vendor), events in group_items(items).items():
            if not events:
                continue
            try:
                stored = await run_in_threadpool(_write_group, events, fmt, st, addr, vendor)
                self.stats.written += stored
            except Exception:  # noqa: BLE001
                self.stats.flush_errors += 1
                log.exception("ingest flush failed (fmt=%s, source=%s/%s)", fmt, st, addr)


# Module-level singleton, created/started in the app lifespan.
_queue: Optional[IngestQueue] = None


def get_queue() -> Optional[IngestQueue]:
    return _queue


def set_queue(q: Optional[IngestQueue]) -> None:
    global _queue
    _queue = q
