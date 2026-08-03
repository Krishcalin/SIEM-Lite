# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Unit tests for the async ingest queue: pure grouping + the worker loop (no DB)."""
import asyncio

from app import streaming
from app.models import NormalizedEvent
from app.streaming import IngestItem, IngestQueue, group_items


def _ev() -> NormalizedEvent:
    return NormalizedEvent(event_time=None, vendor="t")


def test_group_items_merges_by_source_fmt_addr_vendor():
    items = [
        IngestItem([_ev(), _ev()], "generic_syslog", "syslog", "1.1.1.1", "syslog"),
        IngestItem([_ev()], "generic_syslog", "syslog", "1.1.1.1", "syslog"),
        IngestItem([_ev()], "cef", "syslog", "1.1.1.1", "arcsight"),
        IngestItem([_ev()], "generic_syslog", "syslog", "2.2.2.2", "syslog"),
    ]
    groups = group_items(items)
    assert len(groups) == 3                                            # 3 distinct keys
    assert len(groups[("generic_syslog", "syslog", "1.1.1.1", "syslog")]) == 3
    assert len(groups[("cef", "syslog", "1.1.1.1", "arcsight")]) == 1
    assert len(groups[("generic_syslog", "syslog", "2.2.2.2", "syslog")]) == 1


def test_group_items_empty():
    assert group_items([]) == {}


def test_queue_worker_batches_and_flushes(monkeypatch):
    """Submitted items reach the writer grouped, and `written` reflects the rows."""
    captured = []

    def fake_write(events, fmt, st, addr, vendor):
        captured.append((fmt, st, addr, vendor, len(events)))
        return len(events)

    monkeypatch.setattr(streaming, "_write_group", fake_write)

    async def run():
        q = IngestQueue(maxsize=100, workers=1, flush_max=3, flush_ms=50)
        await q.start()
        q.submit(IngestItem([_ev(), _ev()], "cef", "syslog", "1.1.1.1", "arc"))
        q.submit(IngestItem([_ev()], "cef", "syslog", "1.1.1.1", "arc"))  # hits flush_max
        await asyncio.sleep(0.2)
        await q.stop()
        return q

    q = asyncio.run(run())
    assert sum(c[4] for c in captured) == 3          # all 3 events written
    assert q.stats.written == 3 and q.stats.received == 2


def test_queue_drops_when_full():
    """A full queue rejects (and counts) rather than blocking the submitter."""
    async def run():
        q = IngestQueue(maxsize=1, workers=1, flush_max=100, flush_ms=10000)
        # don't start workers, so nothing drains the queue
        ok1 = q.submit(IngestItem([_ev()], "cef", "syslog", "1.1.1.1", "arc"))
        ok2 = q.submit(IngestItem([_ev()], "cef", "syslog", "1.1.1.1", "arc"))
        return ok1, ok2, q

    ok1, ok2, q = asyncio.run(run())
    assert ok1 is True and ok2 is False
    assert q.stats.received == 1 and q.stats.dropped == 1


# ── discarded events must be counted and surfaced ─────────────────────────────
# `_flush` answers any write failure by DISCARDING the buffered batch. That is the one
# remaining silent-loss path in the system: the events exist only in memory and syslog
# has no upstream to replay from. It cannot be made lossless with a counter, but it must
# stop being INVISIBLE — `flush_errors` counts incidents, so one failed flush of a 5000
# event buffer used to read as "1", and /health called the service "ok" throughout.
def test_a_failed_flush_counts_the_events_it_discarded(monkeypatch):
    """The number that matters is events lost, not flushes failed."""
    def boom(events, fmt, st, addr, vendor):
        raise RuntimeError("database is unreachable")

    monkeypatch.setattr(streaming, "_write_group", boom)

    async def run():
        q = IngestQueue(maxsize=100, workers=1, flush_max=3, flush_ms=50)
        await q.start()
        q.submit(IngestItem([_ev(), _ev(), _ev()], "cef", "syslog", "1.1.1.1", "arc"))
        await asyncio.sleep(0.2)
        await q.stop()
        return q

    q = asyncio.run(run())
    assert q.stats.flush_errors == 1
    assert q.stats.events_lost == 3, (
        f"{q.stats.events_lost} events counted as lost, expected 3 — `flush_errors` "
        "alone cannot tell an operator whether 1 event or a full buffer went missing")
    assert q.stats.as_dict()["events_lost"] == 3        # and it reaches /health


def test_health_reports_discarded_events_as_degraded():
    """/health said "ok" while events were being dropped on the floor. Loss outranks a
    CIM tagging gap in the reason list: an event that was never stored cannot be
    recovered, whereas an untagged one is repairable with a backfill."""
    from app.main import _ingest_degraded

    class _Q:
        def __init__(self, **kw): self.stats = streaming.QueueStats(**kw)

    assert _ingest_degraded(None) == []                       # no queue configured
    assert _ingest_degraded(_Q(received=9, written=9)) == []  # healthy: no reasons
    lost = _ingest_degraded(_Q(flush_errors=2, events_lost=8000))
    assert len(lost) == 1 and "8000" in lost[0] and "discarded" in lost[0]
    full = _ingest_degraded(_Q(dropped=4))
    assert len(full) == 1 and "queue was full" in full[0]
