"""Source-agnostic ingest core.

Upload, the HTTP ingest API, and the syslog receiver all funnel through here so
detect/parse/normalize/insert behavior is identical regardless of how the data
arrived. The *orchestration* around this (sha + per-file batch for uploads,
rolling batches for live streams) lives with each caller; this module only turns
a stream of NormalizedEvents into stored rows.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Iterable, Iterator, NamedTuple, Optional

from . import alert_actions, db, risk
from .config import settings
from .detection import engine as detengine, runtime as detruntime
from .models import NormalizedEvent
from .normalize import dedup_hash
from .parsers import PARSERS
from .threatintel import matcher as timatcher, runtime as tiruntime
from .triage import runtime as supruntime

log = logging.getLogger("logocean")


class WriteResult(NamedTuple):
    total: int                 # events seen (inserted-or-deduped)
    alerts: list               # newly-raised alerts (empty unless notifications active)

# Rows per INSERT batch. One executemany per chunk keeps memory flat on big files.
CHUNK = 5000


def parse_events(content: str, fmt: str) -> Iterator[NormalizedEvent]:
    """Parse raw content with the named parser. Raises ValueError on unknown fmt.

    The parser is a generator, so parsing is lazy — work happens as the caller
    iterates (typically inside an open DB transaction)."""
    if fmt not in PARSERS:
        raise ValueError(f"unknown format: {fmt}")
    return PARSERS[fmt].parse(content)


def _upsert_baselines(conn, events: list[NormalizedEvent]) -> None:
    """Maintain the UEBA entity / association baselines from a chunk of events
    (aggregated then upserted, within the caller's transaction)."""
    ents: dict[tuple, list] = {}
    lnks: dict[tuple, list] = {}
    for evt in events:
        t = evt.event_time
        for key in risk.event_entities(evt):
            e = ents.get(key)
            if e is None:
                ents[key] = [1, t, t]
            else:
                e[0] += 1; e[1] = min(e[1], t); e[2] = max(e[2], t)
        for key in risk.event_links(evt):
            ln = lnks.get(key)
            if ln is None:
                lnks[key] = [1, t, t]
            else:
                ln[0] += 1; ln[1] = min(ln[1], t); ln[2] = max(ln[2], t)
    db.upsert_entities(conn, [(et, ev, fr, ls, c) for (et, ev), (c, fr, ls) in ents.items()])
    db.upsert_entity_links(
        conn, [(et, ev, pt, pv, fr, ls, c) for (et, ev, pt, pv), (c, fr, ls) in lnks.items()])


def apply_fallback_time(evt: NormalizedEvent, fallback: datetime) -> NormalizedEvent:
    """Give an event a timestamp when the source had none, tagging it so the
    substitution is visible in `raw`. Rows are never dropped for lacking a time."""
    if evt.event_time is None:
        evt.event_time = fallback
        evt.raw.setdefault("_parse_note", "missing_or_unparsed_timestamp")
    return evt


def write_stream(conn, events: Iterable[NormalizedEvent], batch_id: int,
                 fallback: Optional[datetime] = None) -> WriteResult:
    """Insert `events` (chunked) into `batch_id` on an open connection.

    The caller owns the transaction (commit/rollback) and the batch lifecycle.
    Returns a WriteResult: `total` events seen (inserted-or-deduped; the count
    actually stored is `db.count_batch_rows(batch_id)` since ON CONFLICT hides
    dedup) and `alerts`, the newly-raised alerts — gathered only when a
    notification dispatcher is active, and dispatched by the caller AFTER commit.
    `fallback` (default: now, UTC) stamps events without a time.
    """
    fb = fallback or datetime.now(timezone.utc)
    engine = detruntime.get_engine()           # None if detection disabled/not loaded
    ti_index = tiruntime.get_index()           # empty unless threat-intel is loaded
    ti_active = len(ti_index) > 0
    supp_index = supruntime.get_index()        # empty unless suppressions exist
    supp_active = len(supp_index) > 0
    ueba_active = settings.ueba_enabled        # maintain entity baselines on write
    track_alerts = alert_actions.active()
    total = 0
    chunk: list[NormalizedEvent] = []
    pending: list[dict] = []
    new_alerts: list[dict] = []
    supp_hits: dict[int, int] = {}             # suppression id -> times fired

    def emit(alert: dict) -> None:
        """Queue an alert, marking it suppressed if an allowlist rule matches."""
        if supp_active:
            s = supp_index.match(alert)
            if s is not None:
                alert["status"] = "suppressed"
                supp_hits[s.id] = supp_hits.get(s.id, 0) + 1
        pending.append(alert)

    def flush() -> None:
        db.insert_events(conn, chunk, batch_id)
        new_alerts.extend(db.insert_alerts(conn, pending, return_inserted=track_alerts))
        if supp_hits:
            db.bump_suppressions(conn, supp_hits)
            supp_hits.clear()
        if ueba_active:
            _upsert_baselines(conn, chunk)

    for evt in events:
        total += 1
        apply_fallback_time(evt, fb)
        chunk.append(evt)
        dh: Optional[str] = None               # event identity, computed once if needed
        # Detection / threat-intel must never abort the batch: on any unexpected
        # error the event is still stored (already in `chunk`), just un-alerted.
        try:
            if engine is not None:
                matched = engine.evaluate_event(evt)
                if matched:
                    dh = dedup_hash(evt)       # same identity used for the event row
                    for r in matched:
                        emit(detengine.alert_from_match(r, evt, dh, batch_id))
            if ti_active:
                hits = ti_index.match(evt)
                if hits:
                    dh = dh or dedup_hash(evt)
                    emit(timatcher.ti_alert(hits, evt, dh, batch_id))
        except Exception:  # noqa: BLE001
            log.warning("detection/threat-intel failed for an event; stored un-alerted",
                        exc_info=True)
        if len(chunk) >= CHUNK:
            flush()
            chunk, pending = [], []
    if chunk or pending:
        flush()
    # Suppressed alerts are stored for audit but never notified / actioned.
    return WriteResult(total, [a for a in new_alerts if a.get("status") != "suppressed"])
