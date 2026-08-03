# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Integration test for inline detection in write_stream (DB calls mocked)."""
from pathlib import Path

import app.db as db
from app import pipeline
from app.cim import match as cim_match
from app.detection import runtime as detruntime
from app.detection.engine import DetectionEngine, Rule, load_rules
from app.models import NormalizedEvent

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def _fake_insert_alerts(captured):
    # mirrors db.insert_alerts(conn, alerts, return_inserted=False) -> list
    def _impl(conn, a, return_inserted=False):
        captured.extend(a)
        return list(a)
    return _impl


def test_write_stream_inserts_events_and_emits_alerts(monkeypatch):
    inserted, alerts = [], []
    monkeypatch.setattr(db, "insert_events", lambda conn, chunk, bid: inserted.extend(chunk))
    monkeypatch.setattr(db, "insert_alerts", _fake_insert_alerts(alerts))
    detruntime.set_engine(DetectionEngine(load_rules(RULES_DIR)))
    try:
        events = [
            NormalizedEvent(event_time=None, vendor="microsoft", log_type="security",
                            action="failed-logon"),                       # -> failed logon
            NormalizedEvent(event_time=None, vendor="paloalto", dst_port=3389,
                            action="allow"),                              # -> rdp allowed
            NormalizedEvent(event_time=None, vendor="x", action="allow"),  # -> no rule
        ]
        result = pipeline.write_stream(conn=None, events=iter(events), batch_id=99)
    finally:
        detruntime.set_engine(None)

    assert result.total == 3 and len(inserted) == 3   # every event is still stored
    fired = {a["rule_id"] for a in alerts}
    assert "lo-win-failed-logon" in fired and "lo-rdp-allowed" in fired
    assert all(a["batch_id"] == 99 and a["dedup_hash"] for a in alerts)


def test_write_stream_without_engine_emits_no_alerts(monkeypatch):
    inserted, alerts = [], []
    monkeypatch.setattr(db, "insert_events", lambda conn, chunk, bid: inserted.extend(chunk))
    monkeypatch.setattr(db, "insert_alerts", _fake_insert_alerts(alerts))
    detruntime.set_engine(None)                       # detection disabled
    result = pipeline.write_stream(
        conn=None,
        events=iter([NormalizedEvent(event_time=None, vendor="microsoft",
                                     log_type="security", action="failed-logon")]),
        batch_id=1)
    assert result.total == 1 and len(inserted) == 1 and alerts == []


# ── the resolved-tags hand-off ────────────────────────────────────────────────
# CIM membership used to be walked TWICE per ingested event: once by the detection
# `datamodels:` gate as the event streams, once by `db._row` when the chunk flushes.
# `write_stream` now resolves it once and threads it to both consumers, each of which
# is probed with `_accepts` because a build or a test double may not take the argument.
_MEMBER = dict(vendor="microsoft", product="windows", log_type="security",
               action="failed-logon", raw={"event_id": 4625})


def _count_tag_walks(monkeypatch):
    """Count registry walks, whichever consumer asks for one."""
    calls = []
    real = cim_match.tags_for

    def counting(evt, registry=None):
        calls.append(evt)
        return real(evt, registry)

    monkeypatch.setattr(cim_match, "tags_for", counting)
    return calls


def test_write_stream_resolves_membership_once_per_event(monkeypatch):
    """The whole point of the hand-off: one walk per event, not two. Measured as work
    done rather than wall-clock, so it cannot go flaky on a loaded box."""
    rows, alerts = [], []
    walks = _count_tag_walks(monkeypatch)

    def fake_insert(conn, events, batch_id, cim_tags=None):
        for i, e in enumerate(events):
            rows.append(db._row(e, batch_id, None if cim_tags is None else cim_tags[i]))

    monkeypatch.setattr(db, "insert_events", fake_insert)
    monkeypatch.setattr(db, "insert_alerts", _fake_insert_alerts(alerts))
    bound = Rule(id="dm-bound", title="t", level="low", description="",
                 logsource={}, datamodels=["authentication"],
                 detection={"sel": {"action": "failed-logon"}, "condition": "sel"})
    detruntime.set_engine(DetectionEngine([bound]))
    try:
        events = [NormalizedEvent(event_time=None, **_MEMBER) for _ in range(5)]
        result = pipeline.write_stream(conn=None, events=iter(events), batch_id=3)
    finally:
        detruntime.set_engine(None)

    assert result.total == 5
    assert len(walks) == 5, (
        f"membership was resolved {len(walks)} times for 5 events; the pipeline is "
        "meant to walk the registry once and thread the result to both consumers")
    # and the threaded value must actually reach the stored row
    assert [r["cim_models"] for r in rows] == [["authentication"]] * 5


def test_write_stream_still_works_when_a_consumer_will_not_take_the_tags(monkeypatch):
    """`_accepts` is a probe, not an assumption. A test double (or an older build) with
    the three-argument signature must keep working — it just derives membership itself."""
    inserted, alerts = [], []
    monkeypatch.setattr(db, "insert_events",
                        lambda conn, chunk, bid: inserted.extend(chunk))
    monkeypatch.setattr(db, "insert_alerts", _fake_insert_alerts(alerts))
    detruntime.set_engine(None)
    result = pipeline.write_stream(
        conn=None, events=iter([NormalizedEvent(event_time=None, **_MEMBER)]),
        batch_id=1)
    assert result.total == 1 and len(inserted) == 1


def test_write_stream_leaves_a_registry_failure_for_db_to_count(monkeypatch):
    """The honesty property. When the pipeline's own resolution raises it must thread
    None, NOT an empty set — the event then falls through to `db._row`, which stores it
    untagged and COUNTS it. Boxing the failure here would leave /health reporting zero
    untagged events while every row went in with no tags."""
    threaded, alerts = [], []

    def explode(evt, registry=None):
        raise RuntimeError("models.yaml is broken")

    monkeypatch.setattr(cim_match, "tags_for", explode)

    def fake_insert(conn, events, batch_id, cim_tags=None):
        threaded.extend(cim_tags or [])

    monkeypatch.setattr(db, "insert_events", fake_insert)
    monkeypatch.setattr(db, "insert_alerts", _fake_insert_alerts(alerts))
    detruntime.set_engine(None)
    db.reset_cim_write_state()
    try:
        pipeline.write_stream(
            conn=None, events=iter([NormalizedEvent(event_time=None, **_MEMBER)]),
            batch_id=1)
        assert threaded == [None], (
            f"pipeline threaded {threaded!r}; an empty set here would tell db._row the "
            "event genuinely belongs to no model and the failure would go uncounted")
    finally:
        db.reset_cim_write_state()
