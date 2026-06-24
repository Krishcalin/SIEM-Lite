"""Integration test for inline detection in write_stream (DB calls mocked)."""
from pathlib import Path

import app.db as db
from app import pipeline
from app.detection import runtime as detruntime
from app.detection.engine import DetectionEngine, load_rules
from app.models import NormalizedEvent

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def test_write_stream_inserts_events_and_emits_alerts(monkeypatch):
    inserted, alerts = [], []
    monkeypatch.setattr(db, "insert_events", lambda conn, chunk, bid: inserted.extend(chunk))
    monkeypatch.setattr(db, "insert_alerts", lambda conn, a: alerts.extend(a))
    detruntime.set_engine(DetectionEngine(load_rules(RULES_DIR)))
    try:
        events = [
            NormalizedEvent(event_time=None, vendor="microsoft", log_type="security",
                            action="failed-logon"),                       # -> failed logon
            NormalizedEvent(event_time=None, vendor="paloalto", dst_port=3389,
                            action="allow"),                              # -> rdp allowed
            NormalizedEvent(event_time=None, vendor="x", action="allow"),  # -> no rule
        ]
        total = pipeline.write_stream(conn=None, events=iter(events), batch_id=99)
    finally:
        detruntime.set_engine(None)

    assert total == 3 and len(inserted) == 3          # every event is still stored
    fired = {a["rule_id"] for a in alerts}
    assert "lo-win-failed-logon" in fired and "lo-rdp-allowed" in fired
    assert all(a["batch_id"] == 99 and a["dedup_hash"] for a in alerts)


def test_write_stream_without_engine_emits_no_alerts(monkeypatch):
    inserted, alerts = [], []
    monkeypatch.setattr(db, "insert_events", lambda conn, chunk, bid: inserted.extend(chunk))
    monkeypatch.setattr(db, "insert_alerts", lambda conn, a: alerts.extend(a))
    detruntime.set_engine(None)                       # detection disabled
    total = pipeline.write_stream(
        conn=None,
        events=iter([NormalizedEvent(event_time=None, vendor="microsoft",
                                     log_type="security", action="failed-logon")]),
        batch_id=1)
    assert total == 1 and len(inserted) == 1 and alerts == []
