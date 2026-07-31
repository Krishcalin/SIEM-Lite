# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Log-source health / silent-source detection.

The classification, alert-building and formatting are pure and unit-tested here
without a database. One integration test (skipped unless DB_DSN is set) drives the
real aggregate + run_check end-to-end.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app import sourcehealth as sh

_NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)

# The exact keys db._ALERT_INSERT binds — a silent-source alert must provide them all.
_ALERT_KEYS = {"event_time", "rule_id", "rule_title", "level", "tactics", "techniques",
               "vendor", "src_ip", "dst_ip", "user_name", "host_name", "message",
               "dedup_hash", "batch_id", "status"}


def _row(vendor="acme", log_type="fw", age_minutes=0, n=10):
    return {"vendor": vendor, "log_type": log_type,
            "last_seen": _NOW - timedelta(minutes=age_minutes), "n": n}


# ── pure helpers ──────────────────────────────────────────────────────────────
def test_source_key():
    assert sh.source_key("PaloAlto", "traffic") == "PaloAlto/traffic"
    assert sh.source_key("okta", "") == "okta"
    assert sh.source_key("", "syslog") == "syslog"
    assert sh.source_key(None, None) == "unknown"


def test_human_age():
    assert sh.human_age(45) == "45s"
    assert sh.human_age(12 * 60) == "12m"
    assert sh.human_age(3 * 3600) == "3h"
    assert sh.human_age(2 * 86400 + 4 * 3600) == "2d 4h"
    assert sh.human_age(-5) == "0s"


# ── assess ────────────────────────────────────────────────────────────────────
def test_assess_classifies_silent_and_healthy():
    rows = [_row("acme", "fw", age_minutes=5, n=10),      # recent -> healthy
            _row("beta", "ids", age_minutes=180, n=10)]   # 3h old -> silent (>60m)
    out = {s.key: s for s in sh.assess(rows, _NOW, silence_seconds=3600, min_events=5)}
    assert out["acme/fw"].status == "healthy"
    assert out["beta/ids"].status == "silent"
    assert out["beta/ids"].age_seconds == 180 * 60


def test_assess_drops_sources_below_min_events():
    rows = [_row("acme", "fw", age_minutes=180, n=2)]     # only 2 events -> not "expected"
    assert sh.assess(rows, _NOW, silence_seconds=3600, min_events=5) == []


def test_assess_sorts_silent_first_then_oldest():
    rows = [_row("a", "x", age_minutes=1, n=10),          # healthy
            _row("b", "y", age_minutes=120, n=10),        # silent 2h
            _row("c", "z", age_minutes=600, n=10)]        # silent 10h (oldest)
    keys = [s.key for s in sh.assess(rows, _NOW, silence_seconds=3600, min_events=5)]
    assert keys == ["c/z", "b/y", "a/x"]                  # silent-first, oldest-first


def test_assess_handles_naive_last_seen_as_utc():
    naive = {"vendor": "acme", "log_type": "fw",
             "last_seen": datetime(2026, 6, 1, 9, 0), "n": 10}   # 3h before _NOW, tz-naive
    out = sh.assess([naive], _NOW, silence_seconds=3600, min_events=5)
    assert out[0].status == "silent" and out[0].age_seconds == 3 * 3600


# ── silent_alert ──────────────────────────────────────────────────────────────
def _silent(age_minutes=180):
    return sh.assess([_row("beta", "ids", age_minutes=age_minutes, n=42)], _NOW,
                     silence_seconds=3600, min_events=5)[0]


def test_silent_alert_shape_and_content():
    a = sh.silent_alert(_silent(), _NOW, level="high", repeat_seconds=3600)
    assert set(a) == _ALERT_KEYS                          # every INSERT param present
    assert a["rule_id"] == sh.RULE_ID and a["level"] == "high"
    assert a["techniques"] == ["T1562"] and a["tactics"] == ["defense_evasion"]
    assert a["vendor"] == "beta" and a["src_ip"] is None and a["status"] == "open"
    assert "beta/ids" in a["message"] and "silent for 3h" in a["message"]
    assert "42 events" in a["message"]


def test_silent_alert_dedup_buckets_by_repeat_period():
    s = _silent()
    a0 = sh.silent_alert(s, _NOW, level="medium", repeat_seconds=3600)
    a1 = sh.silent_alert(s, _NOW + timedelta(minutes=30), level="medium", repeat_seconds=3600)
    a2 = sh.silent_alert(s, _NOW + timedelta(hours=2), level="medium", repeat_seconds=3600)
    assert a0["dedup_hash"] == a1["dedup_hash"]           # same repeat bucket -> one alert
    assert a0["dedup_hash"] != a2["dedup_hash"]           # next bucket -> re-alerts


# ── integration (real DB; skipped unless DB_DSN is set) ───────────────────────
@pytest.mark.integration
def test_source_activity_and_run_check(clean_db):
    from app.models import NormalizedEvent
    db = clean_db
    now = datetime.now(timezone.utc)

    def evt(vendor, log_type, when, i):
        return NormalizedEvent(event_time=when, vendor=vendor, log_type=log_type,
                               message=f"{vendor} {i}", raw={"vendor": vendor, "i": i})

    events = []
    for i in range(6):                                    # healthy: newest is "now"
        events.append(evt("acme", "fw", now - timedelta(minutes=i), i))
    for i in range(6):                                    # silent: newest is ~2h old (>60m)
        events.append(evt("beta", "ids", now - timedelta(hours=2, minutes=i), i))
    with db.pool().connection() as conn:
        db.insert_events(conn, events, 1)
        conn.commit()

    rows = {(r["vendor"], r["log_type"]): r for r in db.source_activity(7)}
    assert rows[("acme", "fw")]["n"] == 6 and rows[("beta", "ids")]["n"] == 6

    assert sh.run_check(now) == 1                         # only the silent source alerts
    assert sh.run_check(now) == 0                         # same repeat bucket -> deduped
    with db.pool().connection() as conn:
        got = conn.execute("SELECT rule_id, message FROM alerts "
                           "WHERE rule_id = %s", (sh.RULE_ID,)).fetchall()
    assert len(got) == 1 and "beta/ids" in got[0]["message"]
