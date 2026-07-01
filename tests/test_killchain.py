"""Tests for kill-chain / attack-story reconstruction.

Unit tests exercise the pure reconstructor in app/killchain.py (DB-free); the
integration test at the bottom persists a story as a case against a real DB.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app import killchain as kc

T0 = datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc)


def _a(id, minutes, tactics, techniques=(), level="medium", **entities):
    d = {"id": id, "event_time": T0 + timedelta(minutes=minutes),
         "tactics": list(tactics), "techniques": list(techniques), "level": level}
    d.update(entities)
    return d


# --------------------------------------------------------------------------- #
#  Tactic ordering + normalisation                                            #
# --------------------------------------------------------------------------- #
def test_normalize_tactic_variants():
    assert kc.normalize_tactic("Credential Access") == "credential-access"
    assert kc.normalize_tactic("credential_access") == "credential-access"
    assert kc.normalize_tactic("attack.defense_evasion") == "defense-evasion"
    assert kc.normalize_tactic("lateral-movement") == "lateral-movement"


def test_tactic_rank_is_kill_chain_ordered():
    assert kc.tactic_rank("initial access") < kc.tactic_rank("execution")
    assert kc.tactic_rank("execution") < kc.tactic_rank("exfiltration")
    assert kc.tactic_rank("credential access") < kc.tactic_rank("impact")
    # unknown tactics sort last
    assert kc.tactic_rank("not-a-tactic") > kc.tactic_rank("impact")


def test_tactic_title():
    assert kc.tactic_title("credential_access") == "Credential Access"


def test_alert_entities():
    a = _a(1, 0, ["execution"], src_ip="10.0.0.1", user_name="bob", host_name="H1")
    assert kc.alert_entities(a) == {("ip", "10.0.0.1"), ("user", "bob"), ("host", "H1")}
    assert kc.alert_entities(_a(2, 0, ["execution"])) == set()


# --------------------------------------------------------------------------- #
#  Chain building                                                             #
# --------------------------------------------------------------------------- #
def test_single_linkage_across_entities():
    # alice links 1↔2, host H1 links 2↔3 → all three form one chain
    alerts = [
        _a(1, 0, ["initial access"], user_name="alice", src_ip="10.0.0.5"),
        _a(2, 10, ["execution"], user_name="alice", host_name="H1"),
        _a(3, 20, ["credential access"], host_name="H1"),
    ]
    chains = kc.build_chains(alerts, max_gap_seconds=1800, min_tactics=2)
    assert len(chains) == 1
    assert {a["id"] for a in chains[0]} == {1, 2, 3}


def test_single_tactic_group_is_not_a_story():
    # three alerts, same entity, but all one tactic → not a kill-chain
    alerts = [_a(i, i, ["execution"], host_name="H1") for i in range(3)]
    assert kc.build_chains(alerts, min_tactics=2) == []


def test_time_gap_splits_chains():
    # same host but 3h apart, each alert alone is a single tactic → no story
    alerts = [
        _a(1, 0, ["execution"], host_name="H1"),
        _a(2, 180, ["exfiltration"], host_name="H1"),
    ]
    assert kc.build_chains(alerts, max_gap_seconds=3600, min_tactics=2) == []
    # within the gap they link into one 2-tactic story
    near = [_a(1, 0, ["execution"], host_name="H1"),
            _a(2, 30, ["exfiltration"], host_name="H1")]
    assert len(kc.build_chains(near, max_gap_seconds=3600, min_tactics=2)) == 1


def test_unrelated_noise_excluded():
    alerts = [
        _a(1, 0, ["initial access"], user_name="alice", host_name="H1"),
        _a(2, 10, ["execution"], host_name="H1"),
        _a(9, 5, ["discovery"], src_ip="192.168.9.9"),   # different entity, 1 tactic
    ]
    chains = kc.build_chains(alerts, max_gap_seconds=1800, min_tactics=2)
    assert len(chains) == 1 and 9 not in {a["id"] for a in chains[0]}


# --------------------------------------------------------------------------- #
#  Story summary                                                              #
# --------------------------------------------------------------------------- #
def _story():
    alerts = [
        _a(1, 0, ["initial access"], ["T1078"], "medium", src_ip="10.0.0.5", user_name="alice"),
        _a(2, 10, ["execution"], ["T1059.001"], "high", user_name="alice", host_name="H1"),
        _a(3, 20, ["credential access"], ["T1003.001"], "critical", host_name="H1"),
        _a(4, 40, ["exfiltration"], ["T1048"], "high", host_name="H1"),
    ]
    return kc.summarize_chain(alerts)


def test_summary_stage_ordering_and_rollup():
    s = _story()
    assert [st["tactic"] for st in s["stages"]] == [
        "initial-access", "execution", "credential-access", "exfiltration"]
    assert s["tactic_count"] == 4
    assert s["alert_count"] == 4
    assert s["severity"] == "critical"                 # max of members
    assert s["alert_ids"] == [1, 2, 3, 4]


def test_summary_pivot_entities_are_shared():
    s = _story()
    ents = {(e["type"], e["value"]): e["count"] for e in s["entities"]}
    # H1 shared by 3 alerts, alice by 2; only shared (>=2) entities are pivots
    assert ents[("host", "H1")] == 3
    assert ents[("user", "alice")] == 2
    assert s["entities"][0]["value"] == "H1"           # most-shared first


def test_summary_title_narrative_and_signature():
    s = _story()
    assert "Initial Access" in s["title"] and "Exfiltration" in s["title"]
    assert "H1" in s["title"]
    assert s["techniques"] == ["T1003.001", "T1048", "T1059.001", "T1078"]
    # signature is stable and order-independent for the same alert set
    assert s["signature"] == kc.summarize_chain(list(reversed(s["alerts"])))["signature"]


def test_reconstruct_orders_by_severity():
    # story A: 2 tactics, high; story B: 2 tactics, critical → B first
    a = [_a(1, 0, ["execution"], level="high", host_name="HA"),
         _a(2, 5, ["exfiltration"], level="high", host_name="HA")]
    b = [_a(3, 0, ["execution"], level="critical", user_name="ub"),
         _a(4, 5, ["impact"], level="critical", user_name="ub")]
    stories = kc.reconstruct(a + b, max_gap_seconds=1800, min_tactics=2)
    assert len(stories) == 2
    assert stories[0]["severity"] == "critical"


# --------------------------------------------------------------------------- #
#  Integration: persist a reconstructed story as a case                       #
# --------------------------------------------------------------------------- #
@pytest.mark.integration
def test_killchain_recent_and_create_case(clean_db):
    db = clean_db
    now = datetime.now(timezone.utc)

    def mk(dh, minutes_ago, tactics, level, **ent):
        a = {"event_time": now - timedelta(minutes=minutes_ago), "rule_id": "r",
             "rule_title": f"rule {dh}", "level": level, "tactics": list(tactics),
             "techniques": [], "vendor": None, "src_ip": None, "dst_ip": None,
             "user_name": None, "host_name": None, "message": "x",
             "dedup_hash": dh, "batch_id": None, "status": "open"}
        a.update(ent)
        return a

    with db.pool().connection() as conn:
        db.insert_alerts(conn, [
            mk("k1", 40, ["initial access"], "medium", user_name="alice", src_ip="10.0.0.5"),
            mk("k2", 30, ["execution"], "high", user_name="alice", host_name="H1"),
            mk("k3", 20, ["credential access"], "critical", host_name="H1"),
            mk("noise", 10, ["discovery"], "low", src_ip="192.168.1.1"),
        ])
        conn.commit()

    alerts = db.recent_uncased_alerts(hours=24)
    assert len(alerts) == 4
    stories = kc.reconstruct(alerts, max_gap_seconds=3600, min_tactics=2)
    assert len(stories) == 1
    story = stories[0]
    assert story["severity"] == "critical" and story["tactic_count"] == 3

    cid = db.create_case_from_story(story, created_by="tester")
    case = db.get_case(cid)
    assert case["source"] == "killchain"
    assert case["severity"] == "critical"
    assert case["alert_count"] == 3                       # noise excluded
    assert story["signature"] in db.open_kc_signatures()

    # alerts are now cased → excluded from the next reconstruction
    assert len(db.recent_uncased_alerts(hours=24)) == 1   # only the noise alert
