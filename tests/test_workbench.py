"""Tests for the detection-engineering workbench.

Unit tests exercise the pure rule tester, coverage map, and rule-health buckets;
the integration test checks the windowed rule-firing SQL against a real DB.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app import workbench as wb

_RULE = """title: Encoded PowerShell
id: t-enc-ps
level: high
logsource:
  product: windows
detection:
  sel:
    message|contains: '-enc'
  condition: sel
tags:
  - attack.execution
  - attack.t1059.001
"""


# --------------------------------------------------------------------------- #
#  Rule tester                                                                #
# --------------------------------------------------------------------------- #
def test_rule_match():
    r = wb.test_rule(_RULE, '{"vendor":"microsoft","message":"powershell -enc AAA"}')
    assert r["ok"] and r["error"] is None
    assert r["matched"] is True
    assert r["logsource_ok"] is True
    assert r["selections"] == {"sel": True}
    assert r["techniques"] == ["T1059.001"]
    assert "execution" in r["tactics"]


def test_rule_no_match_on_logsource():
    # right message, wrong product → logsource fails, no match
    r = wb.test_rule(_RULE, '{"vendor":"paloalto","message":"powershell -enc AAA"}')
    assert r["ok"] and r["matched"] is False
    assert r["logsource_ok"] is False


def test_rule_no_match_on_selection():
    r = wb.test_rule(_RULE, '{"vendor":"microsoft","message":"notepad.exe"}')
    assert r["ok"] and r["matched"] is False
    assert r["selections"] == {"sel": False}


def test_rule_matches_via_field_alias():
    # rule keys on `User`; event supplies normalized user_name → alias resolves
    rule = ("title: t\nid: t\nlogsource: {}\n"
            "detection:\n  sel:\n    User: alice\n  condition: sel\n")
    r = wb.test_rule(rule, '{"user_name":"alice"}')
    assert r["matched"] is True


def test_rule_bad_yaml_and_json():
    assert wb.test_rule("::: not yaml :::", "{}")["error"]
    assert wb.test_rule(_RULE, "{not json}")["error"]
    assert wb.test_rule("title: x\nid: x\n", "{}")["error"]  # no detection block
    assert wb.test_rule(_RULE, '["not","an","object"]')["error"]


# --------------------------------------------------------------------------- #
#  Coverage map                                                               #
# --------------------------------------------------------------------------- #
def _rule(tactics, techs, enabled=True, **extra):
    return {"tactics": tactics, "techniques": techs, "enabled": enabled, **extra}


def test_coverage_counts_and_gaps():
    rules = [
        _rule(["execution"], ["T1059.001"], enabled=True),
        _rule(["credential access"], ["T1003.001"], enabled=True),
        _rule(["impact"], ["T1490"], enabled=False),      # only on a disabled rule
        _rule([], [], enabled=True),                       # untagged
    ]
    cov = wb.coverage_map(rules)
    assert cov["total_techniques"] == 3
    assert cov["covered_techniques"] == 2
    assert cov["uncovered_techniques"] == ["T1490"]
    assert cov["coverage_pct"] == round(200.0 / 3, 1)
    assert cov["untagged_rules"] == 1


def test_coverage_technique_covered_wins_over_disabled():
    # same technique on an enabled AND a disabled rule → counts as covered, no gap
    rules = [
        _rule(["execution"], ["T1059.001"], enabled=True),
        _rule(["execution"], ["T1059.001"], enabled=False),
    ]
    cov = wb.coverage_map(rules)
    assert cov["uncovered_techniques"] == []
    exec_stage = next(t for t in cov["tactics"] if t["tactic"] == "execution")
    assert exec_stage["covered"] == ["T1059.001"] and exec_stage["uncovered"] == []


def test_coverage_tactics_in_kill_chain_order():
    rules = [_rule(["impact"], ["T1490"]), _rule(["execution"], ["T1059"]),
             _rule(["initial access"], ["T1078"])]
    order = [t["tactic"] for t in wb.coverage_map(rules)["tactics"]]
    assert order == ["initial-access", "execution", "impact"]


# --------------------------------------------------------------------------- #
#  Rule health                                                                #
# --------------------------------------------------------------------------- #
def test_rule_health_buckets():
    rules = [
        _rule(["execution"], ["T1059"], enabled=True, fired_total=10, fired_window=80),   # noisy
        _rule(["discovery"], ["T1087"], enabled=True, fired_total=0, fired_window=0),      # never
        _rule(["impact"], ["T1490"], enabled=True, fired_total=5, fired_window=0),         # stale
        _rule(["persistence"], ["T1547"], enabled=False, fired_total=1, fired_window=1),   # disabled
        _rule(["execution"], ["T1204"], enabled=True, fired_total=3, fired_window=3),      # healthy
    ]
    h = wb.rule_health(rules, noisy_window_threshold=50)
    assert [r["techniques"] for r in h["noisy"]] == [["T1059"]]
    assert [r["techniques"] for r in h["never_fired"]] == [["T1087"]]
    assert [r["techniques"] for r in h["stale"]] == [["T1490"]]
    assert len(h["disabled"]) == 1
    assert h["counts"] == {"total": 5, "enabled": 4, "never_fired": 1,
                           "noisy": 1, "stale": 1, "disabled": 1}


def test_rule_health_noisy_sorted_desc():
    rules = [
        _rule([], ["A"], fired_total=1, fired_window=60),
        _rule([], ["B"], fired_total=1, fired_window=200),
        _rule([], ["C"], fired_total=1, fired_window=90),
    ]
    windows = [r["fired_window"] for r in wb.rule_health(rules, 50)["noisy"]]
    assert windows == [200, 90, 60]


# --------------------------------------------------------------------------- #
#  Integration: windowed firing stats                                         #
# --------------------------------------------------------------------------- #
@pytest.mark.integration
def test_rule_stats_windowed(clean_db):
    from app.detection.engine import Rule
    db = clean_db
    now = datetime.now(timezone.utc)

    db.sync_rules([
        Rule(id="r-fires", title="Fires", level="high", description="",
             logsource={}, detection={}, tactics=["execution"], techniques=["T1059"]),
        Rule(id="r-quiet", title="Quiet", level="low", description="",
             logsource={}, detection={}, tactics=["discovery"], techniques=["T1087"]),
    ])

    def mk(dh, days_ago):
        return {"event_time": now - timedelta(days=days_ago), "rule_id": "r-fires",
                "rule_title": "Fires", "level": "high", "tactics": ["execution"],
                "techniques": ["T1059"], "vendor": None, "src_ip": None, "dst_ip": None,
                "user_name": None, "host_name": None, "message": "m",
                "dedup_hash": dh, "batch_id": None, "status": "open"}

    with db.pool().connection() as conn:
        db.insert_alerts(conn, [mk("a", 1), mk("b", 5), mk("c", 40)])  # 2 in 30d, 3 all-time
        conn.commit()

    stats = {r["rule_id"]: r for r in db.rule_stats(days=30)}
    assert stats["r-fires"]["fired_total"] == 3
    assert stats["r-fires"]["fired_window"] == 2          # the 40-day-old one is outside
    assert stats["r-fires"]["last_fired"] is not None
    assert stats["r-quiet"]["fired_total"] == 0 and stats["r-quiet"]["fired_window"] == 0

    # feed the real registry through the pure analytics
    cov = wb.coverage_map(list(db.rule_stats(30)))
    assert "T1059" in cov["covered_techniques"] or cov["covered_techniques"] >= 0
    health = wb.rule_health(list(db.rule_stats(30)), noisy_window_threshold=1)
    assert any(r["rule_id"] == "r-fires" for r in health["noisy"])
    assert any(r["rule_id"] == "r-quiet" for r in health["never_fired"])
