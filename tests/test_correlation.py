"""Unit tests for correlation rule loading + alert building (no DB needed)."""
from pathlib import Path

from app.detection.correlation import (CorrelationRule, correlation_alert,
                                        load_correlation_rules, window_seconds)

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def test_window_seconds_parsing():
    assert window_seconds("5m") == 300
    assert window_seconds("30s") == 30
    assert window_seconds("2h") == 7200
    assert window_seconds("1d") == 86400
    assert window_seconds(90) == 90
    assert window_seconds("garbage") == 300        # safe default


def test_load_correlation_rules():
    rules = load_correlation_rules(RULES_DIR)
    by_id = {r.id: r for r in rules}
    assert "lo-corr-bruteforce-logon" in by_id
    bf = by_id["lo-corr-bruteforce-logon"]
    assert bf.match == {"action": "failed-logon"}
    assert bf.group_by == ["src_ip"] and bf.window == 300 and bf.threshold == 5
    assert "T1110" in bf.techniques
    # the per-event rule files (no `correlation:` block) are NOT loaded here
    assert "lo-win-failed-logon" not in by_id


def test_load_tripwire_mass_change_correlation_rule():
    by_id = {r.id: r for r in load_correlation_rules(RULES_DIR)}
    mc = by_id["lo-corr-tripwire-mass-change"]
    assert mc.match["vendor"] == "tripwire"
    assert "modified" in mc.match["action"] and "removed" in mc.match["action"]
    assert mc.group_by == ["host_name"]
    assert mc.window == 600 and mc.threshold == 50
    assert "T1486" in mc.techniques and "impact" in mc.tactics


def test_correlation_alert_dedup_is_stable_per_window_bucket():
    rule = CorrelationRule(id="lo-corr-bruteforce-logon", title="Brute Force",
                           level="high", description="", match={"action": "failed-logon"},
                           group_by=["src_ip"], window=300, threshold=5,
                           techniques=["T1110"], tactics=["credential access"])
    row = {"src_ip": "45.83.122.7", "n": 9, "last_seen": None}
    a1 = correlation_alert(rule, row, bucket=100)
    a2 = correlation_alert(rule, row, bucket=100)        # same window -> same dedup
    a3 = correlation_alert(rule, row, bucket=101)        # next window -> new dedup
    assert a1["dedup_hash"] == a2["dedup_hash"]
    assert a1["dedup_hash"] != a3["dedup_hash"]
    assert a1["src_ip"] == "45.83.122.7" and a1["level"] == "high"
    assert "9 matching events" in a1["message"] and "T1110" in a1["techniques"]
