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
    assert a1["status"] == "open"        # regression: correlation alerts need `status`


def test_all_alert_builders_cover_every_insert_param():
    """Every alert-dict builder must supply all named params in _ALERT_INSERT.

    Guards the whole class of "query parameter missing: X" bugs — a builder that
    forgets a field the SQL binds (e.g. `status`) crashes insert_alerts at runtime.
    """
    import re
    from datetime import datetime, timezone

    from app import db
    from app.detection.engine import Rule, alert_from_match
    from app.models import NormalizedEvent
    from app.threatintel.matcher import IocHit, ti_alert

    required = set(re.findall(r"%\((\w+)\)s", db._ALERT_INSERT))
    evt = NormalizedEvent(event_time=datetime.now(timezone.utc), vendor="v",
                          src_ip="1.2.3.4", user_name="alice", message="m")

    corr = correlation_alert(
        CorrelationRule(id="c", title="t", level="high", description="", match={},
                        group_by=["src_ip"], window=300, threshold=5),
        {"src_ip": "1.2.3.4", "n": 5, "last_seen": None}, bucket=1)
    rule = Rule(id="r", title="t", level="high", description="", logsource={},
                detection={}, tactics=[], techniques=[])
    detn = alert_from_match(rule, evt, dedup_hash="d", batch_id=1)
    ti = ti_alert([IocHit(indicator="1.2.3.4", ioc_type="ip", source="s",
                          severity="high", observed="1.2.3.4")],
                  evt, dedup_hash="d2")

    for name, alert in (("correlation_alert", corr), ("alert_from_match", detn),
                        ("ti_alert", ti)):
        missing = required - set(alert)
        assert not missing, f"{name} is missing SQL params: {missing}"
