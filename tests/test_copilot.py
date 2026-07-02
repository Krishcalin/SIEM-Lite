"""Tests for the AI SOC copilot.

All DB-free and network-free: the pure prompt/parse helpers are tested directly,
and the high-level operations run against a fake client that records the prompt
and returns canned text — no anthropic SDK or API key required.
"""
from __future__ import annotations

from app.copilot import client as cop
from app.copilot import prompts


_ALERT = {
    "id": 7, "rule_id": "aws-root-login", "rule_title": "AWS Root Console Login",
    "level": "high", "tactics": ["initial access"], "techniques": ["T1078.004"],
    "vendor": "aws", "src_ip": "203.0.113.9", "user_name": "root", "host_name": None,
    "message": "ConsoleLogin by root", "event_time": "2026-07-02T10:00:00Z",
}


# --------------------------------------------------------------------------- #
#  Pure prompt builders                                                        #
# --------------------------------------------------------------------------- #
def test_alert_brief_includes_key_fields():
    brief = prompts.alert_brief(_ALERT)
    assert "AWS Root Console Login" in brief
    assert "T1078.004" in brief
    assert "203.0.113.9" in brief
    assert "root" in brief


def test_build_alert_explain_shape():
    system, user = prompts.build_alert_explain(
        _ALERT, related=[{"level": "medium", "rule_title": "Unusual API call",
                          "user_name": "root", "host_name": None, "src_ip": "203.0.113.9"}])
    assert "SOC analyst" in system
    assert "Triage steps" in user
    assert "RELATED ALERTS" in user
    assert "Unusual API call" in user


def test_build_case_summary_shape():
    case = {"title": "Root takeover", "severity": "critical", "status": "open",
            "summary": "possible root compromise"}
    system, user = prompts.build_case_summary(
        case, [_ALERT], notes=[{"note": "escalated to IR"}])
    assert "Attack narrative" in user
    assert "escalated to IR" in user
    assert "Root takeover" in user


def test_build_sigma_from_nl_shape():
    system, user = prompts.build_sigma_from_nl("detect root console login", '{"vendor":"aws"}')
    assert "Sigma" in system and "condition" in system
    assert "detect root console login" in user
    assert "yaml" in user.lower()


def test_clip_truncates():
    assert prompts._clip("x" * 5000).endswith("…[truncated]")
    assert prompts._clip("short") == "short"


# --------------------------------------------------------------------------- #
#  Sigma extraction + validation                                              #
# --------------------------------------------------------------------------- #
_RULE = ("title: t\nid: t\nlevel: high\n"
         "detection:\n  sel:\n    message|contains: '-enc'\n  condition: sel\n")


def test_extract_yaml_from_fence():
    text = f"Here is the rule:\n```yaml\n{_RULE}```\nHope that helps."
    out = prompts.extract_yaml(text)
    assert out and "condition: sel" in out and "Hope that helps" not in out


def test_extract_yaml_plain_fence():
    out = prompts.extract_yaml(f"```\n{_RULE}```")
    assert out and "detection" in out


def test_extract_yaml_bare_rule():
    assert prompts.extract_yaml(_RULE) is not None


def test_extract_yaml_none_on_prose():
    assert prompts.extract_yaml("I cannot write that rule.") is None


def test_valid_sigma():
    assert prompts.valid_sigma(_RULE)[0] is True
    assert prompts.valid_sigma("")[0] is False
    assert prompts.valid_sigma("title: t\nid: t\n")[0] is False          # no detection
    assert prompts.valid_sigma("detection:\n  sel: {a: 1}\n")[0] is False  # no condition
    assert prompts.valid_sigma(":\n  bad: [unclosed")[0] is False          # bad YAML


# --------------------------------------------------------------------------- #
#  High-level operations with a fake client                                   #
# --------------------------------------------------------------------------- #
class FakeClient:
    def __init__(self, reply: str):
        self.reply = reply
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str, max_tokens=None) -> str:
        self.calls.append((system, user))
        return self.reply


def test_explain_alert_uses_client():
    fc = FakeClient("What happened — root logged in.")
    out = cop.explain_alert(fc, _ALERT)
    assert out.startswith("What happened")
    assert len(fc.calls) == 1
    assert "AWS Root Console Login" in fc.calls[0][1]   # alert brief reached the prompt


def test_summarize_case_uses_client():
    fc = FakeClient("Summary — root account compromise.")
    out = cop.summarize_case(fc, {"title": "c", "severity": "high", "status": "open"}, [_ALERT])
    assert "Summary" in out and len(fc.calls) == 1


def test_generate_sigma_extracts_and_validates():
    fc = FakeClient(f"Sure:\n```yaml\n{_RULE}```")
    result = cop.generate_sigma(fc, "detect encoded powershell")
    assert result["valid"] is True
    assert "condition: sel" in result["yaml"]
    assert result["error"] is None


def test_generate_sigma_handles_no_rule():
    fc = FakeClient("I can't help with that.")
    result = cop.generate_sigma(fc, "detect something")
    assert result["valid"] is False
    assert result["yaml"] is None
    assert "No YAML" in result["error"]


# --------------------------------------------------------------------------- #
#  Configuration gating                                                        #
# --------------------------------------------------------------------------- #
def test_is_configured_false_when_disabled():
    # COPILOT_ENABLED defaults to False in the test environment
    assert cop.is_configured() is False


def test_anthropic_available_returns_bool():
    assert isinstance(cop.anthropic_available(), bool)
