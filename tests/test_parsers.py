"""Parser + detection unit tests (no database required)."""
from pathlib import Path

from app.detect import detect_format
from app.parsers import (aws_cloudtrail, azure_activity, cef, cisco_asa,
                         cisco_ios, crowdstrike_csv, crowdstrike_json,
                         entra_signin, fortinet_fortigate, gcp_audit,
                         generic_json, generic_syslog, github_audit,
                         gitlab_audit, m365_audit, meraki, okta_system_log,
                         paloalto_csv, paloalto_syslog, suricata_eve,
                         windows_security, zeek_json, zeek_tsv)

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def _read(name: str) -> str:
    return (SAMPLES / name).read_text(encoding="utf-8")


def test_paloalto_csv():
    evs = list(paloalto_csv.parse(_read("paloalto_traffic.csv")))
    assert len(evs) == 4
    e = evs[0]
    assert e.vendor == "paloalto" and e.product == "ngfw"
    assert e.src_ip == "10.20.30.40"
    assert e.dst_ip == "93.184.216.34"
    assert e.dst_port == 443
    assert e.protocol == "tcp"
    assert e.app == "ssl"
    assert e.action == "allow"
    assert e.user_name == "corp\\jdoe"
    assert e.bytes_total == 84213
    assert e.event_time.year == 2026 and e.event_time.month == 6
    threat = next(x for x in evs if x.log_type == "vulnerability")
    assert threat.severity == "critical"


def test_paloalto_syslog():
    evs = list(paloalto_syslog.parse(_read("paloalto_syslog.log")))
    assert len(evs) == 3
    traffic = next(e for e in evs if e.log_type == "end")
    assert traffic.src_ip == "10.20.30.40"
    assert traffic.dst_ip == "93.184.216.34"
    assert traffic.dst_port == 443
    assert traffic.action == "allow"
    assert traffic.app == "ssl"
    assert traffic.user_name == "corp\\jdoe"
    assert traffic.bytes_total == 84213
    threat = next(e for e in evs if e.log_type == "vulnerability")
    assert threat.severity == "critical"
    assert "SMB" in (threat.message or "")
    system = next(e for e in evs if e.log_type == "system")
    assert system.severity == "informational"
    assert "Configuration committed" in (system.message or "")


def test_crowdstrike_csv():
    evs = list(crowdstrike_csv.parse(_read("crowdstrike_detections.csv")))
    assert len(evs) == 3
    e = evs[0]
    assert e.vendor == "crowdstrike" and e.product == "falcon"
    assert e.log_type == "detection"
    assert e.severity == "Critical"
    assert e.host_name == "FIN-WS-014"
    assert e.user_name == "corp\\jdoe"
    assert e.event_time.year == 2026
    assert "Credential" in (e.message or "")


def test_crowdstrike_json():
    evs = list(crowdstrike_json.parse(_read("crowdstrike_events.json")))
    assert len(evs) == 2
    e = evs[0]
    assert e.vendor == "crowdstrike"
    assert e.log_type == "detection"
    assert e.host_name == "FIN-WS-014"
    assert e.src_ip == "10.20.30.40"
    assert e.severity == "Critical"
    assert e.event_time.year == 2026
    rev = evs[1]
    assert rev.dst_ip == "45.83.122.7"
    assert rev.dst_port == 4444


def test_cef():
    evs = list(cef.parse(_read("cef.log")))
    assert len(evs) == 3
    fg = evs[0]
    assert fg.vendor == "fortinet" and fg.product == "fortigate"
    assert fg.log_type == "firewall"
    assert fg.src_ip == "10.20.30.40" and fg.dst_port == 443 and fg.protocol == "tcp"
    assert fg.action == "accept"
    assert fg.user_name == "corp\\jdoe"
    assert fg.bytes_total == 4096 + 84213
    assert fg.severity == "low"          # CEF severity 3
    assert fg.event_time.year == 2026
    waf = evs[1]
    assert waf.vendor == "imperva inc."
    assert waf.severity == "high"        # CEF severity 8
    assert waf.action == "blocked"
    assert waf.host_name == "app.example.com"
    proxy = evs[2]
    assert proxy.vendor == "mcafee"      # syslog-wrapped CEF
    assert proxy.severity == "medium"    # CEF severity 6
    assert proxy.dst_ip == "185.220.101.5"


def test_fortinet():
    evs = list(fortinet_fortigate.parse(_read("fortinet_fortigate.log")))
    assert len(evs) == 3
    t = evs[0]
    assert t.vendor == "fortinet" and t.product == "fortigate"
    assert t.log_type == "forward"
    assert t.src_ip == "10.20.30.40" and t.dst_ip == "93.184.216.34" and t.dst_port == 443
    assert t.protocol == "tcp"
    assert t.action == "accept"
    assert t.user_name == "corp\\jdoe"
    assert t.host_name == "FGT60F-CORP"
    assert t.rule_name == "Corp-to-Internet"
    assert t.bytes_total == 4096 + 84213
    assert t.severity == "notice"
    assert t.event_time.year == 2026 and t.event_time.month == 6
    ips = next(e for e in evs if e.log_type == "ips")
    assert ips.action == "dropped" and ips.severity == "critical"
    assert ips.src_ip == "45.83.122.7"
    sysev = next(e for e in evs if e.log_type == "system")
    assert sysev.action == "login" and sysev.user_name == "admin"


def test_suricata():
    evs = list(suricata_eve.parse(_read("suricata_eve.json")))
    assert len(evs) == 3
    a = evs[0]
    assert a.vendor == "suricata" and a.log_type == "alert"
    assert a.severity == "high" and a.action == "blocked"
    assert a.src_ip == "45.83.122.7" and a.dst_ip == "10.20.30.40" and a.dst_port == 51515
    assert a.protocol == "tcp"
    assert a.rule_name == "ET MALWARE Backdoor.DoublePulsar Beacon"
    assert a.bytes_total == 1200 + 3400
    assert "DoublePulsar" in (a.message or "")
    assert a.event_time.year == 2026
    dns = next(e for e in evs if e.log_type == "dns")
    assert dns.dst_ip == "8.8.8.8" and dns.dst_port == 53 and dns.protocol == "udp"
    assert "malware-c2.example.net" in (dns.message or "")
    http = next(e for e in evs if e.log_type == "http")
    assert http.dst_ip == "185.220.101.5" and http.app == "http"
    assert "badsite.example.org" in (http.message or "")


def test_windows_json():
    evs = list(windows_security.parse(_read("windows_security.json")))
    assert len(evs) == 2
    fail = evs[0]
    assert fail.vendor == "microsoft" and fail.product == "windows"
    assert fail.log_type == "security"
    assert fail.action == "failed-logon"
    assert fail.user_name == "CORP\\jdoe"
    assert fail.src_ip == "45.83.122.7"
    assert fail.host_name == "FIN-WS-014.corp.local"
    assert fail.rule_name == "Event 4625"
    assert fail.event_time.year == 2026
    ok = evs[1]
    assert ok.action == "logon" and ok.user_name == "CORP\\asmith"
    assert ok.src_ip == "10.20.30.9"


def test_windows_csv():
    evs = list(windows_security.parse(_read("windows_security.csv")))
    assert len(evs) == 1
    e = evs[0]
    assert e.action == "process-create"
    assert e.user_name == "CORP\\jdoe"
    assert e.src_ip is None
    assert e.host_name == "FIN-WS-014.corp.local"


def test_generic_syslog():
    evs = list(generic_syslog.parse(_read("generic_syslog.log")))
    assert len(evs) == 3
    a = evs[0]
    assert a.vendor == "syslog"
    assert a.log_type == "auth"          # facility 4
    assert a.severity == "warning"       # severity 4
    assert a.host_name == "host01.corp.local"
    assert a.app == "sshd"
    assert "45.83.122.7" in (a.message or "")
    assert a.event_time.year == 2026
    b = evs[1]                           # RFC 3164
    assert b.log_type == "authpriv" and b.severity == "notice"
    assert b.app == "sudo" and b.host_name == "host02"
    assert b.event_time is not None
    c = evs[2]
    assert c.log_type == "local0" and c.severity == "informational"
    assert c.app == "myapp" and c.rule_name == "ID99"
    assert "Service started" in (c.message or "")


def test_cisco_asa():
    evs = list(cisco_asa.parse(_read("cisco_asa.log")))
    assert len(evs) == 4
    by_id = {e.log_type: e for e in evs}
    built = by_id["302013"]
    assert built.vendor == "cisco" and built.product == "asa"
    assert built.action == "allow" and built.protocol == "tcp"
    assert built.src_ip == "10.20.30.40" and built.src_port == 51514
    assert built.dst_ip == "93.184.216.34" and built.dst_port == 443
    assert built.severity == "informational"
    assert built.rule_name == "%ASA-6-302013"
    assert built.host_name == "ASA-FW"
    assert built.event_time.year == 2026
    deny = by_id["106023"]
    assert deny.action == "deny" and deny.severity == "critical"
    assert deny.src_ip == "45.83.122.7" and deny.dst_port == 51515
    cmd = by_id["111008"]
    assert cmd.user_name == "admin" and cmd.action is None
    login = by_id["605005"]
    assert login.action == "allow"
    assert login.src_ip == "10.20.30.9" and login.dst_ip == "10.20.30.5"
    assert login.user_name == "asmith"


def test_zeek():
    evs = list(zeek_tsv.parse(_read("zeek_conn.log")))
    assert len(evs) == 3
    c = evs[0]
    assert c.vendor == "zeek" and c.product == "conn" and c.log_type == "conn"
    assert c.src_ip == "10.20.30.40" and c.src_port == 51514
    assert c.dst_ip == "93.184.216.34" and c.dst_port == 443
    assert c.protocol == "tcp" and c.app == "ssl"
    assert c.bytes_total == 4096 + 84213
    assert c.action == "SF"
    assert c.event_time.year == 2026
    rej = evs[1]
    assert rej.src_ip == "45.83.122.7" and rej.dst_port == 51515
    assert rej.action == "REJ" and rej.app is None and rej.bytes_total == 0
    dns = evs[2]
    assert dns.product == "dns" and dns.dst_ip == "8.8.8.8" and dns.dst_port == 53
    assert dns.protocol == "udp" and dns.action == "NOERROR"
    assert "malware-c2.example.net" in (dns.message or "")


def test_aws_cloudtrail():
    evs = list(aws_cloudtrail.parse(_read("aws_cloudtrail.json")))
    assert len(evs) == 2
    login = evs[0]
    assert login.vendor == "aws" and login.product == "cloudtrail"
    assert login.log_type == "signin" and login.rule_name == "ConsoleLogin"
    assert login.action == "failure"
    assert login.src_ip == "45.83.122.7" and login.user_name == "jdoe"
    assert login.host_name == "123456789012"
    assert "ConsoleLogin" in (login.message or "") and "Failure" in (login.message or "")
    assert login.event_time.year == 2026
    create = evs[1]
    assert create.log_type == "iam" and create.rule_name == "CreateUser"
    assert create.action == "failed"
    assert create.src_ip == "10.20.30.9" and create.user_name == "asmith"
    assert "not authorized" in (create.message or "")


def test_m365_audit():
    evs = list(m365_audit.parse(_read("m365_audit.json")))
    assert len(evs) == 2
    fail = evs[0]
    assert fail.vendor == "microsoft" and fail.product == "o365"
    assert fail.log_type == "azureactivedirectory"
    assert fail.action == "UserLoginFailed"
    assert fail.src_ip == "45.83.122.7" and fail.user_name == "jdoe@contoso.com"
    assert "Failed" in (fail.message or "")
    assert fail.event_time.year == 2026
    dl = evs[1]
    assert dl.log_type == "sharepoint" and dl.action == "FileDownloaded"
    assert dl.src_ip == "10.20.30.9" and dl.user_name == "asmith@contoso.com"


def test_okta_system_log():
    evs = list(okta_system_log.parse(_read("okta_system_log.json")))
    assert len(evs) == 2
    fail = evs[0]
    assert fail.vendor == "okta" and fail.product == "system-log"
    assert fail.log_type == "user.session.start"
    assert fail.severity == "warning" and fail.action == "failure"
    assert fail.src_ip == "45.83.122.7" and fail.user_name == "jdoe@contoso.com"
    assert fail.rule_name == "core.user_auth.login_failed"
    assert fail.app == "Okta Dashboard"
    assert "INVALID_CREDENTIALS" in (fail.message or "")
    assert fail.event_time.year == 2026
    ok = evs[1]
    assert ok.severity == "informational" and ok.action == "success"
    assert ok.src_ip == "10.20.30.9" and ok.user_name == "asmith@contoso.com"


def test_entra_signin():
    evs = list(entra_signin.parse(_read("entra_signin.json")))
    assert len(evs) == 2
    fail = evs[0]
    assert fail.vendor == "microsoft" and fail.product == "entra"
    assert fail.log_type == "signin" and fail.action == "failure"
    assert fail.severity == "high"
    assert fail.src_ip == "45.83.122.7" and fail.user_name == "jdoe@contoso.com"
    assert fail.app == "Office 365 Exchange Online"
    assert fail.rule_name == "IMAP4"
    assert fail.host_name is None
    assert "Invalid username" in (fail.message or "")
    assert fail.event_time.year == 2026
    ok = evs[1]
    assert ok.action == "success" and ok.severity is None
    assert ok.src_ip == "10.20.30.9" and ok.user_name == "asmith@contoso.com"
    assert ok.app == "Microsoft Teams" and ok.host_name == "ASMITH-LT"


def test_cisco_ios():
    evs = list(cisco_ios.parse(_read("cisco_ios.log")))
    assert len(evs) == 4
    by_fac = {e.log_type: e for e in evs}
    acl = by_fac["sec"]
    assert acl.vendor == "cisco" and acl.product == "ios"
    assert acl.severity == "informational" and acl.action == "deny"
    assert acl.protocol == "tcp"
    assert acl.src_ip == "45.83.122.7" and acl.src_port == 4444
    assert acl.dst_ip == "10.20.30.40" and acl.dst_port == 51515
    assert acl.rule_name == "%SEC-6-IPACCESSLOGP"
    assert acl.host_name == "RTR-CORE"
    assert acl.event_time.year == 2026
    cfg = by_fac["sys"]
    assert cfg.severity == "notice" and cfg.user_name == "admin"
    assert "Configured from console" in (cfg.message or "")
    link = by_fac["link"]
    assert link.severity == "error" and link.action is None
    login = by_fac["sec_login"]
    assert login.severity == "warning" and login.action == "failure"
    assert login.user_name == "admin" and login.src_ip == "45.83.122.7"


def test_meraki():
    evs = list(meraki.parse(_read("meraki.log")))
    assert len(evs) == 3
    flows = evs[0]
    assert flows.vendor == "cisco" and flows.product == "meraki"
    assert flows.log_type == "flows" and flows.host_name == "MX84-CORP"
    assert flows.src_ip == "45.83.122.7" and flows.dst_ip == "10.20.30.40"
    assert flows.protocol == "tcp" and flows.src_port == 4444 and flows.dst_port == 51515
    assert flows.action == "deny"
    assert "deny all" in (flows.message or "")
    assert flows.event_time.year == 2026
    urls = evs[1]
    assert urls.log_type == "urls"
    assert urls.src_ip == "10.20.30.40" and urls.src_port == 51000
    assert urls.dst_ip == "93.184.216.34" and urls.dst_port == 443
    assert "example.com/login" in (urls.message or "")
    ids = evs[2]
    assert ids.log_type == "ids-alerts" and ids.protocol == "tcp"
    assert ids.src_ip == "45.83.122.7" and ids.dst_ip == "10.20.30.40"
    assert ids.rule_name == "1:2010935:3"
    assert "DoublePulsar" in (ids.message or "")


def test_zeek_json():
    evs = list(zeek_json.parse(_read("zeek_json.json")))
    assert len(evs) == 2
    c = evs[0]
    assert c.vendor == "zeek" and c.product == "conn" and c.log_type == "conn"
    assert c.src_ip == "10.20.30.40" and c.src_port == 51514
    assert c.dst_ip == "93.184.216.34" and c.dst_port == 443
    assert c.protocol == "tcp" and c.app == "ssl"
    assert c.bytes_total == 4096 + 84213 and c.action == "SF"
    assert c.event_time.year == 2026
    dns = evs[1]
    assert dns.product == "dns" and dns.dst_ip == "8.8.8.8" and dns.dst_port == 53
    assert dns.protocol == "udp" and dns.action == "NOERROR"
    assert "malware-c2.example.net" in (dns.message or "")


def test_gcp_audit():
    evs = list(gcp_audit.parse(_read("gcp_audit.json")))
    assert len(evs) == 2
    delete = evs[0]
    assert delete.vendor == "gcp" and delete.product == "cloud-audit"
    assert delete.log_type == "compute.googleapis.com"
    assert delete.action == "v1.compute.instances.delete"
    assert delete.severity == "error"
    assert delete.user_name == "jdoe@example.com" and delete.src_ip == "45.83.122.7"
    assert "PERMISSION_DENIED" in (delete.message or "")
    assert delete.rule_name == "projects/prod/zones/us-central1-a/instances/web-1"
    assert delete.event_time.year == 2026
    create = evs[1]
    assert create.log_type == "storage.googleapis.com"
    assert create.action == "storage.buckets.create" and create.severity == "notice"
    assert create.user_name == "asmith@example.com" and create.src_ip == "10.20.30.9"


def test_azure_activity():
    evs = list(azure_activity.parse(_read("azure_activity.json")))
    assert len(evs) == 2
    vm = evs[0]
    assert vm.vendor == "microsoft" and vm.product == "azure"
    assert vm.log_type == "administrative"
    assert vm.action == "MICROSOFT.COMPUTE/VIRTUALMACHINES/DELETE"
    assert vm.severity == "warning"
    assert vm.user_name == "jdoe@contoso.com" and vm.src_ip == "45.83.122.7"
    assert "Success" in (vm.message or "")
    assert vm.event_time.year == 2026
    role = evs[1]
    assert role.severity == "error" and "Failure" in (role.message or "")
    assert role.user_name == "asmith@contoso.com" and role.src_ip == "10.20.30.9"


def test_github_audit():
    evs = list(github_audit.parse(_read("github_audit.json")))
    assert len(evs) == 2
    destroy = evs[0]
    assert destroy.vendor == "github" and destroy.product == "audit"
    assert destroy.log_type == "repo" and destroy.action == "repo.destroy"
    assert destroy.user_name == "jdoe" and destroy.src_ip == "45.83.122.7"
    assert destroy.rule_name == "Krishcalin/secret-proj"
    assert "repo.destroy" in (destroy.message or "")
    assert destroy.event_time.year == 2026
    override = evs[1]
    assert override.log_type == "protected_branch"
    assert override.action == "protected_branch.policy_override"
    assert override.user_name == "asmith" and override.src_ip == "10.20.30.9"


def test_gitlab_audit():
    evs = list(gitlab_audit.parse(_read("gitlab_audit.json")))
    assert len(evs) == 2
    proj = evs[0]
    assert proj.vendor == "gitlab" and proj.product == "audit"
    assert proj.log_type == "project" and proj.action == "Removed project"
    assert proj.user_name == "jdoe" and proj.src_ip == "45.83.122.7"
    assert proj.rule_name == "Krishcalin/secret-proj"
    assert proj.event_time.year == 2026
    usr = evs[1]
    assert usr.log_type == "user" and usr.action == "add user"
    assert usr.user_name == "asmith" and usr.src_ip == "10.20.30.9"
    assert usr.rule_name == "backdoor"


def test_generic_json():
    evs = list(generic_json.parse(_read("generic_json.json")))
    assert len(evs) == 2
    ecs = evs[0]                                  # Elastic Common Schema (nested)
    assert ecs.vendor == "json"
    assert ecs.action == "file-deleted" and ecs.severity == "high"
    assert ecs.src_ip == "45.83.122.7" and ecs.src_port == 51530
    assert ecs.dst_ip == "10.20.30.40" and ecs.dst_port == 445
    assert ecs.user_name == "corp\\jdoe" and ecs.host_name == "FIN-WS-014"
    assert ecs.protocol == "tcp" and ecs.rule_name == "FIM-001"
    assert ecs.message == "Sensitive file deleted"
    assert ecs.event_time.year == 2026
    flat = evs[1]                                 # flat keys + epoch seconds
    assert flat.src_ip == "10.20.30.9" and flat.dst_ip == "185.220.101.5"
    assert flat.dst_port == 8080 and flat.user_name == "asmith"
    assert flat.action == "allow" and flat.severity == "low"
    assert flat.bytes_total == 2048 and flat.event_time.year == 2026


def test_detect_format():
    assert detect_format("t.csv", _read("paloalto_traffic.csv")) == "paloalto_csv"
    assert detect_format("s.log", _read("paloalto_syslog.log")) == "paloalto_syslog"
    assert detect_format("d.csv", _read("crowdstrike_detections.csv")) == "crowdstrike_csv"
    assert detect_format("e.json", _read("crowdstrike_events.json")) == "crowdstrike_json"
    assert detect_format("c.log", _read("cef.log")) == "cef"
    assert detect_format("f.log", _read("fortinet_fortigate.log")) == "fortinet_fortigate"
    assert detect_format("s.json", _read("suricata_eve.json")) == "suricata_eve"
    assert detect_format("w.json", _read("windows_security.json")) == "windows_security"
    assert detect_format("w.csv", _read("windows_security.csv")) == "windows_security"
    assert detect_format("a.log", _read("cisco_asa.log")) == "cisco_asa"
    assert detect_format("z.log", _read("zeek_conn.log")) == "zeek_tsv"
    assert detect_format("g.log", _read("generic_syslog.log")) == "generic_syslog"
    assert detect_format("ct.json", _read("aws_cloudtrail.json")) == "aws_cloudtrail"
    assert detect_format("m.json", _read("m365_audit.json")) == "m365_audit"
    assert detect_format("o.json", _read("okta_system_log.json")) == "okta_system_log"
    assert detect_format("en.json", _read("entra_signin.json")) == "entra_signin"
    assert detect_format("ios.log", _read("cisco_ios.log")) == "cisco_ios"
    assert detect_format("mr.log", _read("meraki.log")) == "meraki"
    assert detect_format("zj.json", _read("zeek_json.json")) == "zeek_json"
    assert detect_format("gcp.json", _read("gcp_audit.json")) == "gcp_audit"
    assert detect_format("az.json", _read("azure_activity.json")) == "azure_activity"
    assert detect_format("gh.json", _read("github_audit.json")) == "github_audit"
    assert detect_format("gl.json", _read("gitlab_audit.json")) == "gitlab_audit"
    assert detect_format("gj.json", _read("generic_json.json")) == "generic_json"
