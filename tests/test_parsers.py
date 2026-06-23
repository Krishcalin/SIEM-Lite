"""Parser + detection unit tests (no database required)."""
from pathlib import Path

from app.detect import detect_format
from app.parsers import (cef, crowdstrike_csv, crowdstrike_json,
                         fortinet_fortigate, paloalto_csv, paloalto_syslog,
                         suricata_eve, windows_security)

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
