"""Parser + detection unit tests (no database required)."""
from pathlib import Path

from app.detect import detect_format
from app.parsers import (crowdstrike_csv, crowdstrike_json, paloalto_csv,
                         paloalto_syslog)

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


def test_detect_format():
    assert detect_format("t.csv", _read("paloalto_traffic.csv")) == "paloalto_csv"
    assert detect_format("s.log", _read("paloalto_syslog.log")) == "paloalto_syslog"
    assert detect_format("d.csv", _read("crowdstrike_detections.csv")) == "crowdstrike_csv"
    assert detect_format("e.json", _read("crowdstrike_events.json")) == "crowdstrike_json"
