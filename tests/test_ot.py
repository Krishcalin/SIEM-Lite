"""OT/ICS tests: Zeek ICSNPP enrichment + the OT detection-rule pack (no DB)."""
from pathlib import Path

from app.detect import detect_format
from app.detection.correlation import load_correlation_rules
from app.detection.engine import DetectionEngine, load_rules
from app.parsers import zeek_ics, zeek_json, zeek_tsv

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def _read(name: str) -> str:
    return (SAMPLES / name).read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
#  enrich() — pure protocol mapping                                            #
# --------------------------------------------------------------------------- #
def test_enrich_returns_none_for_non_ot_paths():
    assert zeek_ics.enrich("conn", {}) is None
    assert zeek_ics.enrich("http", {"method": "GET"}) is None
    assert zeek_ics.enrich(None, {}) is None


def test_enrich_modbus_string_and_numeric_func():
    a, ot = zeek_ics.enrich("modbus_detailed", {"func": "WRITE_MULTIPLE_REGISTERS"})
    assert a == "write-registers" and ot["protocol"] == "modbus"
    assert ot["operation"] == "write" and ot["is_write"] == "true"
    a, ot = zeek_ics.enrich("modbus", {"func": "5"})          # numeric write single coil
    assert a == "write-coils" and ot["is_write"] == "true"
    a, ot = zeek_ics.enrich("modbus", {"func": "READ_HOLDING_REGISTERS"})
    assert a == "read-registers" and ot["is_write"] == "false"
    a, ot = zeek_ics.enrich("modbus", {"func": "DIAGNOSTICS"})
    assert a == "diagnostic" and ot["operation"] == "control"


def test_enrich_dnp3_control_functions():
    assert zeek_ics.enrich("dnp3", {"fc_request": "COLD_RESTART"})[0] == "cold-restart"
    assert zeek_ics.enrich("dnp3", {"fc_request": "DISABLE_UNSOLICITED"})[0] == "disable-unsolicited"
    a, ot = zeek_ics.enrich("dnp3", {"fc_request": "WRITE"})
    assert a == "write" and ot["is_write"] == "true"


def test_enrich_s7comm_and_cip():
    assert zeek_ics.enrich("s7comm", {"function_name": "Request Download"})[0] == "program-download"
    assert zeek_ics.enrich("s7comm", {"function_name": "PLC Stop"})[0] == "plc-stop"
    a, ot = zeek_ics.enrich("cip", {"cip_service": "Set Attribute Single"})
    assert a == "write-attribute" and ot["is_write"] == "true"


# --------------------------------------------------------------------------- #
#  Zeek parsers lift OT operations onto action + raw["ot"]                     #
# --------------------------------------------------------------------------- #
def test_zeek_tsv_modbus_sample():
    evs = list(zeek_tsv.parse(_read("zeek_modbus.log")))
    assert [e.action for e in evs] == ["read-registers", "write-registers", "diagnostic"]
    assert all(e.vendor == "zeek" and e.log_type == "modbus" for e in evs)
    w = evs[1]
    assert w.dst_port == 502 and w.raw["ot"]["is_write"] == "true"
    assert w.raw["ot"]["address"] == "40001"


def test_zeek_tsv_dnp3_and_s7comm_samples():
    dnp3 = list(zeek_tsv.parse(_read("zeek_dnp3.log")))
    assert [e.action for e in dnp3] == ["read", "cold-restart", "disable-unsolicited"]
    assert all(e.log_type == "dnp3" for e in dnp3)
    s7 = list(zeek_tsv.parse(_read("zeek_s7comm.log")))
    assert [e.action for e in s7] == ["read-var", "program-download", "plc-stop"]


def test_zeek_json_cip_sample():
    evs = list(zeek_json.parse(_read("zeek_cip.json")))
    assert [e.action for e in evs] == ["write-attribute", "read-attribute"]
    assert evs[0].log_type == "cip" and evs[0].raw["ot"]["is_write"] == "true"


def test_ot_samples_autodetect_as_zeek():
    assert detect_format("zeek_modbus.log", _read("zeek_modbus.log")) == "zeek_tsv"
    assert detect_format("zeek_dnp3.log", _read("zeek_dnp3.log")) == "zeek_tsv"
    assert detect_format("zeek_cip.json", _read("zeek_cip.json")) == "zeek_json"


# --------------------------------------------------------------------------- #
#  OT detection-rule pack fires on the enriched events                        #
# --------------------------------------------------------------------------- #
def _fired_ids(evt):
    eng = DetectionEngine(load_rules(RULES_DIR))
    return {r.id for r in eng.evaluate_event(evt)}


def test_ot_rules_fire_on_malicious_operations():
    all_evts = (list(zeek_tsv.parse(_read("zeek_modbus.log")))
                + list(zeek_tsv.parse(_read("zeek_dnp3.log")))
                + list(zeek_tsv.parse(_read("zeek_s7comm.log")))
                + list(zeek_json.parse(_read("zeek_cip.json"))))
    fired = {e.action: _fired_ids(e) for e in all_evts}
    assert "lo-ot-modbus-write" in fired["write-registers"]
    assert "lo-ot-modbus-diagnostic" in fired["diagnostic"]
    assert "lo-ot-dnp3-restart" in fired["cold-restart"]
    assert "lo-ot-dnp3-disable-unsolicited" in fired["disable-unsolicited"]
    assert "lo-ot-s7-program-download" in fired["program-download"]
    assert "lo-ot-s7-plc-stop" in fired["plc-stop"]
    assert "lo-ot-cip-write" in fired["write-attribute"]


def test_ot_rules_quiet_on_benign_reads():
    # a plain read must not trip any OT rule
    all_evts = (list(zeek_tsv.parse(_read("zeek_modbus.log")))
                + list(zeek_tsv.parse(_read("zeek_dnp3.log")))
                + list(zeek_tsv.parse(_read("zeek_s7comm.log")))
                + list(zeek_json.parse(_read("zeek_cip.json"))))
    by_action = {e.action: e for e in all_evts}
    for action in ("read-registers", "read", "read-var", "read-attribute"):
        fired = _fired_ids(by_action[action])
        assert not any(i.startswith("lo-ot") for i in fired), (action, fired)


def test_ot_rules_carry_ics_technique_tags():
    by_id = {r.id: r for r in load_rules(RULES_DIR)}
    assert "T0889" in by_id["lo-ot-s7-program-download"].techniques
    assert "persistence" in by_id["lo-ot-s7-program-download"].tactics
    assert "T0858" in by_id["lo-ot-s7-plc-stop"].techniques
    assert "inhibit response function" in by_id["lo-ot-s7-plc-stop"].tactics


def test_ot_scan_correlation_rule_loads():
    by_id = {r.id: r for r in load_correlation_rules(RULES_DIR)}
    scan = by_id["lo-corr-ot-scan"]
    assert scan.group_by == ["src_ip"] and scan.threshold == 100
    assert scan.match["log_type"] == ["modbus", "dnp3", "s7comm", "cip", "enip"]
    assert "T0846" in scan.techniques
