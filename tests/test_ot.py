# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""OT/ICS tests: Zeek ICSNPP enrichment, the OT rule pack, and OT analytics (no DB)."""
from pathlib import Path

from app import ot
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


# --------------------------------------------------------------------------- #
#  Phase D — OT analytics (pure; DB-free)                                      #
# --------------------------------------------------------------------------- #
def test_is_ot_protocol():
    assert ot.is_ot_protocol("modbus") and ot.is_ot_protocol("S7comm")
    assert not ot.is_ot_protocol("conn") and not ot.is_ot_protocol(None)


def test_classify_conversation():
    new_writer = {"is_new": True, "writes": 2, "controls": 0}
    new_ctrl = {"is_new": True, "writes": 0, "controls": 1}
    new_read = {"is_new": True, "writes": 0, "controls": 0}
    known = {"is_new": False, "writes": 9, "controls": 0}
    assert ot.classify_conversation(new_writer) == "new-writer"
    assert ot.classify_conversation(new_ctrl) == "new-writer"     # control also counts
    assert ot.classify_conversation(new_read) == "new"
    assert ot.classify_conversation(known) == "known"


def test_annotate_conversations_orders_new_writers_first():
    rows = [
        {"master": "10.50.0.20", "events": 40, "writes": 5, "controls": 0, "is_new": False},
        {"master": "10.99.0.5", "events": 9, "writes": 3, "controls": 0, "is_new": True},
        {"master": "10.99.0.7", "events": 2, "writes": 0, "controls": 0, "is_new": True},
    ]
    out = ot.annotate_conversations(rows)
    assert [r["class"] for r in out] == ["new-writer", "new", "known"]
    assert out[0]["master"] == "10.99.0.5"       # new writer floated to the top


def test_summarize_activity_rolls_up_totals():
    rows = [{"protocol": "modbus", "events": 10, "reads": 6, "writes": 3, "controls": 1},
            {"protocol": "dnp3", "events": 3, "reads": 1, "writes": 0, "controls": 2},
            {"protocol": "cip", "events": 0, "reads": 0, "writes": 0, "controls": 0}]
    s = ot.summarize_activity(rows)
    assert s == {"events": 13, "reads": 7, "writes": 3, "controls": 3, "protocols": 2}


def test_ot_protocols_is_single_source_for_db_filter():
    # db.ot_* filters events.log_type on exactly this list
    from app import db
    assert db.OT_PROTOCOLS is ot.OT_PROTOCOLS
    assert "modbus" in ot.OT_PROTOCOLS and "s7comm" in ot.OT_PROTOCOLS
