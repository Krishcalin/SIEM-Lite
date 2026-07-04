# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Unit tests for the compliance mapping + coverage report (no DB)."""
from app.compliance import (FRAMEWORKS, build_report, controls_for_technique)


def test_controls_for_technique():
    m = controls_for_technique("t1110")              # case-insensitive
    assert "NIST 800-53" in m
    nist_ids = {cid for cid, _ in m["NIST 800-53"]}
    assert "AC-7" in nist_ids
    assert controls_for_technique("T9999") == {}     # unmapped technique


def test_build_report_structure_and_frameworks():
    report = build_report(set(), {})
    assert set(report.keys()) == set(FRAMEWORKS)
    for fw in FRAMEWORKS:
        assert report[fw]["total"] > 0
        assert report[fw]["covered"] == 0            # nothing enabled -> no coverage
        for c in report[fw]["controls"]:
            assert {"id", "name", "techniques", "covered", "alerts"} <= set(c)


def test_build_report_coverage_and_alert_counts():
    # An enabled rule covering T1110 should mark its NIST controls covered, and the
    # alert counts for T1110 should attribute to those controls.
    report = build_report({"T1110"}, {"T1110": 7})
    nist = {c["id"]: c for c in report["NIST 800-53"]["controls"]}
    assert nist["AC-7"]["covered"] is True and nist["AC-7"]["alerts"] == 7
    # a control whose techniques are all unrelated stays a gap with 0 alerts
    gap = next(c for c in report["NIST 800-53"]["controls"] if not c["covered"])
    assert gap["alerts"] == 0
    assert report["NIST 800-53"]["covered"] >= 1


def test_iso27001_and_soc2_present_and_populated():
    assert "ISO 27001" in FRAMEWORKS and "SOC 2" in FRAMEWORKS
    report = build_report(set(), {})
    assert report["ISO 27001"]["total"] > 0 and report["SOC 2"]["total"] > 0


def test_enterprise_technique_maps_to_iso_and_soc2():
    m = controls_for_technique("T1486")                  # ransomware
    assert ("A.8.13", "Information Backup") in m["ISO 27001"]
    assert ("A1.2", "Availability - Backup and Recovery") in m["SOC 2"]
    # brute force lights up the authentication/logical-access controls
    bf = controls_for_technique("T1110")
    assert ("A.8.5", "Secure Authentication") in bf["ISO 27001"]
    assert ("CC6.1", "Logical Access Security") in bf["SOC 2"]


def test_enterprise_rule_coverage_lights_up_iso_soc2_controls():
    report = build_report({"T1110", "T1486"}, {"T1110": 3, "T1486": 4})
    iso = {c["id"]: c for c in report["ISO 27001"]["controls"]}
    assert iso["A.8.5"]["covered"] is True and iso["A.8.5"]["alerts"] == 3
    soc = {c["id"]: c for c in report["SOC 2"]["controls"]}
    assert soc["A1.2"]["covered"] is True and soc["A1.2"]["alerts"] == 4
    # a control mapped only to un-enabled techniques stays an uncovered gap
    assert any(not c["covered"] for c in report["ISO 27001"]["controls"])


def test_ics_frameworks_present_and_populated():
    assert "IEC 62443-3-3" in FRAMEWORKS and "NERC CIP" in FRAMEWORKS
    report = build_report(set(), {})
    assert report["IEC 62443-3-3"]["total"] > 0
    assert report["NERC CIP"]["total"] > 0


def test_ics_technique_maps_to_iec_and_nerc():
    m = controls_for_technique("T0889")              # Modify Program (PLC logic)
    assert ("SR 3.4", "Software and Information Integrity") in m["IEC 62443-3-3"]
    assert ("CIP-010", "Configuration Change Management") in m["NERC CIP"]


def test_ot_rule_coverage_lights_up_ics_controls():
    # enabling OT rules (their T0NNN techniques) covers the mapped IEC/NERC controls
    report = build_report({"T0855", "T0889"}, {"T0855": 4, "T0889": 1})
    iec = {c["id"]: c for c in report["IEC 62443-3-3"]["controls"]}
    assert iec["SR 2.1"]["covered"] is True and iec["SR 2.1"]["alerts"] == 5  # 4 + 1
    nerc = {c["id"]: c for c in report["NERC CIP"]["controls"]}
    assert nerc["CIP-010"]["covered"] is True
