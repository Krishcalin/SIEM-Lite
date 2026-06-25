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
