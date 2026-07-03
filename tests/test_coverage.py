"""Unit tests for the detection-coverage scoreboard (no database)."""
import re
from pathlib import Path

from app import coverage
from app.detection.correlation import load_correlation_rules
from app.detection.engine import Rule, load_rules, rule_from_dict

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def _rule(**kw):
    kw.setdefault("title", "t")
    kw.setdefault("level", "high")
    kw.setdefault("description", "d")
    kw.setdefault("logsource", {})
    kw.setdefault("detection", {})
    return Rule(id=kw.pop("id", "r"), **kw)


# ── rule metadata schema ─────────────────────────────────────────────────────
def test_rule_from_dict_parses_new_metadata():
    d = {"id": "lo-x", "title": "X", "level": "high",
         "description": "d", "detection": {"s": {"action": "y"}, "condition": "s"},
         "fidelity": "HIGH", "data_source": "process_creation, sysmon",
         "references": ["https://example.test/a"],
         "tags": ["attack.t1059.001", "attack.execution", "atlas.aml.t0051"]}
    r = rule_from_dict(d, "x.yml")
    assert r.fidelity == "high"
    assert r.data_source == ["process_creation", "sysmon"]
    assert r.references == ["https://example.test/a"]
    assert r.techniques == ["T1059.001"] and "execution" in r.tactics
    assert r.atlas_techniques == ["AML.T0051"]


def test_fidelity_defaults_and_coerces():
    assert rule_from_dict({"id": "a", "detection": {"c": 1}}, "a").fidelity == "medium"
    assert rule_from_dict({"id": "a", "fidelity": "bogus", "detection": {"c": 1}}, "a").fidelity == "medium"


# ── ATT&CK coverage ─────────────────────────────────────────────────────────
def test_attack_coverage_splits_domain_and_fidelity():
    rules = [
        _rule(id="r1", techniques=["T1059.001"], tactics=["execution"],
              fidelity="high", data_source=["process_creation"], enabled=True),
        _rule(id="r2", techniques=["T1486"], tactics=["impact"], fidelity="medium", enabled=True),
        _rule(id="r3", techniques=["T0855"], tactics=["impair process control"],
              fidelity="high", enabled=True),                       # ICS
        _rule(id="r4", techniques=["T1490"], tactics=["impact"], enabled=False),  # disabled -> gap
    ]
    cov = coverage.attack_coverage(rules)
    assert cov["enterprise_covered"] == 2          # T1059.001 + T1486 (T1490 disabled)
    assert cov["ics_covered"] == 1                 # T0855
    # fidelity spans all covered techniques: T1059.001 + T0855 high, T1486 medium
    assert cov["fidelity"]["high"] == 2 and cov["fidelity"]["medium"] == 1
    assert cov["data_sources"] == {"process_creation": 1}
    impact = next(t for t in cov["tactics"] if t["tactic"] == "impact")
    assert "T1486" in impact["enabled_techniques"]
    assert "T1490" in impact["gaps"]               # only a disabled rule covers it


def test_atlas_matrix_ids_are_wellformed_and_unique():
    ids = [tid for t in coverage.ATLAS_MATRIX for tid, _ in t["techniques"]]
    assert ids, "ATLAS matrix must not be empty"
    assert len(ids) == len(set(ids)), "duplicate ATLAS technique ids"
    pat = re.compile(r"^AML\.T\d{4}(?:\.\d{3})?$")
    assert all(pat.match(i) for i in ids), "malformed ATLAS id(s)"


def test_atlas_coverage_reflects_tagged_rules():
    empty = coverage.atlas_coverage([])
    assert empty["covered"] == 0 and empty["total"] == coverage._ATLAS_TOTAL
    tagged = coverage.atlas_coverage([_rule(id="ai", atlas_techniques=["AML.T0051"])])
    assert tagged["covered"] == 1
    ia = next(t for t in tagged["tactics"] if t["tactic"] == "initial-access")
    assert any(x["id"] == "AML.T0051" and x["covered"] for x in ia["techniques"])


def test_navigator_layer_is_valid_and_domain_filtered():
    rules = [_rule(id="e", techniques=["T1059.001"]), _rule(id="i", techniques=["T0855"])]
    ent = coverage.navigator_layer(rules, "enterprise-attack")
    assert ent["domain"] == "enterprise-attack"
    assert {t["techniqueID"] for t in ent["techniques"]} == {"T1059.001"}
    ics = coverage.navigator_layer(rules, "ics-attack")
    assert {t["techniqueID"] for t in ics["techniques"]} == {"T0855"}


# ── against the real rule pack ───────────────────────────────────────────────
def test_coverage_report_over_real_rules():
    det = load_rules(RULES_DIR)
    corr = load_correlation_rules(RULES_DIR)
    rep = coverage.coverage_report(det, corr)
    assert rep["rules"]["total"] == len(det) + len(corr)
    assert rep["attack"]["enterprise_covered"] > 0
    assert rep["attack"]["ics_covered"] > 0             # OT pack tags T0NNN
    assert rep["atlas"]["covered"] == 0                 # no AI telemetry yet
    assert rep["attack"]["untagged_rules"] == 0         # every shipped rule is tagged
