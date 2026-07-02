"""Unit tests for the ATT&CK Navigator layer export (pure)."""
from app.navigator import build_layer


def test_layer_scores_sorts_and_grades():
    layer = build_layer({"T1110": 7, "T1021.001": 3}, days=14)
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5"
    assert "14d" in layer["name"]
    techs = layer["techniques"]
    assert [t["techniqueID"] for t in techs] == ["T1021.001", "T1110"]   # sorted by id
    assert {t["techniqueID"]: t["score"] for t in techs} == {"T1110": 7, "T1021.001": 3}
    assert layer["gradient"]["maxValue"] == 7
    assert techs[0]["comment"] == "3 alert(s)"


def test_layer_empty_has_safe_gradient():
    layer = build_layer({})
    assert layer["techniques"] == []
    assert layer["gradient"]["maxValue"] == 1          # never a zero-width range


def test_enterprise_domain_excludes_ics_techniques():
    layer = build_layer({"T1110": 5, "T0858": 3})       # mixed IT + ICS
    assert layer["domain"] == "enterprise-attack"
    assert [t["techniqueID"] for t in layer["techniques"]] == ["T1110"]


def test_ics_domain_selects_only_ics_techniques():
    layer = build_layer({"T1110": 5, "T0858": 3, "T0889": 1}, domain="ics-attack")
    assert layer["domain"] == "ics-attack"
    assert [t["techniqueID"] for t in layer["techniques"]] == ["T0858", "T0889"]
    assert "ICS" in layer["name"]
