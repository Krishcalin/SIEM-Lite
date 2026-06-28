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
