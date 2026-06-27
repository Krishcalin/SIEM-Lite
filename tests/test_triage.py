"""Unit tests for suppression / allowlist matching (pure, no DB)."""
from app.triage.suppression import Suppression, SuppressionIndex, matches


def _alert(**kw) -> dict:
    base = {"rule_id": "r1", "vendor": "paloalto", "user_name": "jdoe",
            "host_name": "web1", "src_ip": "10.1.2.3"}
    base.update(kw)
    return base


def test_single_condition_matching():
    assert matches(Suppression(1, rule_id="r1"), _alert())
    assert not matches(Suppression(1, rule_id="r2"), _alert())
    assert matches(Suppression(1, src_ip="10.1.2.3"), _alert())       # exact IP
    assert matches(Suppression(1, src_ip="10.0.0.0/8"), _alert())     # CIDR
    assert not matches(Suppression(1, src_ip="192.168.0.0/16"), _alert())
    assert matches(Suppression(1, user_name="JDOE"), _alert())        # case-insensitive
    assert matches(Suppression(1, vendor="PaloAlto"), _alert())
    assert matches(Suppression(1, host_name="WEB1"), _alert())


def test_all_conditions_required():
    s = Suppression(1, rule_id="r1", src_ip="10.0.0.0/8")
    assert matches(s, _alert())
    assert not matches(s, _alert(src_ip="8.8.8.8"))
    assert not matches(s, _alert(rule_id="other"))


def test_empty_suppression_matches_nothing():
    assert Suppression(1).is_empty()
    assert not matches(Suppression(1), _alert())


def test_missing_alert_field_does_not_match():
    assert not matches(Suppression(1, user_name="jdoe"), _alert(user_name=None))
    assert not matches(Suppression(1, src_ip="10.0.0.0/8"), _alert(src_ip=None))


def test_index_returns_first_match_and_skips_empty():
    ix = SuppressionIndex([Suppression(1),                       # empty -> skipped
                           Suppression(2, vendor="cisco"),
                           Suppression(3, rule_id="r1")])
    assert len(ix) == 2
    m = ix.match(_alert())
    assert m is not None and m.id == 3
    assert ix.match(_alert(rule_id="x", vendor="x")) is None
