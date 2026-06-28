"""Unit tests for the UEBA / entity-risk core (pure)."""
from app.models import NormalizedEvent
from app.risk import (SEVERITY_WEIGHT, decay, decayed_score, event_entities,
                      event_links, severity_weight, weight_case_sql)


def _evt(**kw) -> NormalizedEvent:
    kw.setdefault("event_time", None)
    kw.setdefault("vendor", "v")
    return NormalizedEvent(**kw)


def test_event_entities():
    e = _evt(user_name="jdoe", host_name="web1", src_ip="10.0.0.1")
    assert set(event_entities(e)) == {("user", "jdoe"), ("host", "web1"), ("ip", "10.0.0.1")}
    assert event_entities(_evt()) == []                       # nothing identifiable


def test_event_links():
    e = _evt(user_name="jdoe", host_name="web1", src_ip="10.0.0.1", dst_ip="8.8.8.8")
    links = set(event_links(e))
    assert ("user", "jdoe", "ip", "10.0.0.1") in links
    assert ("user", "jdoe", "host", "web1") in links
    assert ("host", "web1", "ip", "8.8.8.8") in links         # host -> destination ip
    assert event_links(_evt(user_name="jdoe")) == []          # needs a peer


def test_severity_weight_and_decay():
    assert severity_weight("CRITICAL") == SEVERITY_WEIGHT["critical"]
    assert severity_weight("nope") == 1.0                     # unknown -> 1
    assert decay(0, 7) == 1.0                                 # no age -> full weight
    assert abs(decay(7 * 86400, 7) - 0.5) < 1e-9             # one half-life -> 0.5
    assert decay(100 * 86400, 7) < 0.01                      # old -> ~0


def test_decayed_score_prefers_recent_and_severe():
    fresh_crit = decayed_score([("critical", 0)], 7)
    old_crit = decayed_score([("critical", 30 * 86400)], 7)
    fresh_low = decayed_score([("low", 0)], 7)
    assert fresh_crit > fresh_low > old_crit
    assert decayed_score([], 7) == 0.0


def test_weight_case_sql_is_constant_only():
    sql = weight_case_sql("level")
    assert sql.startswith("CASE lower(level)")
    for k, v in SEVERITY_WEIGHT.items():
        assert f"WHEN '{k}' THEN {v}" in sql
    assert "%" not in sql and ";" not in sql                  # no params / injection surface
