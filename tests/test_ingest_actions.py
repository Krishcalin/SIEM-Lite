# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Unit tests for ingest actions (drop / mask / route / sample). Pure, DB-free.

Every test here calls the evaluator directly with a hand-built event, which is the point
of the design: the decision that determines whether a row is stored, and with which
values, is a pure function of (rules, event).
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

import pytest
import yaml

from app import ingest_actions as ia
from app.models import NormalizedEvent
from app.normalize import dedup_hash


def _evt(**kw) -> NormalizedEvent:
    base = dict(event_time=datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc),
                vendor="microsoft", product="windows", log_type="security",
                action="success", user_name="jdoe.smith", host_name="WEB1",
                src_ip="10.1.2.3", dst_ip="10.9.9.9", dst_port=443,
                message="logon success for jdoe.smith from 10.1.2.3",
                raw={"TargetUserName": "jdoe.smith", "IpAddress": "10.1.2.3",
                     "EventID": 4624, "Msg": "logon success for jdoe.smith"})
    base.update(kw)
    if "raw" in kw:
        base["raw"] = kw["raw"]
    return NormalizedEvent(**base)


def _action(**kw) -> ia.IngestAction:
    doc = {"id": "ia-1", "action": "drop",
           "detection": {"sel": {"log_type": "security"}, "condition": "sel"}}
    doc.update(kw)
    return ia.action_from_dict(doc, "test.yml")


# ── drop ──────────────────────────────────────────────────────────────────────
def test_drop_removes_a_matching_event():
    d = ia.decide([_action()], _evt())
    assert d.dropped is True
    assert d.rule_id == "ia-1" and d.action == "drop"
    assert d.applied == ("ia-1",) and d.errors == ()


def test_a_rule_that_does_not_match_keeps_the_event():
    d = ia.decide([_action()], _evt(log_type="system"))
    assert d.dropped is False and d.applied == ()


def test_a_disabled_rule_never_runs():
    d = ia.decide([_action(enabled=False)], _evt())
    assert d.dropped is False and d.applied == ()


def test_an_empty_rule_set_keeps_everything():
    assert ia.decide([], _evt()) == ia.KEEP


# ── the match condition is the Sigma subset, not a second language ────────────
def test_the_condition_grammar_is_the_detection_engines():
    """Modifiers, boolean operators and `1 of` come from app.detection.engine."""
    a = _action(detection={
        "selection_user": {"user_name|contains": "jdoe"},
        "selection_net": {"src_ip|cidr": "10.0.0.0/8"},
        "filter": {"action": "failure"},
        "condition": "1 of selection_* and not filter"})
    assert ia.decide([a], _evt()).dropped is True
    assert ia.decide([a], _evt(action="failure")).dropped is False      # `not filter`
    assert ia.decide([a], _evt(user_name="alice", src_ip="8.8.8.8")).dropped is False


def test_a_condition_can_read_a_nested_raw_key():
    """`flatten_event` dot-joins nested raw, so a rule can key on a vendor field."""
    a = _action(detection={"sel": {"event.system.eventid": 4625}, "condition": "sel"})
    assert ia.decide([a], _evt(raw={"Event": {"System": {"EventID": 4625}}})).dropped
    assert not ia.decide([a], _evt(raw={"Event": {"System": {"EventID": 4624}}})).dropped


def test_the_logsource_gate_narrows_a_rule():
    a = _action(logsource={"vendor": "microsoft", "service": "security"})
    assert ia.decide([a], _evt()).dropped is True
    assert ia.decide([a], _evt(vendor="cisco")).dropped is False


def test_a_logsource_only_rule_reduces_to_its_logsource_gate():
    """No `detection:` at all — the rule is exactly its logsource gate."""
    act = ia.action_from_dict(
        {"id": "ia-ls", "action": "drop", "logsource": {"vendor": "cisco"}}, "t.yml")
    assert ia.decide([act], _evt(vendor="cisco")).dropped is True
    assert ia.decide([act], _evt(vendor="microsoft")).dropped is False


def test_a_rule_with_neither_logsource_nor_detection_is_rejected():
    """The drop-everything foot-gun is refused at load, not discovered in production."""
    problems = ia.validate({"id": "ia-x", "action": "drop"})
    assert problems and "matches every event" in problems[0]


# ── the CIM gate ──────────────────────────────────────────────────────────────
def test_a_datamodel_bound_rule_uses_the_cim_gate():
    a = _action(datamodels=["web"], detection={"sel": {"vendor|exists": True},
                                               "condition": "sel"})
    assert ia.decide([a], _evt(), tags={"web"}).dropped is True
    assert ia.decide([a], _evt(), tags={"dns"}).dropped is False


def test_an_unknown_datamodel_disables_the_rule_rather_than_widening_it():
    """A typo in `datamodels:` on a DROP rule must not fall through to match-all."""
    a = _action(datamodels=["webb"], detection={"sel": {"vendor|exists": True},
                                                "condition": "sel"})
    assert ia.decide([a], _evt(), tags={"web", "dns"}).dropped is False


# ── mask: named field ─────────────────────────────────────────────────────────
def test_mask_replaces_a_named_column():
    a = _action(action="mask", mask={"fields": ["user_name"]})
    e = _evt()
    d = ia.decide([a], e)
    assert d.dropped is False and d.applied == ("ia-1",)
    assert e.user_name == "***"


def test_mask_leaves_an_absent_column_alone():
    a = _action(action="mask", mask={"fields": ["rule_name"]})
    e = _evt(rule_name=None)
    ia.decide([a], e)
    assert e.rule_name is None          # no placeholder invented for a field never sent


def test_mask_scrubs_the_value_out_of_raw_and_the_sibling_columns():
    """A mask that only rewrites its own column leaves the value searchable in `raw`
    (jsonb, GIN-indexed) and in `message` (fed to tsvector separately)."""
    a = _action(action="mask", mask={"fields": ["user_name"]})
    e = _evt()
    ia.decide([a], e)
    assert "jdoe.smith" not in str(e.raw)
    assert "jdoe.smith" not in e.message
    assert e.raw["TargetUserName"] == "***"


def test_scrub_can_be_switched_off():
    a = _action(action="mask", mask={"fields": ["user_name"], "scrub": False})
    e = _evt()
    ia.decide([a], e)
    assert e.user_name == "***"
    assert e.raw["TargetUserName"] == "jdoe.smith"       # deliberately left behind


def test_scrub_raw_is_accepted_as_an_alias():
    spec = ia.action_from_dict(
        {"id": "x", "action": "mask", "logsource": {"vendor": "microsoft"},
         "mask": {"fields": ["user_name"], "scrub_raw": False}}, "t.yml").mask
    assert spec.scrub is False


def test_scrub_replaces_a_short_value_as_a_token_but_never_inside_a_word():
    """Substring-rewriting a short common value across a whole record would shred
    unrelated fields, so below 8 characters it is matched on TOKEN boundaries."""
    a = _action(action="mask", mask={"fields": ["severity"]})
    e = _evt(severity="high", raw={"sev": "high", "note": "highly unusual",
                                   "line": "risk high today"})
    ia.decide([a], e)
    assert e.raw["sev"] == "***"                 # exact -> replaced
    assert e.raw["note"] == "highly unusual"     # inside a longer word -> kept
    assert e.raw["line"] == "risk *** today"     # a whole token -> replaced


def test_a_short_username_really_is_removed_from_message_and_nested_raw():
    """The failure this file's own docstring calls the worst kind: the operator is
    told the mask applied while the identity is still there and still indexed.

    Most masking targets are UNDER 8 characters — `jdoe`, `admin`, `root` — and short
    values used to be skipped for anything but an exact match, so the shipped GDPR
    proxy rule hashed `user_name` and left the name sitting in `message` and in nested
    `raw` strings, both fed to the search index. The behaviour flipped on identifier
    length alone: `jdoe.smith` scrubbed correctly, `jdoe` did not.
    """
    a = _action(action="mask",
                mask={"fields": ["user_name"], "mode": "hash", "salt": "s"})
    e = _evt(user_name="jdoe",
             message="GET /hr/salaries.xlsx by jdoe from 10.1.2.3",
             raw={"user": "jdoe", "cs_username": "CORP\\jdoe",
                  "detail": {"cmd": "runas /user:jdoe whoami"},
                  "other": "jdoexyz is a different account"})
    ia.decide([a], e)

    assert e.user_name != "jdoe"
    assert "jdoe" not in e.message
    assert "jdoe" not in e.raw["user"]
    assert "jdoe" not in e.raw["cs_username"]          # after a backslash
    assert "jdoe" not in e.raw["detail"]["cmd"]        # nested, after a colon
    assert e.raw["other"] == "jdoexyz is a different account"   # a DIFFERENT account

    # and the full-text vector, which is fed from `message` separately from `raw`.
    # Searched for as a TOKEN: `jdoexyz` above must still be there, and it contains
    # those four characters.
    import re

    from app.normalize import tsv_text
    assert re.search(r"(?<![0-9A-Za-z_])jdoe(?![0-9A-Za-z_])", tsv_text(e)) is None


def test_a_replacement_containing_regex_syntax_is_written_literally():
    # the token path substitutes through `re`; a replacement holding `\1` or `\g<0>`
    # must not be read as a backreference
    a = _action(action="mask",
                mask={"fields": ["user_name"], "replacement": r"\1\g<0>"})
    e = _evt(user_name="root", message="sudo by root now", raw={})
    ia.decide([a], e)
    assert e.message == r"sudo by \1\g<0> now"


def test_scrub_rewrites_a_long_value_as_a_substring():
    a = _action(action="mask", mask={"fields": ["user_name"]})
    e = _evt(raw={"detail": "account jdoe.smith locked out"})
    ia.decide([a], e)
    assert e.raw["detail"] == "account *** locked out"


def test_scrub_never_rewrites_a_jsonb_key():
    """A key is the record's shape; rewriting one breaks every CIM term naming it."""
    a = _action(action="mask", mask={"fields": ["user_name"]})
    e = _evt(raw={"jdoe.smith": "is the key here", "u": "jdoe.smith"})
    ia.decide([a], e)
    assert "jdoe.smith" in e.raw          # the KEY survives
    assert e.raw["u"] == "***"            # the VALUE does not


# ── mask: typed columns (the INSERT casts these) ──────────────────────────────
def test_masking_an_ip_column_leaves_a_valid_inet_or_null():
    """`db._INSERT` binds `%(src_ip)s::inet` — a text placeholder there aborts the whole
    batch, turning a redaction rule into total data loss."""
    a = _action(action="mask", mask={"fields": ["src_ip"]})
    e = _evt()
    ia.decide([a], e)
    assert e.src_ip is None

    b = _action(action="mask", mask={"fields": ["src_ip"], "mode": "hash"})
    e2 = _evt()
    ia.decide([b], e2)
    assert ipaddress.ip_address(e2.src_ip) in ipaddress.ip_network("100.64.0.0/10")


def test_an_ip_replacement_that_parses_as_an_ip_is_honoured():
    a = _action(action="mask", mask={"fields": ["src_ip"], "replacement": "0.0.0.0"})
    e = _evt()
    ia.decide([a], e)
    assert e.src_ip == "0.0.0.0"


def test_masking_an_integer_column_leaves_an_int_or_null():
    a = _action(action="mask", mask={"fields": ["dst_port"]})
    e = _evt()
    ia.decide([a], e)
    assert e.dst_port is None

    b = _action(action="mask", mask={"fields": ["dst_port"], "replacement": "0"})
    e2 = _evt()
    ia.decide([b], e2)
    assert e2.dst_port == 0


def test_vendor_and_event_time_are_not_maskable():
    assert ia.validate({"id": "x", "action": "mask", "logsource": {"vendor": "a"},
                        "mask": {"fields": ["vendor"]}})
    assert ia.validate({"id": "x", "action": "mask", "logsource": {"vendor": "a"},
                        "mask": {"fields": ["event_time"]}})
    assert ia.validate({"id": "x", "action": "mask", "logsource": {"vendor": "a"},
                        "mask": {"fields": ["raw"]}})


# ── mask: raw keys and regex-within-a-field ───────────────────────────────────
def test_mask_rewrites_a_named_raw_key_including_a_nested_path():
    a = _action(action="mask",
                mask={"fields": [], "raw_keys": ["IpAddress", ["Event", "User"]]})
    e = _evt(raw={"IpAddress": "10.1.2.3", "Event": {"User": "svc-backup"}})
    ia.decide([a], e)
    assert e.raw["IpAddress"] == "***" and e.raw["Event"]["User"] == "***"


def test_masking_a_raw_key_the_source_never_sent_invents_nothing():
    a = _action(action="mask", mask={"raw_keys": ["NotPresent"]})
    e = _evt(raw={"a": 1})
    ia.decide([a], e)
    assert e.raw == {"a": 1}          # no placeholder column across every row


def test_a_pattern_redacts_within_a_field_and_within_raw():
    a = _action(action="mask", mask={"patterns": [
        {"field": "message", "regex": r"\b\d{3}-\d{2}-\d{4}\b", "replacement": "[SSN]"}]})
    e = _evt(message="ssn 123-45-6789 filed", raw={"body": "ssn 123-45-6789 filed"})
    ia.decide([a], e)
    assert e.message == "ssn [SSN] filed"
    assert e.raw["body"] == "ssn [SSN] filed"      # the column alone is not redaction


def test_a_pattern_can_target_a_raw_key_directly():
    a = _action(action="mask", mask={"patterns": [
        {"raw": "CommandLine", "regex": r"(?i)-password\s+\S+",
         "replacement": "-password ***"}]})
    e = _evt(raw={"CommandLine": "net use -password Hunter2 \\\\srv"})
    ia.decide([a], e)
    assert e.raw["CommandLine"] == "net use -password *** \\\\srv"


def test_an_invalid_regex_is_a_load_error_not_an_ingest_error():
    problems = ia.validate({"id": "x", "action": "mask", "logsource": {"vendor": "a"},
                            "mask": {"patterns": [{"field": "message", "regex": "([a-"}]}})
    assert problems and "not a valid regex" in problems[0]


def test_a_catastrophically_backtracking_pattern_is_rejected_at_load():
    problems = ia.validate({"id": "x", "action": "mask", "logsource": {"vendor": "a"},
                            "mask": {"patterns": [{"field": "message", "regex": "(a+)+$"}]}})
    assert problems and "backtracks catastrophically" in problems[0]
    # ...and an ordinary pattern with a group is NOT rejected
    assert ia.validate({"id": "x", "action": "mask", "logsource": {"vendor": "a"},
                        "mask": {"patterns": [
                            {"field": "message", "regex": r"(\d{3})-(\d{2})-\d{4}"}]}}) == []


# ── mask: hashing ─────────────────────────────────────────────────────────────
def test_hash_mode_is_deterministic_and_keeps_values_joinable():
    a = _action(action="mask", mask={"fields": ["user_name"], "mode": "hash"})
    e1, e2, e3 = _evt(), _evt(), _evt(user_name="alice")
    ia.decide([a], e1); ia.decide([a], e2); ia.decide([a], e3)
    assert e1.user_name == e2.user_name          # same input -> same pseudonym
    assert e1.user_name != e3.user_name          # different input -> different
    assert "jdoe.smith" not in e1.user_name


def test_the_salt_changes_the_pseudonym():
    plain = _evt(); salted = _evt()
    ia.decide([_action(action="mask", mask={"fields": ["user_name"], "mode": "hash"})], plain)
    ia.decide([_action(action="mask", mask={"fields": ["user_name"], "mode": "hash",
                                            "salt": "pepper"})], salted)
    assert plain.user_name != salted.user_name


# ── mask vs dedup_hash — the documented decision ──────────────────────────────
def test_masking_changes_dedup_identity_and_does_so_deterministically():
    """The stored identity is derived from the MASKED event (see the module docstring):
    hashing the pre-mask event would make an indexed column a side channel for the value
    the mask exists to remove. The cost is that a rule change changes identity — asserted
    here so it is a decision, not a surprise."""
    a = _action(action="mask", mask={"fields": ["user_name"]})
    before = dedup_hash(_evt())
    e1, e2 = _evt(), _evt()
    ia.decide([a], e1)
    ia.decide([a], e2)
    assert dedup_hash(e1) != before              # a rule change re-inserts, by design
    assert dedup_hash(e1) == dedup_hash(e2)      # ...but masking is idempotent for identity


def test_two_events_differing_only_in_the_masked_value_become_one_identity():
    """The other half of the same argument: after masking, the secret cannot be
    recovered from the hash because the hash no longer depends on it."""
    a = _action(action="mask", mask={"fields": ["user_name"],
                                     "raw_keys": ["TargetUserName"]})
    e1 = _evt(user_name="alice", message="x", raw={"TargetUserName": "alice"})
    e2 = _evt(user_name="bob", message="x", raw={"TargetUserName": "bob"})
    ia.decide([a], e1); ia.decide([a], e2)
    assert dedup_hash(e1) == dedup_hash(e2)


# ── route ─────────────────────────────────────────────────────────────────────
def test_route_rewrites_attribution_and_stamps_the_index():
    a = _action(action="route",
                route={"vendor": "acme", "log_type": "traffic", "index": "noisy"})
    e = _evt()
    d = ia.decide([a], e)
    assert d.dropped is False
    assert (e.vendor, e.log_type) == ("acme", "traffic")
    assert e.product == "windows"                 # untouched: route sets what it names
    assert e.raw["_index"] == "noisy"


def test_route_cannot_rewrite_an_arbitrary_column():
    problems = ia.validate({"id": "x", "action": "route", "logsource": {"vendor": "a"},
                            "route": {"user_name": "nobody"}})
    assert problems and "route cannot rewrite user_name" in problems[0]


def test_an_empty_route_is_rejected():
    assert ia.validate({"id": "x", "action": "route", "logsource": {"vendor": "a"},
                        "route": {}})


# ── sample ────────────────────────────────────────────────────────────────────
def _corpus(n: int) -> list[NormalizedEvent]:
    return [_evt(src_ip=f"10.0.{i // 256}.{i % 256}", message=f"event {i}",
                 raw={"i": i}) for i in range(n)]


def test_sampling_is_deterministic_for_the_same_event():
    a = _action(action="sample", sample={"rate": 10})
    first = [ia.decide([a], e).dropped for e in _corpus(200)]
    second = [ia.decide([a], e).dropped for e in _corpus(200)]
    assert first == second                        # no random, no clock


def test_sampling_keeps_roughly_one_in_n():
    a = _action(action="sample", sample={"rate": 10})
    kept = sum(1 for e in _corpus(2000) if not ia.decide([a], e).dropped)
    assert 140 < kept < 260                       # ~200 of 2000; hash-uniform, not exact


def test_a_rate_of_one_keeps_everything():
    a = _action(action="sample", sample={"rate": 1})
    assert all(not ia.decide([a], e).dropped for e in _corpus(50))


def test_percent_sampling_uses_basis_points():
    a = _action(action="sample", sample={"percent": 25})
    kept = sum(1 for e in _corpus(2000) if not ia.decide([a], e).dropped)
    assert 400 < kept < 600


def test_a_sample_key_keeps_an_entity_whole():
    """Sampling by identity would scatter one host across kept and dropped, which makes
    'show me everything this host did' a lie. `key:` buckets the entity instead."""
    a = _action(action="sample", sample={"rate": 4, "key": ["host_name"]})
    verdicts = {}
    for i in range(200):
        host = f"host{i % 20}"
        d = ia.decide([a], _evt(host_name=host, message=f"m{i}", raw={"i": i}))
        verdicts.setdefault(host, set()).add(d.dropped)
    assert all(len(v) == 1 for v in verdicts.values())
    assert {True, False} == {next(iter(v)) for v in verdicts.values()}   # both outcomes


def test_a_rejected_sample_reports_itself_as_the_terminal_rule():
    a = _action(action="sample", sample={"rate": 1000000})   # keeps ~nothing
    d = ia.decide([a], _evt())
    assert d.dropped is True and d.action == "sample" and d.rule_id == "ia-1"


def test_sample_parameters_are_validated():
    ls = {"vendor": "a"}
    assert ia.validate({"id": "x", "action": "sample", "logsource": ls,
                        "sample": {"rate": 0}})
    assert ia.validate({"id": "x", "action": "sample", "logsource": ls,
                        "sample": {"percent": 0}})
    assert ia.validate({"id": "x", "action": "sample", "logsource": ls,
                        "sample": {"percent": 101}})
    assert ia.validate({"id": "x", "action": "sample", "logsource": ls,
                        "sample": {"rate": 2, "percent": 50}})
    assert ia.validate({"id": "x", "action": "sample", "logsource": ls, "sample": {}})


# ── ordering and composition ──────────────────────────────────────────────────
def test_rules_run_in_order_and_a_drop_is_terminal():
    mask = _action(id="ia-mask", action="mask", order=1, mask={"fields": ["user_name"]})
    drop = _action(id="ia-drop", action="drop", order=2)
    late = _action(id="ia-late", action="route", order=3, route={"vendor": "never"})
    e = _evt()
    d = ia.decide(sorted([late, drop, mask], key=ia.sort_key), e)
    assert d.dropped is True and d.rule_id == "ia-drop"
    assert d.applied == ("ia-mask", "ia-drop")    # the route past the drop never ran
    assert e.vendor == "microsoft"


def test_masks_compose():
    a = _action(id="ia-a", action="mask", order=1, mask={"fields": ["user_name"]})
    b = _action(id="ia-b", action="mask", order=2, mask={"fields": ["host_name"]})
    e = _evt()
    d = ia.decide([a, b], e)
    assert d.applied == ("ia-a", "ia-b")
    assert e.user_name == "***" and e.host_name == "***"


def test_a_later_rule_sees_the_masked_event():
    """Masking must be observable to what follows, or a drop could fire on a secret the
    row no longer carries."""
    mask = _action(id="ia-mask", action="mask", order=1, mask={"fields": ["user_name"]})
    drop = _action(id="ia-drop", action="drop", order=2,
                   detection={"sel": {"user_name|contains": "jdoe"}, "condition": "sel"})
    d = ia.decide([mask, drop], _evt())
    assert d.dropped is False and d.applied == ("ia-mask",)


def test_provenance_is_stamped_on_a_rewritten_event():
    a = _action(id="ia-a", action="mask", order=1, mask={"fields": ["user_name"]})
    b = _action(id="ia-b", action="route", order=2, route={"log_type": "audit"})
    e = _evt()
    ia.decide([a, b], e)
    assert e.raw["_ingest_actions"] == ["ia-a", "ia-b"]


def test_the_stamp_can_be_switched_off_and_is_absent_when_nothing_changed():
    a = _action(action="mask", mask={"fields": ["user_name"]}, stamp=False)
    e = _evt()
    ia.decide([a], e)
    assert "_ingest_actions" not in e.raw

    b = _action(action="route", route={"vendor": "microsoft"})   # already that value
    e2 = _evt()
    ia.decide([b], e2)
    assert "_ingest_actions" not in e2.raw


# ── failure policy: fail OPEN ─────────────────────────────────────────────────
class _Boom:
    """A rule whose match blows up — stands in for any defect reaching the ingest path."""
    datamodels: list = []
    detection: dict = {}

    @property
    def logsource(self):
        raise RuntimeError("boom")


def test_a_broken_rule_fails_open_and_the_event_survives():
    """`streaming.IngestQueue._flush` discards a whole buffered group when a write
    raises, so an exception here is silent permanent loss of every syslog event."""
    boom = ia.IngestAction(id="ia-boom", action="drop", rule=_Boom())
    good = _action(id="ia-good", action="mask", mask={"fields": ["user_name"]})
    e = _evt()
    d = ia.decide([boom, good], e)
    assert d.dropped is False
    assert d.errors == ("ia-boom",)
    assert d.applied == ("ia-good",)              # the rest of the set still ran
    assert e.user_name == "***"


def test_the_index_never_raises_even_if_the_evaluator_does(monkeypatch):
    def explode(*_a, **_k):
        raise RuntimeError("nope")
    monkeypatch.setattr(ia, "decide", explode)
    index = ia.ActionIndex([_action()])
    assert index.apply(_evt()) == ia.KEEP


# ── loading, validation and the audit counters ────────────────────────────────
_YAML = """
id: ia-drop-noise
title: Drop DNS noise
order: 5
action: drop
logsource: {vendor: microsoft}
detection:
  sel: {log_type: security}
  condition: sel
---
id: ia-mask-user
order: 1
action: mask
logsource: {vendor: microsoft}
mask:
  fields: [user_name]
---
id: ia-broken
action: teleport
logsource: {vendor: microsoft}
---
not_an_action: true
"""


def test_loading_a_directory_sorts_by_order_and_reports_bad_documents(tmp_path):
    (tmp_path / "pack.yml").write_text(_YAML, encoding="utf-8")
    actions, errors = ia.load_actions(tmp_path)
    assert [a.id for a in actions] == ["ia-mask-user", "ia-drop-noise"]   # order 1, 5
    assert actions[0].source == "pack.yml"
    # BOTH bad documents are reported: the unknown verb, and the one with no `action:`
    # key at all. The second used to be skipped in silence, so `actions:` instead of
    # `action:` — or any other typo in that one key — made a rule vanish while
    # /health showed zero load_errors, indistinguishable from "no rules configured".
    assert len(errors) == 2
    assert any("teleport" in e for e in errors)
    assert any("no `action:` key" in e for e in errors)


def test_a_document_that_defines_no_rule_names_the_keys_it_did_have(tmp_path):
    (tmp_path / "typo.yml").write_text(
        "id: ia-x\nactions: mask\nlogsource: {vendor: a}\n", encoding="utf-8")
    actions, errors = ia.load_actions(tmp_path)
    assert actions == [] and len(errors) == 1
    assert "actions" in errors[0] and "no `action:` key" in errors[0]


def test_loading_a_single_file_and_a_missing_path(tmp_path):
    f = tmp_path / "one.yaml"
    f.write_text(yaml.safe_dump({"id": "ia-1", "action": "drop",
                                 "logsource": {"vendor": "a"}}), encoding="utf-8")
    actions, errors = ia.load_actions(f)
    assert len(actions) == 1 and errors == []

    # A CONFIGURED path that does not exist is an ERROR, not an empty load. The setting
    # defaults to the relative "ingest_actions", resolved against the process CWD, so
    # a launcher with a different WorkingDirectory silently ran no rules at all while
    # every check the documentation prescribes still passed.
    actions, errors = ia.load_actions(tmp_path / "nope")
    assert actions == [] and len(errors) == 1
    assert "does not exist" in errors[0]

    # ...while a directory that exists and is genuinely empty stays clean
    (tmp_path / "empty").mkdir()
    assert ia.load_actions(tmp_path / "empty") == ([], [])


def test_unparseable_yaml_costs_that_file_only(tmp_path):
    (tmp_path / "a.yml").write_text("id: ia-ok\naction: drop\nlogsource: {vendor: a}\n",
                                    encoding="utf-8")
    (tmp_path / "b.yml").write_text("{{{ not yaml", encoding="utf-8")
    actions, errors = ia.load_actions(tmp_path)
    assert [a.id for a in actions] == ["ia-ok"] and len(errors) == 1


def test_validate_accepts_a_good_rule_and_names_the_problem_in_a_bad_one():
    assert ia.validate({"id": "x", "action": "drop", "logsource": {"vendor": "a"}}) == []
    assert "unknown action" in ia.validate(
        {"id": "x", "action": "nope", "logsource": {"vendor": "a"}})[0]
    assert ia.validate("not a mapping")


def test_the_index_counts_what_it_did():
    index = ia.ActionIndex([_action(id="ia-mask", action="mask", order=1,
                                    mask={"fields": ["user_name"]}),
                            _action(id="ia-drop", action="drop", order=2,
                                    detection={"sel": {"host_name": "WEB1"},
                                               "condition": "sel"})])
    index.apply(_evt())                       # masked, then dropped
    index.apply(_evt(host_name="WEB2"))       # masked, kept
    s = index.summary()
    assert s["rules"] == 2 and s["enabled"] == 2
    assert s["dropped"] == 1 and s["errors"] == 0
    assert s["by_rule"]["ia-mask"]["matched"] == 2
    assert s["by_rule"]["ia-drop"]["dropped"] == 1
    assert s["changed"] == 1                  # the kept event was rewritten


def test_the_index_counts_a_failing_rule_as_an_error():
    index = ia.ActionIndex([ia.IngestAction(id="ia-boom", action="drop", rule=_Boom())])
    index.apply(_evt())
    assert index.summary()["errors"] == 1


def test_an_index_with_no_rules_short_circuits():
    assert ia.ActionIndex().apply(_evt()) == ia.KEEP


def test_the_runtime_singleton_reloads_from_disk(tmp_path):
    previous = ia.get_index()
    try:
        (tmp_path / "p.yml").write_text(
            "id: ia-r\naction: drop\nlogsource: {vendor: microsoft}\n", encoding="utf-8")
        index = ia.reload_index(tmp_path)
        assert len(index) == 1 and ia.get_index() is index
        assert ia.apply(_evt()).dropped is True
        assert ia.stats()["dropped"] == 1
    finally:
        ia.set_index(previous)


# ── pure helpers ──────────────────────────────────────────────────────────────
def test_raw_path_follows_the_models_yaml_segment_convention():
    assert ia.raw_path("k") == ("k",)
    assert ia.raw_path(["a", "b"]) == ("a", "b")


def test_raw_set_never_invents_structure():
    """The helper's own contract, pinned independently of `apply_mask`'s pre-check:
    masking a key a source never sent must not add a placeholder to every row."""
    raw = {"a": {"b": "v"}}
    assert ia.raw_set(raw, ("a", "b"), "***") is True
    assert ia.raw_set(raw, ("nope",), "x") is False            # absent top-level key
    assert ia.raw_set(raw, ("a", "missing"), "x") is False     # absent nested key
    assert ia.raw_set(raw, ("a", "b", "deeper"), "x") is False  # parent is not a dict
    assert ia.raw_set(raw, (), "x") is False                   # empty path
    assert raw == {"a": {"b": "***"}}


def test_raw_get_walks_objects_only():
    raw = {"a": {"b": "v"}, "list": [{"c": "x"}], "id.orig_h": "10.0.0.1"}
    assert ia.raw_get(raw, ("a", "b")) == "v"
    assert ia.raw_get(raw, ("list", "0")) is None      # never an array index
    assert ia.raw_get(raw, ("id.orig_h",)) == "10.0.0.1"   # byte-exact, never dot-split


def test_walk_strings_is_depth_bounded():
    deep: dict = {}
    cur = deep
    for _ in range(40):
        cur["n"] = {}
        cur = cur["n"]
    cur["leaf"] = "secret"
    ia.walk_strings(deep, lambda s: "***")
    assert cur["leaf"] == "secret"                      # past the bound, left alone


def test_pseudo_ip_is_stable_and_inside_the_shared_address_space():
    a, b = ia.pseudo_ip("10.1.2.3"), ia.pseudo_ip("10.1.2.3")
    assert a == b
    assert ipaddress.ip_address(a) in ipaddress.ip_network("100.64.0.0/10")
    assert ia.pseudo_ip("10.1.2.3", "salt") != a


@pytest.mark.parametrize("action", ia.ACTIONS)
def test_every_advertised_action_loads(action):
    doc = {"id": "x", "action": action, "logsource": {"vendor": "a"},
           "mask": {"fields": ["user_name"]}, "route": {"vendor": "b"},
           "sample": {"rate": 2}}
    assert ia.validate(doc) == []
