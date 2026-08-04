# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Content packs: format, hostile input, planning, and the two merges.

DB-free by construction — the module's only database contact is :class:`DbWriter` and
:func:`snapshot`, and every test here goes through :class:`RecordingWriter` instead.

A content pack is untrusted input from the internet, so the tests are written the way the
vault's are: each one fails for ONE named reason, stated in its docstring or a comment, and
the security tests assert the REFUSAL rather than the happy path. A validator that accepts
everything passes every round-trip test ever written, which is why roughly half of this
file is hostile input.
"""
from __future__ import annotations

from dataclasses import replace

import pytest
import yaml

from app import compliance as compliance_module
from app import contentpack as cp
from app.cim import match as cim_match
from app.cim import registry as cim_registry
from app.cim.spec import CimClause, CimField, CimModel, CimRegistry, CimSource, CimTerm
from app.models import NormalizedEvent

# The CIM vocabulary the format tests run against. Hand-built so the tests do not move when
# `app/cim/models.yaml` does (that file is edited by the WIRE phase and by every source
# onboarding); one test at the bottom checks the real registry separately.
MODELS = ("network", "authentication")
FRAMEWORKS = ("NIST 800-53", "CIS v8")

RULE_YAML = """\
id: acme-admin-login
title: ACME admin login
level: high
logsource: {vendor: acme}
detection:
  selection:
    user_name: admin
  condition: selection
tags: [attack.t1078]
"""

PACK_YAML = """\
pack: 1
name: acme-firewall
version: 1.2.0
description: Onboard the ACME firewall end to end.
author: Krishnendu De
license: MIT
labels: [firewall, acme]
requires: {logocean: ">=1.0"}
parsers:
  - id: acme-fw
    title: ACME firewall field map
    match_key: product
    match_value: acme-fw
    vendor: acme
    product: firewall
    field_map: {srcip: src_ip, dstip: dst_ip, act: action}
rules:
  - id: acme-admin-login
    title: ACME admin login
    yaml: |
%s
cim:
  - model: network
    membership:
      - {vendor: [acme], log_type: [widgetflow]}
compliance:
  - technique: T1110
    framework: NIST 800-53
    controls:
      - {id: AC-7, name: Unsuccessful Logon Attempts}
""" % "\n".join("      " + line for line in RULE_YAML.splitlines())


def load(text: str = PACK_YAML) -> cp.Pack:
    return cp.parse(text, known_models=MODELS, known_frameworks=FRAMEWORKS)


def refuse(text: str) -> str:
    """Parse `text` expecting a PackError, and return the message."""
    with pytest.raises(cp.PackError) as exc:
        load(text)
    return str(exc.value)


def minimal(**sections: str) -> str:
    body = "".join(sections.values())
    return "name: p\nversion: 1.0.0\n" + (body or
                                          "parsers:\n  - {id: a, title: A, match_key: k, "
                                          "match_value: v, vendor: acme}\n")


def rule_pack(rule_body: str, rule_id: str = "r1") -> str:
    indented = "".join("      " + line + "\n" for line in rule_body.strip().splitlines())
    return f"name: p\nversion: 1.0.0\nrules:\n  - id: {rule_id}\n    yaml: |\n{indented}"


BASIC_RULE = """
id: r1
title: R1
level: high
detection:
  selection: {user_name: admin}
  condition: selection
"""


# ── the shape of a pack ───────────────────────────────────────────────────────
def test_parse_reads_every_section():
    pack = load()
    assert pack.name == "acme-firewall"
    assert pack.version == "1.2.0"
    assert pack.key == "acme-firewall@1.2.0"
    assert pack.counts() == {"parsers": 1, "rules": 1, "cim": 1, "compliance": 1}
    assert pack.labels == ("firewall", "acme")
    assert pack.requires_dict == {"logocean": ">=1.0"}


def test_parse_keeps_a_rule_body_verbatim():
    # The reason rules travel as TEXT and not as a re-emitted mapping: a pack must be
    # diffable against the rule it was cut from. Re-serializing would drop the comments
    # and reorder the keys.
    assert load().rules[0].yaml_text == RULE_YAML


def test_a_parser_field_map_keeps_document_order():
    # Mutation: `tuple(sorted(pairs))` in `_parser_entry` — order is data the author chose.
    assert load().parsers[0].field_map == (("srcip", "src_ip"), ("dstip", "dst_ip"),
                                           ("act", "action"))


def test_dumps_then_parse_round_trips_the_whole_pack():
    pack = load()
    assert cp.parse(cp.dumps(pack), known_models=MODELS, known_frameworks=FRAMEWORKS) == pack


def test_dumps_writes_a_rule_as_a_readable_literal_block():
    """A rule emitted as one quoted line with \\n escapes is unreviewable, and an
    unreviewable pack is one nobody reads before importing."""
    text = cp.dumps(load())
    assert "yaml: |" in text
    assert "\\n" not in text


def test_dumps_omits_empty_sections():
    # Mutation: emit every key unconditionally — the export then reads like a form, not a
    # document, and every pack carries four empty lists.
    text = cp.dumps(load(minimal()))
    assert "rules:" not in text and "cim:" not in text and "compliance:" not in text


def test_parse_accepts_the_same_document_as_json():
    """JSON is a pack's other on-the-wire shape (an API POST body); `yaml.safe_load` reads
    it, so nothing else in the format may assume YAML syntax."""
    import json
    pack = load()
    assert cp.parse(json.dumps(cp.to_dict(pack)), known_models=MODELS,
                    known_frameworks=FRAMEWORKS) == pack


def test_a_rule_may_be_authored_inline_instead_of_as_text():
    text = ("name: p\nversion: 1.0.0\nrules:\n  - id: r1\n    title: R1\n"
            "    rule: {id: r1, title: R1, detection: {selection: {user_name: admin}, "
            "condition: selection}}\n")
    pack = load(text)
    assert pack.rules[0].doc["detection"]["condition"] == "selection"


def test_a_rule_may_not_be_given_twice_over():
    assert "not both" in refuse(
        "name: p\nversion: 1.0.0\nrules:\n  - id: r1\n    title: R1\n"
        "    yaml: \"id: r1\\ntitle: R1\\ndetection: {selection: {a: b}, condition: selection}\"\n"
        "    rule: {id: r1, title: R1, detection: {selection: {a: b}, condition: selection}}\n")


def test_an_empty_pack_is_refused():
    """A pack that installs nothing is always a mistake — usually a mis-typed section key
    that `_reject_unknown` would have caught if the author had spelled it close enough."""
    assert "at least one" in refuse("name: p\nversion: 1.0.0\n")


# ── hostile input ─────────────────────────────────────────────────────────────
def test_yaml_aliases_are_refused():
    """The billion-laughs expansion bomb. Removed rather than bounded: a pack has no
    legitimate use for an alias, so there is nothing to trade off.

    Mutation: drop `_PackLoader.compose_node` — this document then parses fine, and the
    nine-fold version of it exhausts memory before any limit in this module is consulted.
    """
    bomb = ("name: p\nversion: 1.0.0\nlabels: &a [x, x, x]\nparsers:\n"
            "  - {id: a, title: A, match_key: k, match_value: v, vendor: acme}\n"
            "  - {id: b, title: B, match_key: k, match_value: v, vendor: *a}\n")
    assert "aliases are not allowed" in refuse(bomb)


def test_duplicate_mapping_keys_are_refused():
    """Two `rules:` keys let a pack show a reviewer one list and install another — PyYAML
    keeps the last and says nothing. Same defence `app/cim/registry.py` applies."""
    assert "duplicate key" in refuse(minimal() + "parsers: []\n")


def test_an_unknown_top_level_key_is_refused_with_a_hint():
    msg = refuse(minimal() + "tags: [firewall]\n")
    assert "unknown key 'tags'" in msg and "labels" in msg and "cim_models" in msg


def test_a_near_miss_key_gets_a_did_you_mean():
    assert "did you mean 'compliance'?" in refuse(minimal() + "complaince: []\n")


def test_an_unknown_key_inside_a_section_item_is_refused():
    # A key that imports as a no-op is how content silently does nothing.
    assert "unknown key 'colour'" in refuse(
        "name: p\nversion: 1.0.0\nparsers:\n"
        "  - {id: a, title: A, match_key: k, match_value: v, colour: red}\n")


def test_a_document_over_the_size_cap_is_refused_before_it_is_parsed():
    with pytest.raises(cp.PackError) as exc:
        cp.parse("#" * (cp.MAX_DOCUMENT_BYTES + 1), known_models=MODELS)
    assert "over the" in str(exc.value)


def test_a_document_nested_past_the_depth_cap_is_refused():
    """Canonicalization and `_depth` both recurse; an attacker-chosen nesting depth is a
    stack overflow, which is a crash, not a validation error."""
    deep = {"name": "p", "version": "1.0.0", "parsers": []}
    node: list = deep["parsers"]
    for _ in range(cp.MAX_DEPTH + 4):
        nxt: list = []
        node.append(nxt)
        node = nxt
    with pytest.raises(cp.PackError) as exc:
        cp.pack_from_dict(deep, known_models=MODELS)
    assert "nests deeper" in str(exc.value)


def test_a_section_with_too_many_items_is_refused():
    items = "".join(f"  - {{id: p{i}, title: T, match_key: k, match_value: v, vendor: a}}\n"
                    for i in range(cp.MAX_SECTION_ITEMS + 1))
    assert "limit" in refuse("name: p\nversion: 1.0.0\nparsers:\n" + items)


@pytest.mark.parametrize("bad", ["Not A Slug", "../etc/passwd", "acme/fw", "-lead"])
def test_a_pack_name_outside_the_slug_charset_is_refused(bad):
    """The name is a primary key and a filename in every export path — a traversal
    sequence or a space in it is a bug waiting for a place to happen."""
    assert "lower-case" in refuse(f"name: {bad!r}\nversion: 1.0.0\nparsers: []\n")


@pytest.mark.parametrize("bad", ["banana", "1.2.3.4.5", ""])
def test_a_version_that_is_not_semver_ish_is_refused(bad):
    assert "version" in refuse(f"name: p\nversion: {bad!r}\nparsers: []\n")


def test_yaml_booleans_where_text_was_meant_are_refused_not_coerced():
    """YAML 1.1 turns bare `on`/`no` into booleans. `vendor: on` stored as `True` is a
    parser that matches nothing, discovered weeks later. Same stance as
    `app/cim/registry.py:_values`."""
    assert "quote it" in refuse(
        "name: p\nversion: 1.0.0\nparsers:\n"
        "  - {id: a, title: A, match_key: k, match_value: v, vendor: on}\n")


def test_a_duplicate_object_id_inside_one_pack_is_refused():
    # Two parsers with one id: the second silently wins the upsert and the first is
    # content the author believes shipped.
    assert "duplicate parser id" in refuse(
        "name: p\nversion: 1.0.0\nparsers:\n"
        "  - {id: a, title: A, match_key: k, match_value: v, vendor: x}\n"
        "  - {id: a, title: B, match_key: k, match_value: w, vendor: y}\n")


# ── parsers section ───────────────────────────────────────────────────────────
def test_a_field_map_may_only_target_a_fillable_column():
    """`event_time` and `raw` are excluded from `custom_parser._ALLOWED` so a definition
    cannot corrupt provenance or partitioning; a pack must not be a way around that."""
    msg = refuse("name: p\nversion: 1.0.0\nparsers:\n"
                 "  - {id: a, title: A, match_key: k, match_value: v, "
                 "field_map: {x: event_time}}\n")
    assert "not a fillable column" in msg


def test_a_parser_that_would_change_nothing_is_refused():
    # No field_map, no vendor, no product: it matches events and does nothing to them.
    assert "changes nothing" in refuse(
        "name: p\nversion: 1.0.0\nparsers:\n  - {id: a, title: A, match_key: k, match_value: v}\n")


def test_the_parser_column_whitelist_tracks_custom_parser():
    """`PARSER_COLUMNS` is restated rather than imported (this module stays DB-free), so
    this test is the only thing keeping the two from drifting apart. If `custom_parser`
    gains a fillable column, a pack must be able to target it."""
    pytest.importorskip("psycopg")
    from app import custom_parser
    assert cp.PARSER_COLUMNS == custom_parser._ALLOWED


# ── rules section ─────────────────────────────────────────────────────────────
def test_a_valid_rule_is_accepted_and_keeps_its_id():
    pack = load(rule_pack(BASIC_RULE))
    assert pack.rules[0].id == "r1" and pack.rules[0].enabled is True


def test_a_condition_naming_an_undefined_selection_is_refused():
    """`engine._Cond` reads an unknown token as `False` (`self.sel.get(t, False)`), so a
    typo'd selection name loads, runs, and never fires — the single most expensive silent
    failure a pack can ship."""
    msg = refuse(rule_pack(BASIC_RULE.replace("condition: selection",
                                              "condition: selektion")))
    assert "undefined selection 'selektion'" in msg


def test_a_quantifier_pattern_that_matches_no_selection_is_refused():
    assert "matches no selection" in refuse(rule_pack("""
id: r1
title: R1
detection:
  selection: {user_name: admin}
  condition: 1 of nomatch_*
"""))


def test_a_real_quantifier_condition_is_accepted():
    # Mutation guard for the test above: `1 of sel_*` must NOT be refused.
    pack = load(rule_pack("""
id: r1
title: R1
detection:
  sel_a: {user_name: admin}
  sel_b: {host_name: dc1}
  condition: 1 of sel_*
"""))
    assert pack.rules[0].id == "r1"


@pytest.mark.parametrize("condition", ["selection and not filter", "all of them",
                                       "1 of them", "(selection or filter) and not filter"])
def test_the_condition_grammar_is_not_mistaken_for_selection_names(condition):
    """Mutation: drop `all` from `_CONDITION_WORDS` — `all of them` is then reported as an
    undefined selection and every rule using it is refused."""
    assert load(rule_pack(f"""
id: r1
title: R1
detection:
  selection: {{user_name: admin}}
  filter: {{host_name: dc1}}
  condition: {condition}
""")).rules[0].id == "r1"


def test_a_rule_with_no_detection_block_is_refused():
    assert "no document with a `detection` block" in refuse(
        rule_pack("id: r1\ntitle: R1\nlevel: high\n"))


def test_a_rule_with_an_unknown_level_is_refused():
    assert "level must be one of" in refuse(
        rule_pack(BASIC_RULE.replace("level: high", "level: catastrophic")))


def test_a_correlation_rule_cannot_travel_in_a_pack():
    """`load_correlation_rules` reads `rules/` FILES; a correlation rule stored as a
    `custom_rules` row is loaded by nothing and fires never. Shipping one in a pack would
    be a coverage claim with no coverage behind it."""
    assert "files only" in refuse(rule_pack("""
id: r1
title: R1
correlation: {match: {}, group_by: [src_ip]}
detection:
  selection: {user_name: admin}
  condition: selection
"""))


def test_a_rule_bound_to_an_unknown_data_model_is_refused():
    """`engine._gate` DISABLES a rule whose `datamodels:` names no model — deliberately,
    so a typo cannot fall through to match-all. A disabled rule is invisible."""
    assert "unknown CIM data model" in refuse(rule_pack("""
id: r1
title: R1
datamodels: [netwrok]
detection:
  selection: {user_name: admin}
  condition: selection
"""))


def test_a_rule_bound_to_a_known_data_model_is_accepted():
    assert load(rule_pack("""
id: r1
title: R1
datamodels: [network]
detection:
  selection: {user_name: admin}
  condition: selection
""")).rules[0].id == "r1"


def test_a_rule_that_does_not_compile_is_refused():
    # `logsource` must be a mapping; `rule_from_dict` accepts junk, `_logsource_matches`
    # then explodes per event, inside the ingest transaction.
    assert "does not compile" in refuse(rule_pack("""
id: r1
title: R1
detection:
  selection: {user_name: admin}
  condition: selection
tags: 5
"""))


def test_rule_problems_is_callable_on_a_bare_dict():
    """The console needs the same check at authoring time, without building a pack."""
    assert cp.rule_problems({"id": "x", "title": "T",
                             "detection": {"sel": {"a": "b"}, "condition": "sel"}}) == []
    assert cp.rule_problems("not a mapping") == ["a rule must be a mapping"]


# ── ReDoS guard ───────────────────────────────────────────────────────────────
SAFE_PATTERNS = [
    # Copied from shipped rules (`rules/linux_reverse_shell.yml`,
    # `rules/web_command_injection.yml`, `rules/web_sql_injection.yml`) — the guard is
    # worthless if it cannot pass the content we already run.
    r"(?i)(perl|python[23]?|ruby|php)\b.{0,60}(socket|/dev/tcp|sh -i|exec)",
    r"(?i)[;|`]\s*(id|whoami|uname|ifconfig|cat|nc|ncat|bash|sh|curl|wget|ping)\b",
    r"(?i)('|%27|\")\s*(or|and)\s*('|%27|\")?\d+\s*=\s*\d+",
    r"(?:\d{1,3}\.){3}\d{1,3}",
    r"https?://[^\s]+",
    r"[0-9a-f]{32}",
    r"^\\\\[^\\]+\\[A-Za-z]\$",
    r"(a+){2}",                      # bounded outer repeat: linear, must not be flagged
]

DANGEROUS_PATTERNS = [
    r"(a+)+$",                       # the textbook exponential
    r"(a*)*b",
    r"(\d+\s*)*x",
    r"([a-z]+){2,}",                 # `{n,}` is unbounded
    r"(.*)*",
    r"(a|ab)*c",                     # overlapping alternatives
    r"(a|a)+",
    r"(\w|\d)+",                     # `\d` is a subset of `\w`
    "x{%d}" % (cp.MAX_REPEAT + 1),
]


@pytest.mark.parametrize("pattern", SAFE_PATTERNS)
def test_the_redos_guard_passes_patterns_we_already_ship(pattern):
    """A guard nobody can satisfy gets disabled. These are real production regexes."""
    assert cp.redos_risk(pattern) is None, pattern


@pytest.mark.parametrize("pattern", DANGEROUS_PATTERNS)
def test_the_redos_guard_catches_catastrophic_backtracking(pattern):
    """Mutation: return None from `redos_risk` — every one of these then imports and runs
    against every event, and `(a+)+$` against 30 non-matching characters is minutes of CPU
    inside the ingest transaction."""
    assert cp.redos_risk(pattern), pattern


def test_an_over_long_pattern_is_refused():
    assert cp.redos_risk("a" * (cp.MAX_PATTERN_CHARS + 1))


def test_a_rule_regex_is_redos_checked_at_parse_time():
    assert "backtracks catastrophically" in refuse(rule_pack("""
id: r1
title: R1
detection:
  selection: {message|re: '(a+)+$'}
  condition: selection
"""))


def test_a_rule_regex_that_does_not_compile_is_refused():
    assert "not a valid regex" in refuse(rule_pack("""
id: r1
title: R1
detection:
  selection: {message|re: '('}
  condition: selection
"""))


def test_only_re_modified_values_are_treated_as_regexes():
    """Mutation: check every selection value — `message: (a+)+` is a LITERAL in Sigma
    (`_match_scalar` only calls `re.search` under the `re` modifier), and flagging it would
    reject rules that are entirely safe."""
    assert load(rule_pack("""
id: r1
title: R1
detection:
  selection: {message: '(a+)+'}
  condition: selection
""")).rules[0].id == "r1"


def test_a_regex_inside_a_keyword_list_selection_is_still_checked():
    assert "backtracks" in refuse(rule_pack("""
id: r1
title: R1
detection:
  selection:
    - {message|re: '(a+)+$'}
    - {message|re: 'safe'}
  condition: selection
"""))


# ── CIM section ───────────────────────────────────────────────────────────────
def test_a_cim_membership_clause_is_validated_by_the_registrys_own_parser():
    """`rule_name` is a CIM FIELD but not a membership column (`cim/sql.py:_TERM_COLUMNS`).
    Reusing `registry._clause` is what guarantees a pack can express exactly what
    models.yaml can express and nothing more."""
    assert "not allowed in a membership term" in refuse(
        "name: p\nversion: 1.0.0\ncim:\n"
        "  - {model: network, membership: [{rule_name: [x]}]}\n")


def test_a_cim_clause_with_an_unsafe_jsonb_key_is_refused():
    # `@timestamp` fails `cim/sql.py:_KEY_RE`; without this check it would raise at DDL
    # time, i.e. on the next restart, for whoever restarts the app — not the importer.
    assert "unsafe jsonb key" in refuse(
        "name: p\nversion: 1.0.0\ncim:\n"
        "  - {model: network, membership: [{'raw:@timestamp': [x]}]}\n")


def test_a_pack_may_not_define_a_new_data_model():
    """A model tag is what detections bind to. A pack that could mint one could capture
    every rule bound to that name, and the registry's honesty rules (every clause measured
    against a real corpus) cannot be enforced on a stranger's YAML."""
    msg = refuse("name: p\nversion: 1.0.0\ncim:\n"
                 "  - {model: acmemodel, membership: [{vendor: [a]}]}\n")
    assert "never define one" in msg


def test_a_cim_entry_with_neither_membership_nor_fields_is_refused():
    assert "needs `membership`" in refuse(
        "name: p\nversion: 1.0.0\ncim:\n  - {model: network}\n")


# ── compliance section ────────────────────────────────────────────────────────
def test_a_compliance_entry_is_read_into_control_pairs():
    entry = load().compliance[0]
    assert entry.technique == "T1110" and entry.framework == "NIST 800-53"
    assert entry.controls == (("AC-7", "Unsuccessful Logon Attempts"),)


@pytest.mark.parametrize("technique", ["T1110", "T1021.001", "T0846", "AML.T0051"])
def test_enterprise_ics_and_atlas_technique_ids_are_all_accepted(technique):
    # `compliance.MAP` already carries ICS (T0846) keys; ATLAS tags exist on rules.
    assert load(f"name: p\nversion: 1.0.0\ncompliance:\n"
                f"  - {{technique: {technique}, framework: CIS v8, "
                f"controls: [{{id: '1.1', name: X}}]}}\n").compliance[0].technique


def test_a_technique_that_is_not_an_attack_id_is_refused():
    assert "must be an ATT&CK id" in refuse(
        "name: p\nversion: 1.0.0\ncompliance:\n"
        "  - {technique: sqlinjection, framework: CIS v8, controls: [{id: x, name: y}]}\n")


def test_a_framework_this_build_does_not_render_is_refused():
    """`compliance.FRAMEWORKS` drives the page; controls under any other framework import
    successfully and are then never shown to anyone — a silent no-op is worse than a stop."""
    msg = refuse("name: p\nversion: 1.0.0\ncompliance:\n"
                 "  - {technique: T1110, framework: DORA, controls: [{id: x, name: y}]}\n")
    assert "FRAMEWORKS" in msg


def test_a_compliance_entry_with_no_controls_is_refused():
    assert "at least one control" in refuse(
        "name: p\nversion: 1.0.0\ncompliance:\n"
        "  - {technique: T1110, framework: CIS v8, controls: []}\n")


# ── compatibility ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize("actual,constraint,ok", [
    ("1.0.0", ">=1.0", True), ("0.9.9", ">=1.0", False),
    ("1.5", ">=1.0, <2.0", True), ("2.0.1", ">=1.0, <2.0", False),
    ("1.2.0", "1.2", True),                 # bare means >=, not ==
    ("1.2.1", "1.2", True),
    ("2.0", "==2.0", True), ("2.0.1", "==2.0", False),
    ("1.0.0-rc1", ">=1.0", True),           # pre-release metadata is ignored
])
def test_version_constraints_compare_the_way_a_floor_should(actual, constraint, ok):
    """Mutation: read a bare `1.2` as `==1.2` — every pack then expires on the next patch
    release, which is how a compatibility field becomes something people delete."""
    assert cp.satisfies(actual, constraint) is ok


def test_an_unreadable_constraint_is_an_error_not_a_pass():
    with pytest.raises(cp.PackError):
        cp.satisfies("1.0", "roughly 1.x")


def test_a_pack_that_needs_a_newer_build_is_reported():
    pack = load(minimal() + "requires: {logocean: '>=9.0'}\n")
    assert cp.compatibility_problems(pack, app_version="1.0.0")
    assert cp.compatibility_problems(pack, app_version="9.1.0") == []


def test_a_pack_from_a_newer_format_is_refused_by_this_build():
    pack = replace(load(minimal()), format=cp.PACK_FORMAT + 1)
    assert any("newer than this build" in p
               for p in cp.compatibility_problems(pack, app_version="1.0.0"))


def test_a_pack_that_needs_a_newer_cim_registry_is_reported():
    pack = load(minimal() + "requires: {cim: '9'}\n")
    assert cp.compatibility_problems(pack, app_version="1.0.0", cim_version=3)
    assert cp.compatibility_problems(pack, app_version="1.0.0", cim_version=9) == []


# ── integrity + signing ───────────────────────────────────────────────────────
def test_the_digest_covers_content_and_not_formatting():
    """A signature must survive re-indenting the YAML and must not survive a content edit.
    Mutation: hash the file bytes instead of the canonical parse — reformatting a pack then
    invalidates its signature and everyone learns to ignore the warning."""
    pack = load()
    reformatted = cp.parse(yaml.safe_dump(cp.to_dict(pack), sort_keys=True),
                           known_models=MODELS, known_frameworks=FRAMEWORKS)
    assert cp.digest(pack) == cp.digest(reformatted)
    edited = replace(pack, description=pack.description + "!")
    assert cp.digest(pack) != cp.digest(edited)


def test_the_digest_ignores_the_signature_block_itself():
    # Otherwise signing would change the thing being signed and verification is impossible.
    pack = load()
    assert cp.digest(pack) == cp.digest(cp.sign(pack, "k"))


def test_sign_then_verify_round_trips_through_the_file():
    signed = cp.sign(load(), "shared-key", key_id="acme-1")
    reloaded = cp.parse(cp.dumps(signed), known_models=MODELS, known_frameworks=FRAMEWORKS)
    assert reloaded.signature.key_id == "acme-1"
    assert cp.verify(reloaded, "shared-key") is True


def test_verify_rejects_the_wrong_key_and_a_tampered_pack():
    """Mutation: `return True` from `verify` — a tampered pack then imports as trusted,
    which is the entire failure mode signing exists to prevent."""
    signed = cp.sign(load(), "shared-key")
    assert cp.verify(signed, "other-key") is False
    tampered = replace(signed, rules=())
    assert cp.verify(tampered, "shared-key") is False


def test_an_unsigned_pack_never_verifies():
    assert cp.verify(load(), "shared-key") is False


def test_an_unsupported_signature_algorithm_is_refused_at_parse_time():
    """Refusing beats ignoring: an algorithm we cannot check must not read as "no
    signature", which is what a downgrade attack asks for."""
    assert "not supported" in refuse(
        minimal() + "signature: {algorithm: md5, value: '%s'}\n" % ("0" * 64))


def test_a_malformed_signature_value_is_refused():
    assert "hex digest" in refuse(
        minimal() + "signature: {algorithm: hmac-sha256, value: nothex}\n")


# ── export (pure over DB rows) ────────────────────────────────────────────────
PARSER_ROW = {"parser_id": "p1", "title": "P1", "match_key": "product",
              "match_value": "acme", "field_map": {"srcip": "src_ip"},
              "vendor": "acme", "product": None, "kv_source": None, "kv_sep": None,
              "enabled": True}
RULE_ROW = {"rule_id": "r1", "title": "R1", "enabled": True,
            "yaml_text": "id: r1\ntitle: R1\ndetection:\n  selection: {user_name: admin}\n"
                         "  condition: selection\n"}


def test_export_builds_a_pack_out_of_plain_rows():
    pack = cp.export_pack(name="acme", version="1.0.0", parser_rows=[PARSER_ROW],
                          rule_rows=[RULE_ROW], known_models=MODELS)
    assert pack.parsers[0].id == "p1" and pack.rules[0].yaml_text == RULE_ROW["yaml_text"]


def test_export_reads_a_jsonb_field_map_that_arrives_as_text():
    row = dict(PARSER_ROW, field_map='{"dstip": "dst_ip"}')
    assert cp.parser_entry_from_row(row).field_map == (("dstip", "dst_ip"),)


def test_export_drops_a_field_map_entry_that_targets_an_unfillable_column():
    # Rows predate the whitelist; exporting one unchanged would produce a pack this build
    # refuses to import — an export must never emit what import rejects.
    row = dict(PARSER_ROW, field_map={"srcip": "src_ip", "ts": "event_time"})
    assert cp.parser_entry_from_row(row).field_map == (("srcip", "src_ip"),)


def test_export_output_always_re_imports():
    """Mutation: skip the `pack_from_dict` call at the end of `export_pack` — the export
    can then emit a document the importer refuses, which is the worst possible bug in a
    format whose whole job is travelling between installations."""
    pack = cp.export_pack(name="acme", version="1.0.0", parser_rows=[PARSER_ROW],
                          rule_rows=[RULE_ROW], known_models=MODELS)
    assert cp.parse(cp.dumps(pack), known_models=MODELS) == pack


def test_export_refuses_to_emit_an_invalid_row():
    with pytest.raises(cp.PackError):
        cp.export_pack(name="acme", version="1.0.0",
                       parser_rows=[dict(PARSER_ROW, parser_id="")])


def test_compliance_entries_can_be_lifted_out_of_the_shipped_map():
    entries = cp.compliance_entries_from_map(compliance_module.MAP, ["T1110"])
    assert entries and {e.technique for e in entries} == {"T1110"}
    assert all(e.controls for e in entries)


# ── planning (the dry run) ────────────────────────────────────────────────────
def test_a_fresh_install_plans_a_create_for_everything():
    plan = cp.plan_install(load(), cp.ExistingState())
    assert plan.applicable is True
    assert plan.counts()["create"] == 5         # pack + parser + rule + cim + compliance
    assert plan.restart_required is True               # membership needs a restart


def test_planning_consumes_nothing_and_is_deterministic():
    """A dry run must be re-runnable and must not disturb the snapshot it was handed.

    Mutation: have `plan_install` `pop()` from `existing.parsers` as it walks the pack (an
    easy way to compute "what is left over") — the first plan then reads correctly and
    every plan after it reports creates for objects that already exist.
    """
    pack = load()
    state = cp.ExistingState(parsers={"acme-fw": {"parser_id": "acme-fw"}},
                             rules={"acme-admin-login": pack.rules[0].yaml_text})
    first = cp.plan_install(pack, state, overwrite=True)
    second = cp.plan_install(pack, state, overwrite=True)
    assert first == second
    assert set(state.parsers) == {"acme-fw"} and set(state.rules) == {"acme-admin-login"}


def test_an_identical_reinstall_plans_as_unchanged():
    pack = load()
    row = {"parser_id": "acme-fw", "title": "ACME firewall field map",
           "match_key": "product", "match_value": "acme-fw",
           "field_map": {"srcip": "src_ip", "dstip": "dst_ip", "act": "action"},
           "vendor": "acme", "product": "firewall", "enabled": True}
    state = cp.ExistingState(parsers={"acme-fw": row},
                             rules={"acme-admin-login": pack.rules[0].yaml_text},
                             owners={("parser", "acme-fw"): pack.name,
                                     ("rule", "acme-admin-login"): pack.name},
                             installed={pack.name: pack})
    plan = cp.plan_install(pack, state)
    verbs = {(c.kind, c.verb) for c in plan.changes}
    assert ("parser", cp.UNCHANGED) in verbs and ("rule", cp.UNCHANGED) in verbs
    assert plan.restart_required is False              # nothing to re-derive


def test_a_changed_object_plans_as_an_update():
    pack = load()
    row = {"parser_id": "acme-fw", "title": "OLD TITLE", "match_key": "product",
           "match_value": "acme-fw", "field_map": {"srcip": "src_ip"},
           "vendor": "acme", "product": "firewall", "enabled": True}
    state = cp.ExistingState(parsers={"acme-fw": row},
                             owners={("parser", "acme-fw"): pack.name},
                             installed={pack.name: pack})
    assert any(c.kind == "parser" and c.verb == cp.UPDATE for c in cp.plan_install(pack, state).changes)


def test_a_reordered_field_map_is_not_a_spurious_update():
    """Mutation: compare `field_map` as an ordered tuple on both sides — every re-import
    then reports an update, and "nothing changed" stops meaning anything."""
    pack = load()
    row = {"parser_id": "acme-fw", "title": "ACME firewall field map",
           "match_key": "product", "match_value": "acme-fw",
           "field_map": {"act": "action", "dstip": "dst_ip", "srcip": "src_ip"},
           "vendor": "acme", "product": "firewall", "enabled": True}
    state = cp.ExistingState(parsers={"acme-fw": row},
                             owners={("parser", "acme-fw"): pack.name},
                             installed={pack.name: pack})
    assert any(c.kind == "parser" and c.verb == cp.UNCHANGED
               for c in cp.plan_install(pack, state).changes)


def test_an_object_owned_by_another_pack_is_a_conflict():
    state = cp.ExistingState(parsers={"acme-fw": {"parser_id": "acme-fw"}},
                             owners={("parser", "acme-fw"): "someone-elses-pack"})
    plan = cp.plan_install(load(), state)
    assert plan.applicable is False
    assert plan.conflicts[0].owner == "someone-elses-pack"


def test_hand_authored_content_is_a_conflict_too():
    """An object with no owner was authored in the console. Overwriting it silently is how
    a content pack eats somebody's afternoon."""
    state = cp.ExistingState(parsers={"acme-fw": {"parser_id": "acme-fw"}})
    plan = cp.plan_install(load(), state)
    assert plan.conflicts and "not installed by a pack" in plan.conflicts[0].detail


def test_overwrite_turns_a_conflict_into_an_update():
    state = cp.ExistingState(parsers={"acme-fw": {"parser_id": "acme-fw"}},
                             owners={("parser", "acme-fw"): "someone-elses-pack"})
    plan = cp.plan_install(load(), state, overwrite=True)
    assert plan.applicable is True
    assert any(c.kind == "parser" and c.verb == cp.UPDATE for c in plan.changes)


def test_an_upgrade_deletes_what_the_new_version_dropped():
    """Mutation: skip the `previous` loop — the old parser stays installed and enabled
    forever, still matching events, with nothing in the UI explaining where it came from."""
    old = load()
    new = replace(old, version="2.0.0", parsers=())
    state = cp.ExistingState(owners={("parser", "acme-fw"): old.name},
                             installed={old.name: old})
    plan = cp.plan_install(new, state)
    assert any(c.kind == "parser" and c.verb == cp.DELETE and c.ident == "acme-fw"
               for c in plan.changes)
    assert any(c.kind == "pack" and c.verb == cp.UPDATE for c in plan.changes)


def test_an_incompatible_pack_produces_a_problem_and_not_a_plan():
    pack = load(minimal() + "requires: {logocean: '>=9.0'}\n")
    plan = cp.plan_install(pack, cp.ExistingState(), app_version="1.0.0")
    assert plan.problems and plan.applicable is False


def test_uninstall_plans_removal_of_exactly_what_the_pack_installed():
    pack = load()
    state = cp.ExistingState(owners={("parser", "acme-fw"): pack.name,
                                     ("rule", "acme-admin-login"): pack.name,
                                     ("parser", "somebody-elses"): "other"},
                             installed={pack.name: pack})
    idents = {(c.kind, c.ident) for c in cp.plan_uninstall(pack.name, state).changes}
    assert ("parser", "acme-fw") in idents and ("rule", "acme-admin-login") in idents
    assert ("parser", "somebody-elses") not in idents


def test_uninstall_leaves_an_object_another_pack_has_since_claimed():
    """Two packs can ship the same upstream rule id. Uninstalling the first must not
    delete content the second now owns."""
    pack = load()
    state = cp.ExistingState(owners={("parser", "acme-fw"): "a-later-pack"},
                             installed={pack.name: pack})
    idents = {(c.kind, c.ident) for c in cp.plan_uninstall(pack.name, state).changes}
    assert ("parser", "acme-fw") not in idents


def test_uninstalling_something_that_is_not_installed_is_an_error():
    with pytest.raises(cp.PackError):
        cp.plan_uninstall("never-heard-of-it", cp.ExistingState())


# ── applying ──────────────────────────────────────────────────────────────────
def test_apply_stages_every_created_object_and_the_pack_row():
    writer = cp.RecordingWriter()
    result = cp.apply_plan(cp.plan_install(load(), cp.ExistingState()), writer)
    assert [p.id for p in writer.parsers] == ["acme-fw"]
    assert [r.id for r in writer.rules] == ["acme-admin-login"]
    assert writer.pack.name == "acme-firewall"
    assert result.restart_required is True


def test_apply_refuses_a_plan_with_conflicts():
    """Mutation: drop the conflict check in `apply_plan` — the dry run then reports a
    conflict that the apply happily overwrites, which makes the report a lie."""
    state = cp.ExistingState(parsers={"acme-fw": {"parser_id": "acme-fw"}},
                             owners={("parser", "acme-fw"): "other"})
    with pytest.raises(cp.PackError):
        cp.apply_plan(cp.plan_install(load(), state), cp.RecordingWriter())


def test_apply_refuses_a_plan_with_problems():
    plan = cp.ImportPlan(pack=load(), problems=("nope",))
    with pytest.raises(cp.PackError):
        cp.apply_plan(plan, cp.RecordingWriter())


def test_apply_does_not_rewrite_an_unchanged_object():
    pack = load()
    state = cp.ExistingState(rules={"acme-admin-login": pack.rules[0].yaml_text},
                             owners={("rule", "acme-admin-login"): pack.name},
                             installed={pack.name: pack})
    writer = cp.RecordingWriter()
    cp.apply_plan(cp.plan_install(pack, state), writer)
    assert writer.rules == []


def test_apply_stages_deletes_for_an_upgrade():
    old = load()
    new = replace(old, version="2.0.0", parsers=())
    state = cp.ExistingState(owners={("parser", "acme-fw"): old.name},
                             installed={old.name: old})
    writer = cp.RecordingWriter()
    cp.apply_plan(cp.plan_install(new, state), writer)
    assert writer.removed_parsers == ["acme-fw"]


def test_apply_of_an_uninstall_plan_removes_the_pack_row_too():
    pack = load()
    state = cp.ExistingState(owners={("parser", "acme-fw"): pack.name,
                                     ("rule", "acme-admin-login"): pack.name},
                             installed={pack.name: pack})
    writer = cp.RecordingWriter()
    cp.apply_plan(cp.plan_uninstall(pack.name, state), writer)
    assert writer.removed_pack == pack.name
    assert writer.removed_parsers == ["acme-fw"] and writer.removed_rules == ["acme-admin-login"]
    assert writer.pack is None


def test_everything_is_staged_before_anything_is_committed():
    """The atomicity story: a writer sees the whole plan in its buffer and exactly one
    `flush`, so the database is handed a complete, already-validated change set.

    Mutation: call `flush()` per object — a pack that fails half-way then leaves the
    install partially applied, with no record of which half.
    """
    flushes = []

    class CountingWriter(cp.RecordingWriter):
        def flush(self):
            flushes.append((len(self.parsers), len(self.rules), self.pack is not None))

    cp.apply_plan(cp.plan_install(load(), cp.ExistingState()), CountingWriter())
    assert flushes == [(1, 1, True)]


# ── merges: how the CIM and compliance sections take effect ───────────────────
def tiny_registry() -> CimRegistry:
    """A two-model registry, hand-built so these tests do not move with models.yaml."""
    model = CimModel(
        name="Network", tag="network", version=1, description="",
        clauses=(CimClause(terms=(CimTerm(source=CimSource.column_of("log_type"),
                                          values=("traffic",), label="log_type"),)),),
        fields=(CimField(name="src", source=CimSource.column_of("src_ip")),))
    other = CimModel(
        name="Authentication", tag="authentication", version=2, description="",
        clauses=(CimClause(terms=(CimTerm(source=CimSource.column_of("log_type"),
                                          values=("security",), label="log_type"),)),),
        fields=(CimField(name="user", source=CimSource.column_of("user_name")),))
    return CimRegistry(version=1, models=(model, other))


def evt(**kw) -> NormalizedEvent:
    return NormalizedEvent(event_time=None, vendor=kw.pop("vendor", "acme"), **kw)


def test_merge_cim_widens_membership_for_a_new_source():
    """The behavioural test, not a structural one: an event that belonged to NO model must
    belong to Network once the pack's clause is merged.

    Mutation: append the clause to the wrong model, or build the new registry without it —
    `tags_for` then still returns [] and the pack looks installed but does nothing.
    """
    reg = tiny_registry()
    e = evt(log_type="widgetflow")
    assert cim_match.tags_for(e, reg) == []
    merged = cp.merge_cim(reg, [cp.CimEntry(model="network",
                                            membership=({"vendor": ["acme"],
                                                         "log_type": ["widgetflow"]},))])
    assert cim_match.tags_for(e, merged) == ["network"]


def test_merge_cim_does_not_mutate_the_registry_it_was_given():
    """The registry is a process-wide cached singleton; mutating it in place would make a
    pack's effect depend on whether anyone had read the registry first."""
    reg = tiny_registry()
    before = len(reg.by_name("network").clauses)
    cp.merge_cim(reg, [cp.CimEntry(model="network", membership=({"vendor": ["acme"]},))])
    assert len(reg.by_name("network").clauses) == before
    assert cim_match.tags_for(evt(log_type="widgetflow"), reg) == []


def test_merge_cim_only_ever_adds_clauses():
    reg = tiny_registry()
    merged = cp.merge_cim(reg, [cp.CimEntry(model="network",
                                            membership=({"vendor": ["acme"]},))])
    assert merged.by_name("network").clauses[:1] == reg.by_name("network").clauses
    # and the untouched model is carried through byte-identical
    assert merged.by_name("authentication") == reg.by_name("authentication")


def test_merge_cim_leaves_other_models_alone():
    """A clause added to Network must land on Network ONLY.

    Mutation: apply the additions to every model instead of the named one — the pack's own
    event is then stamped with both tags, and a detection bound to Authentication starts
    firing on firewall traffic. The event chosen here is the one the clause matches,
    because an event the clause does NOT match cannot tell the two behaviours apart.
    """
    merged = cp.merge_cim(tiny_registry(),
                          [cp.CimEntry(model="network",
                                       membership=({"vendor": ["acme"],
                                                    "log_type": ["widgetflow"]},))])
    assert cim_match.tags_for(evt(log_type="widgetflow"), merged) == ["network"]
    assert cim_match.tags_for(evt(log_type="security"), merged) == ["authentication"]


def test_merge_cim_accepts_a_model_by_display_name_as_well_as_by_tag():
    merged = cp.merge_cim(tiny_registry(),
                          [cp.CimEntry(model="Network", membership=({"vendor": ["acme"]},))])
    assert len(merged.by_name("network").clauses) == 2


def test_merge_cim_bumps_the_version_only_when_a_field_is_added():
    """`version` documents the model's SCHEMA. Widening membership adds no column and
    breaks no consumer; adding a field changes the projection and must be visible."""
    reg = tiny_registry()
    clauses_only = cp.merge_cim(reg, [cp.CimEntry(model="network",
                                                  membership=({"vendor": ["acme"]},))])
    assert clauses_only.by_name("network").version == 1
    with_field = cp.merge_cim(reg, [cp.CimEntry(model="network",
                                                fields=({"name": "zone", "raw": ["zone"]},))])
    assert with_field.by_name("network").version == 2
    assert with_field.by_name("network").fields[-1].name == "zone"


def test_merge_cim_refuses_a_field_that_shadows_an_existing_one():
    """Two fields of one name load cleanly and then abort CREATE VIEW with SQLSTATE 42701 —
    on the next restart, for whoever restarts the app."""
    with pytest.raises(cp.PackError):
        cp.merge_cim(tiny_registry(),
                     [cp.CimEntry(model="network", fields=({"name": "src", "raw": ["x"]},))])


def test_merge_cim_refuses_an_unknown_model():
    with pytest.raises(cp.PackError):
        cp.merge_cim(tiny_registry(), [cp.CimEntry(model="acme", membership=({"vendor": ["a"]},))])


def test_merge_cim_is_a_no_op_for_no_entries():
    reg = tiny_registry()
    assert cp.merge_cim(reg, []) is reg


def test_merge_compliance_adds_a_technique_without_touching_the_base():
    """Mutation: mutate `base` in place — `compliance.MAP` is module state shared by the
    whole process, so an import would rewrite the shipped crosswalk for everyone."""
    base = {"T1110": {"CIS v8": [("6.2", "Access Revoking")]}}
    merged = cp.merge_compliance(base, [cp.ComplianceEntry("T9999", "CIS v8",
                                                           (("1.1", "New"),))])
    assert merged["T9999"]["CIS v8"] == [("1.1", "New")]
    assert "T9999" not in base
    assert base["T1110"]["CIS v8"] == [("6.2", "Access Revoking")]


def test_merge_compliance_appends_controls_and_drops_duplicates():
    base = {"T1110": {"CIS v8": [("6.2", "Access Revoking")]}}
    merged = cp.merge_compliance(base, [cp.ComplianceEntry(
        "T1110", "CIS v8", (("6.2", "a different name for the same id"), ("9.9", "Added")))])
    assert merged["T1110"]["CIS v8"] == [("6.2", "Access Revoking"), ("9.9", "Added")]


def test_merge_compliance_cannot_remove_a_shipped_mapping():
    """A pack must not be able to un-map a control someone's audit report depends on."""
    merged = cp.merge_compliance(compliance_module.MAP,
                                 [cp.ComplianceEntry("T1110", "CIS v8", (("9.9", "X"),))])
    for technique, frameworks in compliance_module.MAP.items():
        for framework, controls in frameworks.items():
            assert set(controls) <= set(merged[technique][framework])


def test_merged_compliance_still_builds_a_report():
    """The merged map has to be shaped exactly like `compliance.MAP`, because
    `build_report` consumes it directly."""
    merged = cp.merge_compliance(compliance_module.MAP,
                                 [cp.ComplianceEntry("T1110", "CIS v8", (("9.9", "New"),))])
    saved = compliance_module.MAP
    try:
        compliance_module.MAP = merged
        compliance_module._FW_CONTROLS = compliance_module._index()
        report = compliance_module.build_report({"T1110"}, {"T1110": 3})
        ids = {row["id"] for row in report["CIS v8"]["controls"]}
        assert "9.9" in ids
    finally:
        compliance_module.MAP = saved
        compliance_module._FW_CONTROLS = compliance_module._index()


def test_overlay_registry_applies_installed_pack_membership(monkeypatch):
    """The one call `app/cim/registry.py` makes. `installed_packs` is stubbed, so this
    exercises the overlay with no database."""
    pack = replace(load(), cim=(cp.CimEntry(model="network",
                                            membership=({"vendor": ["acme"],
                                                         "log_type": ["widgetflow"]},)),))
    seen = []
    monkeypatch.setattr(cp, "installed_packs",
                        lambda known_models=None: (seen.append(known_models), (pack,))[1])
    merged = cp.overlay_registry(tiny_registry())
    assert cim_match.tags_for(evt(log_type="widgetflow"), merged) == ["network"]
    # `known_models` must be threaded down from the registry in hand. With it left None,
    # `parse` resolves the model list via `cim_registry.get_registry()` — and the overlay
    # runs INSIDE that function's non-reentrant lock, so the re-entrant call hangs the
    # process on the first startup after any pack is installed, silently (a lock that
    # never releases raises nothing for `_registry_model_names` to box).
    assert seen and seen[0] is not None and "network" in seen[0]


def test_overlay_registry_falls_back_to_the_shipped_registry_on_a_bad_pack(monkeypatch):
    """A pack whose model was renamed out from under it must cost that PACK, not the whole
    registry.

    Mutation: let `merge_cim` raise out of `overlay_registry` — `get_registry` then fails,
    `tags_for` degrades to no membership for EVERY event, and the whole CIM layer goes dark
    because one stored document went stale.
    """
    broken = replace(load(), cim=(cp.CimEntry(model="no-such-model",
                                              membership=({"vendor": ["acme"]},)),))
    monkeypatch.setattr(cp, "installed_packs", lambda: (broken,))
    reg = tiny_registry()
    assert cp.overlay_registry(reg) is reg


def test_overlay_registry_is_a_no_op_with_no_packs(monkeypatch):
    monkeypatch.setattr(cp, "installed_packs", lambda: ())
    reg = tiny_registry()
    assert cp.overlay_registry(reg) is reg


# ── contracts the rest of the app depends on ─────────────────────────────────
def test_validate_returns_messages_instead_of_raising():
    assert cp.validate(PACK_YAML, known_models=MODELS, known_frameworks=FRAMEWORKS) == []
    problems = cp.validate("name: 'BAD NAME'\nversion: 1.0.0\n", known_models=MODELS)
    assert len(problems) == 1 and "lower-case" in problems[0]


def test_validate_accepts_an_already_parsed_mapping():
    assert cp.validate(cp.to_dict(load()), known_models=MODELS,
                       known_frameworks=FRAMEWORKS) == []


def test_a_pack_validates_against_the_real_registry_and_framework_list():
    """The format tests run on a hand-built vocabulary so they do not move with
    `models.yaml`; this one proves the shipped vocabulary actually resolves, so a pack
    naming a real model is not refused in production."""
    pack = cp.parse(PACK_YAML)                     # no known_* -> live registry + FRAMEWORKS
    assert pack.cim[0].model == "network"
    assert pack.compliance[0].framework in compliance_module.FRAMEWORKS


def test_the_registry_lookup_degrades_instead_of_refusing_every_pack(monkeypatch):
    """A broken CIM registry is already reported by /health; refusing every content-pack
    operation on top of it adds a second, more confusing symptom."""
    monkeypatch.setattr(cim_registry, "get_registry",
                        lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert cp._registry_model_names() == ()
    assert cp.parse(PACK_YAML, known_frameworks=FRAMEWORKS).name == "acme-firewall"


def test_a_recording_writer_is_what_a_dry_run_uses():
    # DbWriter must remain the ONLY database contact: if `RecordingWriter` ever grew one,
    # every test in this file would silently need a database.
    assert cp.RecordingWriter.flush is cp.PackWriter.flush
    assert cp.DbWriter.flush is not cp.PackWriter.flush
