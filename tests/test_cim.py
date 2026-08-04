# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""CIM data models (Backbone #2) — the DB-free proof that membership is correct.

The whole CIM layer is deliberately pure: a YAML registry is loaded into frozen
:mod:`app.cim.spec` objects, :mod:`app.cim.sql` turns them into view DDL, and
:mod:`app.cim.match` evaluates membership in Python at ingest. Nothing here needs a
database, which is the point — this file is the only verification the layer gets on a
developer box, and the store seams (`db._row`, `_INSERT`, the backfill query) are
asserted as *emitted text* for the same reason.

Four things are being defended, in rising order of how badly they fail silently:

1. **Loader guards.** A YAML-1.1 bare ``on`` becomes the string ``'true'`` and matches
   nothing, forever; a duplicated field name aborts ``CREATE VIEW`` with SQLSTATE 42701
   at startup. Both are load-time errors now, and each guard test writes a registry that
   deviates from `_GOOD` in exactly one way.
2. **SQL emission.** Byte-exact, because these strings become DDL: a jsonb key is never
   split on ``.`` (Zeek writes literal dotted top-level keys such as ``id.orig_h``), and
   every output label is quoted (bare ``AS user`` silently returns ``CURRENT_USER``).
3. **The evaluator.** Compiled plan and reference walk must agree — that equivalence,
   asserted over the whole sample corpus, is what keeps the two from drifting.
4. **The corpus.** Every file in ``samples/`` parsed by its real parser and tagged, with
   a checked-in per-source expectation, so a regression *names* the source it broke
   instead of moving a percentage. This is what enforces the roadmap's Phase-1 exit
   criterion, ">=8 CIM models populated by existing parsers".
"""
from __future__ import annotations

import re
import textwrap
import traceback
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import jinja2
import pytest

from app import db
from app.cim import match, registry as cim_registry, sql as cim_sql
from app.cim.spec import (CimClause, CimError, CimField, CimModel, CimRegistry,
                          CimSource, CimTerm)
from app.detect import detect_format
from app.models import NormalizedEvent
from app.parsers import PARSERS

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
TEMPLATES = ROOT / "app" / "templates"

REGISTRY = cim_registry.get_registry()
_T = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)


def evt(**cols) -> NormalizedEvent:
    """A NormalizedEvent carrying only the columns a membership term can read."""
    cols.setdefault("vendor", "acme")
    return NormalizedEvent(event_time=_T, **cols)


def row_of(e: NormalizedEvent) -> dict[str, Any]:
    """The same event as a stored `events` row — the shape `db.backfill_cim` re-evaluates.
    Exactly the nine term columns plus `raw`, i.e. what `_CIM_BACKFILL_COLS` selects."""
    d = {c: getattr(e, c) for c in sorted(cim_sql._TERM_COLUMNS)}
    d["raw"] = e.raw
    return d


def one_model(*terms: CimTerm, tag: str = "t", name: str = "T") -> CimRegistry:
    """A one-model, one-clause registry over `terms` (AND-ed) — the smallest thing that
    can be evaluated, for tests about a single term's semantics."""
    return CimRegistry(version=1, models=(CimModel(
        name=name, tag=tag, version=1, description="",
        clauses=(CimClause(terms=terms),),
        fields=(CimField(name="user", source=CimSource.column_of("user_name")),)),))


def load_yaml(tmp_path: Path, text: str) -> CimRegistry:
    p = tmp_path / "models.yaml"
    p.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")
    return cim_registry.load(p)


def _never_called(*a, **k):
    """Stand-in for a registry walk that must NOT happen — proves a threaded value was
    used rather than silently recomputed."""
    raise AssertionError("the registry was walked when a resolved value was supplied")


def _boom(*a, **k):
    """A registry that will not evaluate — the post-boot failure `_cim_tags` degrades."""
    raise CimError("boom")


# The minimal registry the loader guards below deviate from, one deviation at a time. It
# is asserted to load first, so a guard that fires for the wrong reason cannot hide here.
_GOOD = """
    version: 1
    models:
      - name: Alpha
        tag: alpha
        version: 1
        description: the minimal valid model
        membership:
          - {log_type: [security]}
        fields:
          - {name: user, column: user_name}
    """


# ── registry loader guards ────────────────────────────────────────────────────
def test_loader_accepts_the_minimal_registry(tmp_path):
    """The control for every guard below: `_GOOD` must load, or the guards prove nothing."""
    reg = load_yaml(tmp_path, _GOOD)
    assert reg.tags == ["alpha"] and reg.names == ["Alpha"]
    assert reg.by_name("ALPHA") is reg.models[0]          # name/tag, case-insensitive


def test_loader_rejects_duplicate_field_name(tmp_path):
    """Two fields with one name load cleanly and then abort CREATE VIEW with SQLSTATE
    42701 ('column specified more than once') — at startup, on every boot."""
    with pytest.raises(CimError) as e:
        load_yaml(tmp_path, """
            version: 1
            models:
              - name: Alpha
                tag: alpha
                membership: [{log_type: [security]}]
                fields:
                  - {name: user, column: user_name}
                  - {name: user, column: host_name}
            """)
    assert "duplicate field name" in str(e.value)


def test_loader_rejects_duplicate_model_tag(tmp_path):
    with pytest.raises(CimError) as e:
        load_yaml(tmp_path, """
            version: 1
            models:
              - name: Alpha
                tag: alpha
                membership: [{log_type: [security]}]
                fields: [{name: user, column: user_name}]
              - name: Beta
                tag: alpha
                membership: [{log_type: [audit]}]
                fields: [{name: user, column: user_name}]
            """)
    assert "duplicate model tag" in str(e.value)


def test_loader_rejects_duplicate_model_name(tmp_path):
    """`by_name` would otherwise resolve to whichever model happened to be listed first,
    so `from datamodel:Alpha` would silently search the wrong one."""
    with pytest.raises(CimError) as e:
        load_yaml(tmp_path, """
            version: 1
            models:
              - name: Alpha
                tag: one
                membership: [{log_type: [security]}]
                fields: [{name: user, column: user_name}]
              - name: Alpha
                tag: two
                membership: [{log_type: [audit]}]
                fields: [{name: user, column: user_name}]
            """)
    assert "collision" in str(e.value) and "alpha" in str(e.value)


def test_loader_rejects_a_tag_shadowing_another_models_display_name(tmp_path):
    """Names and tags share ONE key space because `by_name` resolves both. Here Alpha's
    tag is `beta`, which is also Beta's display name — `from datamodel:Beta` would be
    ambiguous, so the registry refuses to load rather than pick one."""
    with pytest.raises(CimError) as e:
        load_yaml(tmp_path, """
            version: 1
            models:
              - name: Alpha
                tag: beta
                membership: [{log_type: [security]}]
                fields: [{name: user, column: user_name}]
              - name: Beta
                tag: gamma
                membership: [{log_type: [audit]}]
                fields: [{name: user, column: user_name}]
            """)
    assert "collision" in str(e.value) and "beta" in str(e.value)


@pytest.mark.parametrize("value", ["yes", "no", "on", "off", "true", "false"])
def test_loader_rejects_yaml_bool_membership_values(tmp_path, value):
    """The YAML 1.1 trap. PyYAML reads bare yes/no/on/off as booleans, so a membership
    value of `on` used to compile to the literal 'true' and match nothing — a data model
    that silently stays empty, which looks exactly like 'there were no such events'."""
    with pytest.raises(CimError) as e:
        load_yaml(tmp_path, f"""
            version: 1
            models:
              - name: Alpha
                tag: alpha
                membership: [{{action: [{value}]}}]
                fields: [{{name: user, column: user_name}}]
            """)
    assert "quote" in str(e.value)


@pytest.mark.parametrize("value", ["null", "~"])
def test_loader_rejects_yaml_null_membership_values(tmp_path, value):
    with pytest.raises(CimError) as e:
        load_yaml(tmp_path, f"""
            version: 1
            models:
              - name: Alpha
                tag: alpha
                membership: [{{action: [{value}]}}]
                fields: [{{name: user, column: user_name}}]
            """)
    assert "quote" in str(e.value)


def test_loader_keeps_integer_membership_values(tmp_path):
    """The POSITIVE half of the YAML-scalar guard, and a real dependency: the shipped
    models.yaml lists Windows event ids as bare integers, and `windows_security.py`
    writes `raw["event_id"]` back as an int. Both sides have to arrive at '4625'."""
    reg = load_yaml(tmp_path, """
        version: 1
        models:
          - name: Alpha
            tag: alpha
            membership: [{raw:event_id: [4624, 4625]}]
            fields: [{name: user, column: user_name}]
        """)
    term = reg.models[0].clauses[0].terms[0]
    assert term.values == ("4624", "4625")
    assert match.tags_for(evt(raw={"event_id": 4625}), reg) == ["alpha"]


def test_loader_rejects_duplicate_mapping_keys(tmp_path):
    """PyYAML silently keeps the LAST of a repeated key, so a clause written with two
    `event_id:` terms would quietly lose one and the model would stop matching."""
    with pytest.raises(CimError) as e:
        load_yaml(tmp_path, """
            version: 1
            models:
              - name: Alpha
                tag: alpha
                membership:
                  - log_type: [security]
                    log_type: [audit]
                fields: [{name: user, column: user_name}]
            """)
    assert "duplicate key" in str(e.value)


def test_loader_rejects_a_membership_term_on_a_non_term_column(tmp_path):
    """Membership may only test the nine text columns; `message` is not one of them
    (`sql._TERM_COLUMNS`), and the evaluator's import-time check pins that same list."""
    with pytest.raises(CimError) as e:
        load_yaml(tmp_path, """
            version: 1
            models:
              - name: Alpha
                tag: alpha
                membership: [{message: [hello]}]
                fields: [{name: user, column: user_name}]
            """)
    assert "not allowed in a membership term" in str(e.value)


# ── by_name: an exact NAME beats another model's tag ──────────────────────────
# `CimRegistry.by_name` resolves a display name OR a tag, and it does so in TWO passes —
# all names first, then all tags. The one-pass form (`m.name.lower() == low or m.tag ==
# low`, per model) reads identically and is wrong: it returns whichever model comes FIRST
# in the file, so an earlier model's tag shadows a later model's exact display name. That
# is `from datamodel:Web` silently searching Proxy — the wrong events, no error. The
# loader refuses this registry outright (see the tag-shadowing guard above), so the order
# below is the belt-and-braces half, and it is the half a hand-built registry in any test
# actually leans on.

def _named(name: str, tag: str) -> CimModel:
    return CimModel(name=name, tag=tag, version=1, description="",
                    clauses=(CimClause(terms=(CimTerm(source=CimSource.column_of("vendor"),
                                                      values=(tag,)),)),),
                    fields=(CimField(name="user", source=CimSource.column_of("user_name")),))


def test_by_name_prefers_an_exact_name_over_an_earlier_models_tag():
    """A named Proxy TAGGED web, declared before a model NAMED Web."""
    proxy, web = _named("Proxy", "web"), _named("Web", "proxy")
    reg = CimRegistry(version=1, models=(proxy, web))
    assert reg.by_name("Web") is web                  # the exact name, not Proxy's tag
    assert reg.by_name("WEB") is web                  # ...case-insensitively
    assert reg.by_name("Proxy") is proxy              # and symmetrically, the other way
    assert reg.by_name("web") is web and reg.by_name("proxy") is proxy


def test_by_name_still_falls_back_to_a_tag_no_name_claims():
    """The second pass is not decoration — `ics` is a tag no display name spells."""
    assert REGISTRY.by_name("ics") is REGISTRY.by_name("Industrial")
    assert REGISTRY.by_name("Industrial").tag == "ics"


@pytest.mark.parametrize("key, tag", [
    ("  Industrial  ", "ics"),      # `.strip()` — the key is normalized before matching
    ("INDUSTRIAL", "ics"),          # `.lower()` — so is its case, on both sides
    ("nosuchmodel", None),          # a miss stays a miss; never "whichever came first"
    (None, None),                   # `(name or "")` — a None key must not raise
])
def test_by_name_normalizes_its_key_and_never_guesses(key, tag):
    model = REGISTRY.by_name(key)
    assert (model.tag if model else None) == tag


# ── SQL emission ──────────────────────────────────────────────────────────────
def test_single_raw_key_emits_the_arrow_operator():
    assert cim_sql.source_sql(CimSource.raw_of("query")) == "(raw ->> 'query')"


def test_multiple_raw_keys_emit_coalesce_in_order():
    """Ordered alternatives, first non-null wins — vendors spell one concept many ways."""
    sql = cim_sql.source_sql(CimSource.raw_of("event_id", "EventID", "Event ID"))
    assert sql == ("COALESCE((raw ->> 'event_id'), (raw ->> 'EventID'), "
                   "(raw ->> 'Event ID'))")


def test_nested_path_emits_the_jsonb_path_operator():
    """An ARRAY constructor, not a '{a,b}' array literal — a key containing a space or a
    comma cannot then break out of array-literal quoting."""
    assert (cim_sql.source_sql(CimSource.raw_of(("ot", "operation")))
            == "(raw #>> ARRAY['ot', 'operation'])")


def test_a_dotted_raw_key_is_never_split():
    """THE Zeek regression guard. `id.orig_h` is a literal TOP-LEVEL key, so dot-splitting
    it into a nested path would silently empty the Network model of every Zeek event."""
    sql = cim_sql.source_sql(CimSource.raw_of("id.orig_h"))
    assert sql == "(raw ->> 'id.orig_h')"
    assert "ARRAY[" not in sql and "'id'" not in sql


def test_a_dotted_raw_key_survives_the_yaml_loader(tmp_path):
    """Same guard one layer up: the YAML author writes `raw: id.orig_h` and gets one key."""
    reg = load_yaml(tmp_path, """
        version: 1
        models:
          - name: Alpha
            tag: alpha
            membership: [{raw:id.orig_h: ["10.0.0.1"]}]
            fields: [{name: src, raw: id.orig_h}]
        """)
    field = reg.models[0].fields[0]
    assert field.source.paths == (("id.orig_h",),)
    assert cim_sql.field_value_sql(field) == "(raw ->> 'id.orig_h')"
    assert match.tags_for(evt(raw={"id.orig_h": "10.0.0.1"}), reg) == ["alpha"]
    # a genuinely nested {"id": {"orig_h": ...}} must NOT satisfy the flat key
    assert match.tags_for(evt(raw={"id": {"orig_h": "10.0.0.1"}}), reg) == []


def test_reserved_word_field_label_is_quoted():
    """Authentication maps `user`. Unquoted, `CREATE VIEW` accepts `user_name AS user`
    and a later bare `SELECT user` parses as CURRENT_USER — the connection role on every
    row, no error anywhere. Every label is quoted, so it cannot happen."""
    ddl = cim_sql.create_view_ddl(REGISTRY.by_name("Authentication"))
    assert 'user_name AS "user"' in ddl
    assert re.search(r'AS\s+user(?![\w"])', ddl) is None


def test_every_field_label_in_every_shipped_model_is_quoted():
    for model in REGISTRY.models:
        ddl = cim_sql.create_view_ddl(model)
        for f in model.fields:
            assert f'AS "{f.name}"' in ddl, f"{model.tag}.{f.name} label is not quoted"


def test_membership_sql_is_an_or_of_ands_with_literal_values():
    sql = cim_sql.membership_sql(REGISTRY.by_name("Industrial"))
    assert sql == ("(((lower(log_type) IN ('modbus', 'dnp3', 's7comm', 'cip', 'enip', "
                   "'bacnet', 'iec104', 'opcua', 'profinet'))))")


def test_membership_values_are_quote_escaped():
    """A view body cannot bind parameters, so the registry's values are escaped inline.
    The registry is trusted config, but this is the same defence the LOQL compiler applies."""
    term = CimTerm(source=CimSource.column_of("vendor"), values=("x' or '1'='1",))
    sql = cim_sql._term_sql(term)
    assert sql == "(lower(vendor) = 'x'' or ''1''=''1')"


def test_membership_predicate_is_the_containment_form_the_gin_index_serves():
    assert (cim_sql.membership_predicate("web")
            == "cim_models @> ARRAY['web']::text[]")


def test_view_ddl_projects_the_model_vocabulary_over_its_members():
    model = REGISTRY.by_name("DNS")
    ddl = cim_sql.create_view_ddl(model)
    assert ddl.startswith("CREATE VIEW cim_dns AS")
    assert ddl.rstrip().endswith("WHERE cim_models @> ARRAY['dns']::text[]")
    # one labelled expression per field and nothing else labelled
    assert ddl.count(" AS ") == len(model.fields)
    # id/event_time for drill-down, then the passthroughs no field name took
    assert "SELECT id, event_time, " in ddl
    assert ddl.rstrip().splitlines()[1].endswith(
        ", vendor, product, log_type, severity, message, raw")


# ── injection safety: the four emitters that ARE the parameterization ─────────
# A view body cannot bind parameters, so `db.init_cim` sends `cim_sql`'s output to
# PostgreSQL as text. `_ident`, `_quote_ident`, `_key` and `_lit` are therefore not
# tidiness — they are the whole of the defence, and each one has a different job:
#
#   _ident       whitelists a bare lower-case name (tags + field names). REJECTS.
#   _quote_ident validates through `_ident`, THEN double-quotes the output label.
#   _key         whitelists the characters a jsonb key may contain. REJECTS.
#   _lit         escapes; it accepts anything and doubles every quote. CONTAINS.
#
# The registry is trusted config, which is exactly the argument that leaves a layer like
# this untested until the day someone pastes a vendor field name into models.yaml. Every
# case below is adversarial, and each asserts that the input is REJECTED or CONTAINED —
# never merely that nothing crashed.

# Rejected by `_ident`. Newlines appear here twice deliberately: Python's `$` matches
# before a SINGLE trailing newline, so a bare `"alpha\n"` is the one shape this pattern
# does not refuse — contained, because nothing may FOLLOW the newline and `registry._model`
# `.strip()`s every tag and field name before `_ident` ever sees one. `alpha\ndrop` and
# `alpha\r\n` are the shapes that could carry something, and both are refused.
_HOSTILE_IDENTS = [
    "", "   ", None, "Alpha", "1alpha", "_alpha", "a b", "a-b", "a.b", "a*",
    'a"b', "a'b", "a;b", "a--b", "a/*b*/", "a\tb", "a\nb", "alpha\ndrop", "alpha\r\n",
    'x"; DROP VIEW cim_web; --', "x'); DROP TABLE events; --", "events WHERE 1=1",
    "álpha", "α", "аlpha",          # latin-1, greek, cyrillic homoglyph
]


@pytest.mark.parametrize("name", _HOSTILE_IDENTS)
def test_ident_rejects_everything_that_is_not_a_bare_lowercase_name(name):
    """`_ident`'s output is interpolated into DDL RAW — `cim_<tag>`, and the tag inside
    `membership_predicate`'s array literal — so the whitelist is the only thing between
    a registry edit and arbitrary DDL. Nothing here may come back."""
    with pytest.raises(CimError):
        cim_sql._ident(name)
    with pytest.raises(CimError):
        cim_sql._quote_ident(name)                 # …and the quoter validates first


def test_ident_accepts_exactly_the_shapes_the_registry_really_uses():
    """The control. A whitelist that rejected everything would pass the test above and
    break every model, so pin what must still get through — including every tag and
    field name the shipped registry actually emits."""
    for good in ("a", "alpha", "a1", "a_1", "vendor_product", "cim_web"):
        assert cim_sql._ident(good) == good
    for model in REGISTRY.models:
        assert cim_sql._ident(model.tag) == model.tag
        for f in model.fields:
            assert cim_sql._ident(f.name) == f.name


def test_quote_ident_quotes_every_label_and_not_just_the_keywords():
    """`user` is why the label quoter exists at all: bare, a later `SELECT user` parses as
    CURRENT_USER, returns the connection role on every row and raises nothing.

    It quotes UNCONDITIONALLY rather than consulting a keyword list, because that list is
    one more thing to keep in step with the server version — so `src`, which needs no
    quoting on any PostgreSQL, is quoted too. That is the decision being pinned here.
    """
    assert cim_sql._quote_ident("user") == '"user"'
    assert cim_sql._quote_ident("src") == '"src"'
    assert cim_sql._quote_ident("vendor_product") == '"vendor_product"'


# Rejected by `_key`. `%` matters beyond SQL: a jsonb key reaches psycopg through the
# LOQL projection, where a bare `%` is read as a placeholder.
_HOSTILE_KEYS = [
    "", None, "k'", 'k"', "k;", "k\\", "k\\'", "k%", "k(", "k)", "{k}",
    "k,j", "k|j", "k\nx", "k\tx", "k=x", "k'||'x", "id.orig_h'); DROP TABLE events; --",
    "évent", "κ",
]


@pytest.mark.parametrize("key", _HOSTILE_KEYS)
def test_key_rejects_every_character_that_could_leave_a_string_literal(key):
    with pytest.raises(CimError):
        cim_sql._key(key)
    with pytest.raises(CimError):
        cim_sql.source_sql(CimSource(kind="raw", paths=((key,),)))
    with pytest.raises(CimError):                  # …and nested, one segment down
        cim_sql.source_sql(CimSource(kind="raw", paths=(("ok", key),)))


@pytest.mark.parametrize("key", ["event_id", "Event ID", "id.orig_h", "x-forwarded-for",
                                 "a/b", "EventID", "9", "_k"])
def test_key_allows_the_punctuation_real_vendor_keys_carry_and_lets_lit_contain_it(key):
    """The other half: dots (Zeek), spaces (`Event ID`), hyphens and slashes are LEGAL,
    and none of them is dangerous — `_lit` puts the key inside a string literal, where
    `--` is not a comment and `-` is not an operator."""
    assert cim_sql._key(key) == key
    assert cim_sql.source_sql(CimSource(kind="raw", paths=((key,),))) == f"(raw ->> '{key}')"


# Accepted by `_lit`, and CONTAINED rather than rejected: a membership value is analyst
# text, and refusing an apostrophe would refuse `o'brien`.
_HOSTILE_LITERALS = [
    "x'; DROP TABLE events; --", "'; DROP TABLE events; --", "') OR true --",
    "o'brien", "it''s", "\\'", "\\", "%s", "%", "a\nb", "a;b", "--", "/*", "*/",
    "' UNION SELECT current_user --", "'' OR ''=''", 4625, 0, None,
]


@pytest.mark.parametrize("value", _HOSTILE_LITERALS)
def test_lit_doubles_every_quote_so_a_value_cannot_end_its_own_literal(value):
    """standard_conforming_strings=on, so doubling the quote is the whole escape — and
    the backslash cases are why that assumption is asserted rather than assumed: with it
    OFF, `\\'` would escape the closing quote and the payload would be code."""
    out = cim_sql._lit(value)
    assert out.startswith("'") and out.endswith("'")
    body = out[1:-1]
    assert "'" not in body.replace("''", "")       # every quote inside is doubled
    assert body.replace("''", "'") == str(value)   # …and nothing else was altered


def test_lit_is_the_only_escape_a_membership_value_gets():
    """The term emitter, end to end: the payload lands inside the literal and the
    `IN (…)` list stays one value per element."""
    term = CimTerm(source=CimSource.column_of("vendor"),
                   values=("o'brien", "x'); DROP TABLE events; --"))
    assert (cim_sql._term_sql(term)
            == "(lower(vendor) IN ('o''brien', 'x''); DROP TABLE events; --'))")


@pytest.mark.parametrize("column", [
    "message; DROP TABLE events", "id) FROM events; DROP TABLE events --",
    "raw", "cim_models", "search_tsv", "1", "src_ip)", "user",
])
def test_a_field_column_must_be_on_the_whitelist(column):
    """`_field_column` interpolates the column name VERBATIM (`host(src_ip)` needs the
    function call), so the whitelist is its only guard."""
    with pytest.raises(CimError):
        cim_sql.field_value_sql(CimField(name="x", source=CimSource.column_of(column)))


@pytest.mark.parametrize("name", ["vendor || ';'", "unknown", "", "current_user",
                                  "concat_ws(':', vendor, product)"])
def test_a_named_expression_must_be_on_the_whitelist(name):
    """`expr:` is a KEY into `_NAMED_EXPR`, never SQL itself — including the case that
    spells the whitelisted snippet out longhand, which must still be refused."""
    with pytest.raises(CimError):
        cim_sql.source_sql(CimSource.expr_of(name))
    assert (cim_sql.source_sql(CimSource.expr_of("vendor_product"))
            == "concat_ws(':', vendor, product)")


def _outside_literals(sql: str) -> str:
    """`sql` with every single-quoted literal removed, scanned the way PostgreSQL (and
    `db.split_statements`) scans one: `''` inside a literal is an escaped quote, not the
    end of it. What comes back is the part of the statement the SERVER would parse as
    code — so a payload that shows up here has escaped its literal."""
    out, i, n = [], 0, len(sql)
    while i < n:
        if sql[i] != "'":
            out.append(sql[i])
            i += 1
            continue
        i += 1                                     # opening quote
        while i < n:
            if sql[i] == "'":
                if sql[i + 1:i + 2] == "'":
                    i += 2
                    continue
                i += 1
                break
            i += 1
    return "".join(out)


def test_a_hostile_registry_cannot_produce_sql_that_escapes_its_own_literal(tmp_path):
    """THE property this layer exists for, asserted end to end over a real registry.

    Every author-controlled string in models.yaml that reaches PostgreSQL as a literal
    carries a different escape payload here. Two emitters take them: `const:` fields
    reach the view DDL `db.init_cim` executes, and membership values reach
    `membership_sql`, the audit predicate the module docstring keeps runnable. Both are
    scanned, because the view's own WHERE is the `cim_models @>` containment form and so
    carries no value at all — a test that looked only at the DDL would be checking the
    escaping of a string that is not there.

    The script must still cut into exactly the statements that were emitted, and no
    payload may appear in the part of it PostgreSQL would parse as code.
    """
    reg = load_yaml(tmp_path, r"""
        version: 1
        models:
          - name: Hostile
            tag: hostile
            version: 1
            description: every quote-escape payload that could reach DDL
            membership:
              - vendor: ["x'; drop table events; --"]
                product: ["'); drop view cim_hostile; --", "o'brien", "it''s"]
              - {raw:id.orig_h: ["' union select current_user --"]}
              - {log_type: ["a\\'b"]}
            fields:
              - {name: pay, const: "x'; DROP TABLE events; --"}
              - {name: sneak, const: "') OR true --"}
              - {name: back, const: "\\'"}
              - {name: user, column: user_name}
        """)
    model = reg.models[0]
    stmts = cim_sql.ddl_statements(reg)
    assert len(stmts) == 2                          # DROP VIEW, CREATE VIEW — nothing else
    audit = f"SELECT count(*) FROM events WHERE {cim_sql.membership_sql(model)}"
    # the terminated script the way `db.init_cim` sends its half, cut by the real
    # splitter: a payload that ended its literal early would add statements here.
    script = "".join(s + ";\n" for s in [*stmts, audit])
    assert len(db.split_statements(script)) == 3
    code = _outside_literals(script).lower()
    # `drop view cim_hostile` and not `drop view`: the script's own first statement is
    # the legitimate `DROP VIEW IF EXISTS cim_hostile`, and the payload spells it bare.
    for payload in ("drop table", "drop view cim_hostile", "union select",
                    "current_user", "or true", "--"):
        assert payload not in code, f"{payload!r} escaped its literal: {code}"
    # …and every payload really is in there, so this cannot pass on empty SQL
    assert "'x''; drop table events; --'" in audit  # value, lower-cased on load
    assert "'a\\''b'" in audit                      # the backslash escape, contained
    assert "'x''; DROP TABLE events; --' AS " + '"pay"' in stmts[1]   # const, case kept
    assert stmts[1].count(" AS ") == 4


# ── the evaluator ─────────────────────────────────────────────────────────────
def test_raw_keys_are_byte_exact_and_case_sensitive():
    """The DELIBERATE divergence from `detection.engine.flatten_event`, which lower-cases
    and dot-joins. jsonb `->>` is byte-exact, so this evaluator must be too."""
    reg = one_model(CimTerm(source=CimSource.raw_of("Hashes"), values=("abc",)))
    assert match.tags_for(evt(raw={"Hashes": "abc"}), reg) == ["t"]
    assert match.tags_for(evt(raw={"hashes": "abc"}), reg) == []
    assert match.tags_for(evt(raw={"HASHES": "abc"}), reg) == []


def test_raw_values_are_compared_case_insensitively():
    """The KEY is byte-exact; the VALUE is not — `lower(<lhs>) IN (...)` on the SQL side."""
    reg = one_model(CimTerm(source=CimSource.raw_of("k"), values=("okta",)))
    assert match.tags_for(evt(raw={"k": "OKTA"}), reg) == ["t"]


@pytest.mark.parametrize("value,hits", [
    (4625, True),            # the int windows_security.py writes back — the whole fix
    ("4625", True),
    (" 4625 ", True),        # Python strips the event value (documented SQL divergence)
    ("04625", False),        # a padded CSV cell is NOT the same event id
    (46250, False),
    (None, False),           # a JSON null never matches
    ({"a": 1}, False),       # a container is never a value
    ([4625], False),
])
def test_raw_value_coercion(value, hits):
    reg = one_model(CimTerm(source=CimSource.raw_of("event_id"), values=("4625",)))
    assert bool(match.tags_for(evt(raw={"event_id": value}), reg)) is hits


def test_bool_raw_value_renders_the_way_jsonb_does():
    """jsonb renders a boolean as 'true'; Python's str() gives 'True'. The mapping is
    spelled out, and `bool` is checked BEFORE `int` because bool subclasses int."""
    reg = one_model(CimTerm(source=CimSource.raw_of("is_write"), values=("true",)))
    assert match.tags_for(evt(raw={"is_write": True}), reg) == ["t"]
    assert match.tags_for(evt(raw={"is_write": False}), reg) == []


def test_a_missing_raw_key_never_matches():
    reg = one_model(CimTerm(source=CimSource.raw_of("event_id"), values=("4625",)))
    assert match.tags_for(evt(raw={}), reg) == []
    assert match.tags_for(evt(), reg) == []


def test_raw_alternatives_coalesce_first_non_null_wins():
    reg = one_model(CimTerm(source=CimSource.raw_of("a", "b"), values=("hit",)))
    assert match.tags_for(evt(raw={"b": "hit"}), reg) == ["t"]          # falls through
    assert match.tags_for(evt(raw={"a": "hit", "b": "miss"}), reg) == ["t"]
    # the first alternative is present but wrong — COALESCE stops there, so no match
    assert match.tags_for(evt(raw={"a": "miss", "b": "hit"}), reg) == []


def test_nested_raw_path_walks_one_object_level_per_segment():
    reg = one_model(CimTerm(source=CimSource.raw_of(("Event", "System", "EventID")),
                            values=("4688",)))
    assert match.tags_for(
        evt(raw={"Event": {"System": {"EventID": 4688}}}), reg) == ["t"]
    # a scalar on the way down ends that alternative with no value, as jsonb yields NULL
    assert match.tags_for(evt(raw={"Event": "oops"}), reg) == []
    assert match.tags_for(evt(raw={"Event": {"System": None}}), reg) == []


def test_a_clause_is_an_and_of_its_terms():
    reg = one_model(CimTerm(source=CimSource.column_of("vendor"), values=("okta",)),
                    CimTerm(source=CimSource.column_of("product"), values=("system-log",)))
    assert match.tags_for(evt(vendor="okta", product="system-log"), reg) == ["t"]
    assert match.tags_for(evt(vendor="okta", product="workflows"), reg) == []
    assert match.tags_for(evt(vendor="okta"), reg) == []


def test_a_model_is_an_or_of_its_clauses():
    model = CimModel(
        name="T", tag="t", version=1, description="",
        clauses=(CimClause(terms=(CimTerm(source=CimSource.column_of("vendor"),
                                          values=("okta",)),)),
                 CimClause(terms=(CimTerm(source=CimSource.column_of("log_type"),
                                          values=("signin",)),))),
        fields=(CimField(name="user", source=CimSource.column_of("user_name")),))
    reg = CimRegistry(version=1, models=(model,))
    assert match.tags_for(evt(vendor="okta"), reg) == ["t"]
    assert match.tags_for(evt(vendor="acme", log_type="signin"), reg) == ["t"]
    assert match.tags_for(evt(vendor="acme", log_type="conn"), reg) == []


def test_an_empty_clause_matches_nothing_through_both_paths():
    """NOT Python's vacuous `all(())` truth. `registry.load` cannot produce an empty
    clause, so this only bites a hand-built registry — where tagging every event in the
    store is much the worse failure."""
    model = CimModel(name="T", tag="t", version=1, description="",
                     clauses=(CimClause(terms=()),),
                     fields=(CimField(name="user", source=CimSource.column_of("user_name")),))
    assert match.clause_matches(model.clauses[0], evt()) is False
    assert match.model_matches(model, evt()) is False
    assert match.tags_for(evt(), CimRegistry(version=1, models=(model,))) == []


def test_a_model_with_no_clauses_matches_nothing():
    model = CimModel(name="T", tag="t", version=1, description="", clauses=(),
                     fields=(CimField(name="user", source=CimSource.column_of("user_name")),))
    assert match.model_matches(model, evt()) is False
    assert match.tags_for(evt(), CimRegistry(version=1, models=(model,))) == []


def test_tags_for_is_sorted_and_stable_under_model_reordering():
    """`@>` containment is order-insensitive, so nothing depends on registry order — and
    an alphabetical array keeps a backfill re-run byte-identical after a cosmetic edit."""
    a = CimClause(terms=(CimTerm(source=CimSource.column_of("vendor"), values=("acme",)),))
    f = (CimField(name="user", source=CimSource.column_of("user_name")),)
    zed = CimModel(name="Zed", tag="zed", version=1, description="", clauses=(a,), fields=f)
    abe = CimModel(name="Abe", tag="abe", version=1, description="", clauses=(a,), fields=f)
    forward = match.tags_for(evt(), CimRegistry(version=1, models=(zed, abe)))
    reverse = match.tags_for(evt(), CimRegistry(version=1, models=(abe, zed)))
    assert forward == reverse == ["abe", "zed"]


def test_an_unmatched_event_keeps_the_gin_index_sparse():
    """`tags_for` says [] but `cim_models_for` — the value `db._row` binds — says NULL, so
    an untagged row contributes no entries to the GIN index on `cim_models`."""
    e = evt(vendor="nobody", log_type="nothing")
    assert match.tags_for(e) == []
    assert match.cim_models_for(e) is None
    assert match.cim_models_for(evt(log_type="conn")) == ["network"]


# Everything a parser, a hand-built event or a stored row could put in `raw` that is not
# a jsonb object. `raw` is typed `dict` on NormalizedEvent, so every one of these is a
# defect somewhere upstream — and none of them may cost the ingest chunk it arrives in.
_MALFORMED_RAW = [None, "a string", ["a", "list"], 7, 0, "", 3.5, True]


@pytest.mark.parametrize("raw", _MALFORMED_RAW)
def test_a_malformed_raw_never_raises(raw):
    """One bad event must not abort a 5000-event ingest chunk.

    The event has to REACH a `raw:` term for this to be testing anything. Membership is
    resolved per event as `_column_texts` + `_raw_of`, and `_raw_of`'s
    `isinstance(raw, Mapping)` guard is the whole defence — but `_raw_value` is only
    called by a term that reads jsonb, so evaluated on a column-only event
    (`log_type=conn`, whose Network clauses are pure column terms) the guard is never
    reached and deleting it changes nothing.

    vendor/product/log_type below put the event on the three Windows Security clauses
    (Authentication / Endpoint / Change), each of which reads `raw:event_id` — so every
    value here is walked, and every one has to come back as "no value" rather than as an
    AttributeError out of `db._row` mid-flush.
    """
    e = evt(vendor="microsoft", product="windows", log_type="security", raw=raw)
    assert match.tags_for(e) == []                  # no event_id, so no clause completes
    assert match.tags_for(row_of(e)) == []          # ...and the same through the Mapping arm
    assert match.model_matches(REGISTRY.by_name("Authentication"), e) is False
    # not raising is not the same as swallowing the event: the columns still decide every
    # model they can decide on their own.
    assert match.tags_for(evt(log_type="conn", raw=raw)) == ["network"]


def test_a_hostile_str_on_a_raw_value_never_raises():
    class Boom:
        def __str__(self):                                    # noqa: D105
            raise RuntimeError("boom")

    reg = one_model(CimTerm(source=CimSource.raw_of("k"), values=("x",)))
    assert match.tags_for(evt(raw={"k": Boom()}), reg) == []


def test_an_object_with_no_raw_attribute_never_raises():
    class Bare:
        vendor = "acme"

    assert match.tags_for(Bare()) == []


def test_a_malformed_registry_does_raise():
    """The asymmetry is deliberate: a bad event is data, a bad registry is a deployment
    defect, and a data model that silently matches nothing is the failure this backbone
    exists to remove."""
    with pytest.raises(CimError):
        match.tags_for(evt(), one_model(
            CimTerm(source=CimSource.column_of("message"), values=("x",))))
    with pytest.raises(CimError):
        match.tags_for(evt(), one_model(
            CimTerm(source=CimSource.const_of("x"), values=("x",))))
    with pytest.raises(CimError):
        match.tags_for(evt(), one_model(
            CimTerm(source=CimSource.column_of("vendor"), values=())))


def test_a_stored_row_evaluates_identically_to_the_parsed_event():
    """The `db.backfill_cim` path: one evaluator serves ingest and backfill, so a
    re-derived row must be byte-identical to the freshly ingested one."""
    e = evt(vendor="microsoft", product="windows", log_type="security",
            raw={"event_id": 4625})
    assert match.tags_for(e) == ["authentication"]
    assert match.tags_for(row_of(e)) == match.tags_for(e)
    # a row selected WITHOUT `raw` silently matches no raw: term — hence `_CIM_BACKFILL_COLS`
    stripped = row_of(e)
    stripped.pop("raw")
    assert match.tags_for(stripped) == []


# ── model reachability ────────────────────────────────────────────────────────
# One hand-built event per shipped model. A model no event can ever match is the exact
# failure Backbone #2 was built to fix, so every tag in the registry needs a row here.
_REACHABLE: dict[str, dict[str, Any]] = {
    "authentication": {"vendor": "okta", "product": "system-log"},
    "network":        {"log_type": "conn"},
    "web":            {"log_type": "access"},
    "dns":            {"log_type": "dns"},
    "endpoint":       {"vendor": "microsoft", "product": "sysmon"},
    "change":         {"vendor": "github", "product": "audit"},
    "malware":        {"vendor": "crowdstrike", "product": "falcon",
                       "log_type": "detection"},
    "ids":            {"log_type": "alert"},
    "ics":            {"log_type": "modbus"},
    "email":          {"log_type": "exchange"},
    "vulnerability":  {"vendor": "qualys", "log_type": "vulnerability"},
}


@pytest.mark.parametrize("tag", sorted(_REACHABLE))
def test_every_shipped_model_is_reachable(tag):
    e = evt(**_REACHABLE[tag])
    assert tag in match.tags_for(e)
    assert match.model_matches(REGISTRY.by_name(tag), e)


def test_the_reachability_table_covers_the_whole_registry():
    """A new model in models.yaml must arrive with an event that reaches it."""
    assert sorted(_REACHABLE) == sorted(REGISTRY.tags)


def test_an_ot_event_is_both_network_and_industrial():
    """Decision 3: the nine OT protocols are network sessions AND control-plane activity."""
    assert match.tags_for(evt(log_type="modbus")) == ["ics", "network"]


# ── the sample corpus ─────────────────────────────────────────────────────────
# Measured, not asserted: every file below was parsed by the parser `app.detect` picks
# for it and tagged by `match.tags_for`. The value is (the distinct model tags the file's
# events carry, how many of its events carry no tag at all). A registry edit that breaks
# a source therefore names the source.
_GOLDEN: dict[str, tuple[tuple[str, ...], int]] = {
    "aws_cloudtrail.json":        (("authentication", "change"), 0),
    "aws_guardduty.json":         (("ids",), 0),
    # The three ASFF log_types fan out to three models: Compliance.Status -> config
    # -> Change, a non-empty Vulnerabilities[] -> vulnerability -> Vulnerability,
    # everything else -> threat -> IDS.
    "aws_securityhub.json":       (("change", "ids", "vulnerability"), 0),
    "azure_activity.json":        (("change",), 0),
    "cef.log":                    (("ids", "network", "web"), 0),
    "cisco_asa.log":              (("authentication", "network"), 0),
    # FTD carries the EVENT CLASS in log_type (connection / intrusion / file-transfer
    # / malware), which is what lets the generic clauses reach several models; every
    # event is also a Network member through {vendor: cisco, product: firepower}.
    # NOT an Endpoint member: 430004 used to spell its log_type `file`, the bare token
    # the Endpoint clause carries for a FIM source's ECS event.category, so an inline
    # NETWORK file-transfer observation joined a model described as "host telemetry
    # from EDR/Sysmon/auditd/FIM" — with `dvc` set to the firewall and every process
    # and registry field null. It also split the two file-policy events arbitrarily,
    # 430004 in Endpoint and its sibling 430005 not. `file-transfer` ends both.
    "cisco_ftd.log":              (("ids", "malware", "network"), 0),
    "cisco_ios.log":              (("authentication", "network"), 0),
    # Cortex Data Lake records reshaped into a PAN CSV export, so they ride
    # paloalto_csv and land exactly where PAN-OS logs land.
    "cortex_prisma_access.csv":   (("ids", "malware", "network", "web"), 0),
    "crowdstrike_detections.csv": (("endpoint", "malware"), 0),
    "crowdstrike_events.json":    (("endpoint", "malware"), 0),
    # Defender XDR routes on serviceSource: endpoint/xdr -> Endpoint, identity ->
    # Authentication, email -> Email (the alert that finally populates that model),
    # and the Ransomware-category endpoint alert is additionally a Malware member.
    # The 1 untagged is the INCIDENT record, and it is deliberate rather than a gap.
    # An incident is a correlation object, not telemetry; with $expand=alerts on, the
    # parser emits each nested alert as its own event, which lands in Endpoint/Malware
    # on its own merits — so no evidence is lost by leaving the wrapper untagged. The
    # sample carries an expanded incident specifically so this is MEASURED here: the
    # corpus previously held only alerts, i.e. it could not see the default output of
    # the shipped `defender_incidents` collector at all.
    "defender_xdr.json":          (("authentication", "email", "endpoint",
                                    "malware"), 1),
    "entra_signin.json":          (("authentication",), 0),
    "fortinet_fortigate.log":     (("authentication", "ids", "network"), 0),
    "gcp_audit.json":             (("change",), 0),
    # #2 is a schemaless flow record with no type/category key at all — log_type is NULL,
    # so no term can match it by construction.
    "generic_json.json":          (("endpoint",), 1),
    # the local0 "Service started successfully" line: an application syslog message on a
    # non-security facility, with no security semantics to key on.
    "generic_syslog.log":         (("authentication",), 1),
    "github_audit.json":          (("change",), 0),
    "gitlab_audit.json":          (("change",), 0),
    # Tripwire cat=Correlation is a cross-source meta-alert; Splunk models those in its
    # `Alerts` data model, which this registry deliberately does not have.
    "leef.log":                   (("authentication", "endpoint", "network"), 1),
    "linux_auditd.log":           (("authentication", "endpoint"), 0),
    "m365_audit.json":            (("authentication", "change"), 0),
    "meraki.log":                 (("ids", "network", "web"), 0),
    # A saved decode from the NetFlow/IPFIX receiver, re-uploaded — the path the
    # detect.py "netflow" rule exists for (the live receiver names its format).
    "netflow.json":               (("network",), 0),
    "nutanix_files.log":          (("endpoint",), 0),
    "nutanix_pc.log":             (("change", "network"), 0),
    "okta_system_log.json":       (("authentication",), 0),
    "paloalto_syslog.log":        (("change", "ids", "network"), 0),
    "paloalto_traffic.csv":       (("ids", "network"), 0),
    "qualys_detection.xml":       (("vulnerability",), 0),
    "rapid7_insightvm.json":      (("vulnerability",), 0),
    "suricata_eve.json":          (("dns", "ids", "web"), 0),
    "sysmon.json":                (("dns", "endpoint"), 0),
    "tenable_vulns.json":         (("vulnerability",), 0),
    "web_access.log":             (("web",), 0),
    "windows_security.csv":       (("endpoint",), 0),
    "windows_security.json":      (("authentication",), 0),
    "zeek_cip.json":              (("ics", "network"), 0),
    "zeek_conn.log":              (("dns", "network"), 0),
    "zeek_dnp3.log":              (("ics", "network"), 0),
    "zeek_json.json":             (("dns", "network"), 0),
    "zeek_modbus.log":            (("ics", "network"), 0),
    "zeek_s7comm.log":            (("ics", "network"), 0),
}

# Members per model over the corpus. As of the Phase-2 onboarding wave EVERY model has
# members: `vulnerability` went 0 -> 10 (Qualys / Tenable / Rapid7 / AWS Inspector via
# Security Hub) and `email` 0 -> 1 (the Defender for Office 365 alert), so the two
# "EMPTY BY DESIGN" pins are gone and `test_every_model_has_at_least_one_member` below
# is now a real assertion rather than an aspiration.
_MEMBERS = {"authentication": 16, "network": 44, "web": 7, "dns": 4, "endpoint": 22,
            "change": 18, "malware": 9, "ids": 14, "ics": 11, "email": 1,
            "vulnerability": 10}

_CORPUS_EVENTS = 133
_CORPUS_UNTAGGED = 4
# It was 29/97 (30%) before the Backbone #2 registry work, 3/97 (3.1%) after it, and is
# 4/133 (3.0%) now. The 4th is the Defender incident wrapper added to close a corpus
# blind spot — a shipped collector whose default output no measurement could see. The
# threshold is the ceiling a regression may not cross, not the achievement.
_MAX_UNTAGGED_FRACTION = 0.05

_corpus_cache: Optional[dict[str, list[NormalizedEvent]]] = None


def corpus() -> dict[str, list[NormalizedEvent]]:
    """Every sample file parsed by the parser `app.detect` picks for it, memoized.

    Deliberately routed through `detect_format` rather than a hand-written filename ->
    parser map: this is the same path an uploaded file takes, so a detection regression
    shows up here too.
    """
    global _corpus_cache
    if _corpus_cache is None:
        out: dict[str, list[NormalizedEvent]] = {}
        for path in sorted(SAMPLES.iterdir()):
            if path.is_dir():
                continue
            text = path.read_text(encoding="utf-8")
            fmt = detect_format(path.name, text)
            assert fmt in PARSERS, f"{path.name}: detect_format returned {fmt!r}"
            out[path.name] = list(PARSERS[fmt].parse(text))
        _corpus_cache = out
    return _corpus_cache


def corpus_tags() -> list[tuple[str, NormalizedEvent, list[str]]]:
    return [(name, e, match.tags_for(e))
            for name, events in corpus().items() for e in events]


def test_the_golden_map_covers_every_shipped_sample():
    """A new sample file must arrive with its expected tags, or it could silently be
    untagged and only move the aggregate percentage."""
    assert sorted(corpus()) == sorted(_GOLDEN)


@pytest.mark.parametrize("name", sorted(_GOLDEN))
def test_sample_source_tags(name):
    tagged = [match.tags_for(e) for e in corpus()[name]]
    seen = tuple(sorted({t for tags in tagged for t in tags}))
    untagged = sum(1 for tags in tagged if not tags)
    assert (seen, untagged) == _GOLDEN[name]


def test_at_least_eight_models_are_populated_by_existing_parsers():
    """The roadmap's Phase-1 exit criterion, verbatim: ">=8 CIM models populated by
    existing parsers" (docs/SPLUNK_TRANSFORMATION_ROADMAP.md)."""
    populated = {t for _, _, tags in corpus_tags() for t in tags}
    assert len(populated) >= 8, sorted(populated)


def test_every_shipped_model_has_at_least_one_corpus_member():
    """The Phase-2 exit criterion, and stronger than the reachability test above.

    `test_every_shipped_model_is_reachable` proves a model can be matched by a
    HAND-BUILT event; this proves a REAL parser, over a real vendor document, emits
    one. Email and Vulnerability were pinned at 0 until the Defender XDR and
    Qualys/Tenable/Rapid7/Security-Hub sources onboarded — a model with no member is
    a schema nobody has ever filled, which is exactly what CIM Backbone #2 exists to
    prevent, so it is asserted rather than left to the per-model counts.
    """
    populated = {t for _, _, tags in corpus_tags() for t in tags}
    assert sorted(populated) == sorted(REGISTRY.tags)


def test_the_untagged_fraction_stays_under_the_threshold():
    rows = corpus_tags()
    untagged = [(name, e.vendor, e.log_type) for name, e, tags in rows if not tags]
    assert len(rows) == _CORPUS_EVENTS
    assert len(untagged) == _CORPUS_UNTAGGED, untagged
    assert len(untagged) / len(rows) <= _MAX_UNTAGGED_FRACTION


@pytest.mark.parametrize("tag", sorted(_MEMBERS))
def test_corpus_member_count_per_model(tag):
    assert sum(1 for _, _, tags in corpus_tags() if tag in tags) == _MEMBERS[tag]


def test_the_compiled_plan_agrees_with_the_reference_walk_on_every_sample():
    """THE anti-divergence guard. `tags_for` walks a compiled plan and `model_matches`
    the readable spec; they share `_term_hit`, but only this keeps the AND/OR nesting —
    written twice — from drifting."""
    for name, e, tags in corpus_tags():
        reference = sorted(m.tag for m in REGISTRY.models if match.model_matches(m, e))
        assert tags == reference, f"{name}: compiled {tags} != reference {reference}"


def test_a_stored_row_agrees_with_the_parsed_event_on_every_sample():
    """The backfill path over the whole corpus — `db.backfill_cim` re-derives from a row,
    and a re-derived row that disagreed with the ingested one would be invisible drift."""
    for name, e, tags in corpus_tags():
        assert match.tags_for(row_of(e)) == tags, name


# ── the specific blockers Backbone #2 fixed ───────────────────────────────────
def test_windows_logon_events_reach_authentication():
    """Decision 2. The three `raw:event_id` clauses were DEAD until windows_security.py
    wrote the normalized id back into the record."""
    events = corpus()["windows_security.json"]
    ids = [e.raw.get("event_id") for e in events]
    assert ids == [4625, 4624] and all(isinstance(i, int) for i in ids)
    assert all(match.tags_for(e) == ["authentication"] for e in events)


def test_windows_process_creation_reaches_endpoint():
    e = corpus()["windows_security.csv"][0]
    assert e.raw.get("event_id") == 4688
    assert match.tags_for(e) == ["endpoint"]


def test_palo_alto_traffic_reaches_network_despite_the_subtype_in_log_type():
    """paloalto_*.py put the PAN *subtype* (end / deny) in log_type, so the clause has to
    read the real TYPE out of raw — syslog keeps it under `log_type`/`type`, the CSV
    export header is `Type`."""
    for name in ("paloalto_syslog.log", "paloalto_traffic.csv"):
        traffic = [e for e in corpus()[name] if e.log_type in ("end", "deny")]
        assert traffic, name
        for e in traffic:
            assert match.tags_for(e) == ["network"], (name, e.log_type)


def test_palo_alto_ips_threats_are_ids_and_not_vulnerability():
    """A firewall IPS detection is not a scanner finding. The old bare
    `{log_type: [vulnerability]}` clause captured every PAN THREAT alert."""
    threats = [e for name in ("paloalto_syslog.log", "paloalto_traffic.csv")
               for e in corpus()[name] if e.log_type == "vulnerability"]
    assert len(threats) == 2
    for e in threats:
        assert match.tags_for(e) == ["ids"]


@pytest.mark.parametrize("name", ["zeek_modbus.log", "zeek_dnp3.log",
                                  "zeek_s7comm.log", "zeek_cip.json"])
def test_ot_protocol_logs_reach_both_network_and_industrial(name):
    events = corpus()[name]
    assert events
    for e in events:
        assert match.tags_for(e) == ["ics", "network"], (name, e.log_type)
        assert isinstance(e.raw.get("ot"), dict)          # the nested source Industrial reads


def test_no_flow_record_lands_in_email():
    """The deleted `{app: [smtp, smtps, submission]}` clause filled Email with firewall
    flows whose sender/recipient/subject were all null.

    Email USED to be asserted empty, because an empty model was the only way to state
    "no flow record is in here". It has real members now (Defender for Office 365), so
    the assertion is the guarantee itself rather than its proxy: every member must
    carry mail semantics. A firewall flow has no subject, sender or recipient by
    construction, so re-adding an `app:`-style clause fails this immediately.
    """
    members = [(name, e) for name, e, tags in corpus_tags() if "email" in tags]
    assert members, "Email has no members; it is supposed to be populated"
    for name, e in members:
        mail = [e.raw.get(k) for k in ("subject", "sender", "from",
                                       "recipient", "to")]
        assert any(v for v in mail), (name, e.vendor, e.log_type, sorted(e.raw))


def _project(model, e):
    """Resolve every declared field of `model` over `e`, the way the SQL view does."""
    out = {}
    for f in model.fields:
        s, v = f.source, None
        if s.kind == "column":
            v = getattr(e, s.name, None)
        elif s.kind == "raw":
            for path in s.paths:
                cur = e.raw
                for seg in path:
                    cur = cur.get(seg) if isinstance(cur, dict) else None
                    if cur is None:
                        break
                if cur is not None:
                    v = cur
                    break
        elif s.kind == "const":
            v = s.name
        elif s.kind == "expr":
            v = f"{e.vendor}:{e.product}"
        out[f.name] = v
    return out


def test_the_vulnerability_model_projects_real_values_from_the_scanner_corpus():
    """Honesty rule 4 on the model that was empty until Phase 2.

    Every declared field must be provided by SOME member — a mapping no member can
    fill is null-by-construction and models.yaml deletes it rather than shipping it.
    `user` was deleted for exactly that reason (a scanner finding has no acting
    account) and `cvss` was added for the opposite one, so both directions are pinned
    here: without this, dropping the `cvss` mapping breaks no test at all.
    """
    model = REGISTRY.by_name("vulnerability")
    members = [e for _, e, tags in corpus_tags() if "vulnerability" in tags]
    assert len(members) >= 10, len(members)
    filled = {k for e in members for k, v in _project(model, e).items()
              if v not in (None, "")}
    declared = {f.name for f in model.fields}
    assert declared - filled == set(), sorted(declared - filled)
    assert "cvss" in filled and "cve" in filled
    # The deleted mapping stays deleted: no member could ever fill it.
    assert "user" not in declared
    assert not any(e.user_name for e in members)


def test_the_email_model_projects_real_values_for_the_defender_member():
    """The Email model went from zero members to one; prove it is not a null row.

    A member whose subject/recipient/sender are all null would satisfy the membership
    test above while leaving the model exactly as useless as it was when empty.
    """
    model = REGISTRY.by_name("email")
    members = [e for _, e, tags in corpus_tags() if "email" in tags]
    assert members
    filled = {k for e in members for k, v in _project(model, e).items()
              if v not in (None, "")}
    assert {"subject", "recipient", "src_user", "action", "signature"} <= filled, \
        sorted(filled)


def test_zeek_dotted_keys_survive_the_whole_pipeline():
    """End-to-end proof of the no-dot-split rule against real parser output."""
    conn = corpus()["zeek_conn.log"][0]
    assert "id.orig_h" in conn.raw
    assert match.tags_for(conn) == ["network"]


# ── store + DDL seams (no database) ───────────────────────────────────────────
def test_row_carries_cim_models_for_a_matching_event():
    e = evt(vendor="microsoft", product="windows", log_type="security",
            raw={"event_id": 4625})
    assert db._row(e, 1)["cim_models"] == ["authentication"]


def test_row_binds_null_not_empty_array_for_an_unmatched_event():
    """NULL keeps the GIN index proportional to tagged rows. `backfill_cim` re-derives
    through the same `cim_models_for`, so a corrected row matches an ingested one."""
    assert db._row(evt(vendor="nobody", log_type="nothing"), 1)["cim_models"] is None


def test_insert_names_cim_models_and_stays_placeholder_aligned():
    """The guard that catches the next column added to one half only."""
    cols = re.search(r"INSERT INTO events \((.*?)\)", db._INSERT, re.S).group(1)
    columns = [c.strip() for c in cols.split(",")]
    params = re.findall(r"%\((\w+)\)s", db._INSERT)
    assert "cim_models" in columns
    assert "%(cim_models)s::text[]" in db._INSERT
    assert len(columns) == len(params) == 22
    assert set(params) == set(db._row(evt(), 1))


# ── the resolved-tags hand-off (pipeline -> db) ───────────────────────────────
# `tags_for` used to run TWICE per ingested event: once for the detection `datamodels:`
# gate as the event streams, once in `db._row` when the chunk flushes. The pipeline now
# resolves it once and threads it to both consumers. These pin the db half of that
# contract — the pipeline half is in test_pipeline.py, the engine half in test_detection.py.
def insert_conn():
    """Just enough connection for `insert_events` — captures the rows it binds."""
    class FakeCursor:
        def __init__(self, sink): self.sink = sink
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def executemany(self, sql, rows): self.sink.extend(rows)

    class FakeConn:
        def __init__(self): self.rows: list = []
        def execute(self, *a, **k): return self       # ensure_partitions
        def cursor(self): return FakeCursor(self.rows)

    return FakeConn()


def test_row_uses_threaded_tags_instead_of_walking_the_registry(monkeypatch):
    """A threaded value must be USED, not merely accepted — otherwise the hand-off is
    dead code and the walk still happens twice."""
    monkeypatch.setattr(match, "tags_for", _never_called)
    e = evt(vendor="microsoft", product="windows", log_type="security",
            raw={"event_id": 4625})
    assert db._row(e, 1, frozenset({"authentication"}))["cim_models"] == ["authentication"]


def test_row_resorts_threaded_tags_so_stored_arrays_stay_alphabetical():
    """The pipeline holds a frozenset, whose iteration order is arbitrary.
    `events.cim_models` must stay sorted however it was produced, or `backfill_cim`
    rewrites every heap tuple it re-derives for no visible reason."""
    stored = db._row(evt(), 1, frozenset({"web", "authentication", "network"}))
    assert stored["cim_models"] == ["authentication", "network", "web"]


def test_row_without_threaded_tags_still_derives_them_itself():
    """Every caller outside `insert_events` omits the argument — the backfill, the tests,
    an ingest path that never ran detection. They must keep working unchanged."""
    e = evt(vendor="microsoft", product="windows", log_type="security",
            raw={"event_id": 4625})
    assert db._row(e, 1)["cim_models"] == ["authentication"]


def test_insert_events_threads_each_events_own_tags():
    """Index alignment is the whole contract: `cim_tags[i]` belongs to `events[i]`."""
    conn = insert_conn()
    a, b = evt(vendor="a"), evt(vendor="b")
    db.insert_events(conn, [a, b], 7,
                     cim_tags=[frozenset({"web"}), frozenset({"network"})])
    assert [r["cim_models"] for r in conn.rows] == [["web"], ["network"]]


def test_insert_events_derives_the_positions_left_unresolved():
    """`None` at a position means "the pipeline could not resolve this one" — that row
    derives its own membership rather than being stored untagged."""
    conn = insert_conn()
    member = evt(vendor="microsoft", product="windows", log_type="security",
                 raw={"event_id": 4625})
    db.insert_events(conn, [member, evt()], 7, cim_tags=[None, frozenset({"web"})])
    assert [r["cim_models"] for r in conn.rows] == [["authentication"], ["web"]]


def test_insert_events_rejects_a_misaligned_tag_list():
    """Truncating or shifting would be invisible in the stored data: every row after a
    missing entry would silently inherit its neighbour's tags."""
    conn = insert_conn()
    with pytest.raises(ValueError, match="index-aligned"):
        db.insert_events(conn, [evt(), evt()], 7, cim_tags=[frozenset({"web"})])


def test_insert_events_without_tags_is_unchanged():
    """The three-argument call is what an older build, a test double and `_accepts`'s
    negative branch all make."""
    conn = insert_conn()
    e = evt(vendor="microsoft", product="windows", log_type="security",
            raw={"event_id": 4625})
    db.insert_events(conn, [e], 7)
    assert conn.rows[0]["cim_models"] == ["authentication"]


def test_threaded_tags_do_not_hide_a_broken_registry(monkeypatch):
    """The honesty property. The pipeline threads None (not an empty set) when its own
    resolution raises, so the failure lands here and is COUNTED. Threading a confident
    `frozenset()` instead would leave /health reading zero untagged events while every
    row went in with no tags."""
    monkeypatch.setattr(match, "tags_for", _boom)
    db.reset_cim_write_state()
    try:
        assert db._row(evt(), 1, None)["cim_models"] is None
        assert db.cim_write_state()["failures"] == 1
    finally:
        db.reset_cim_write_state()


# ── the compiled plan's column narrowing ──────────────────────────────────────
# `_column_texts` coerces event columns up front, once each, because a registry walk asks
# for the same value many times. It used to coerce all nine columns a term MAY read; the
# plan now carries only the columns some term actually READS (four, for the shipped
# registry). The saving is real but the failure mode is silent: a column left out of the
# set resolves to "no value" and kills its term, which is dead membership — the exact
# thing this backbone exists to remove. These are the guard.
def test_plan_columns_are_exactly_the_columns_its_terms_read():
    """The safety contract, asserted against the live registry: never a column short."""
    plan = match._plan(REGISTRY)
    read = {t.column for _, clauses in plan.models for terms in clauses
            for t in terms if t.column}
    assert set(plan.columns) == read, (
        f"plan.columns is {sorted(plan.columns)} but its terms read {sorted(read)}; a "
        "column short of the truth silently kills every term that reads it")
    assert read <= cim_sql._TERM_COLUMNS, "a term reads a column SQL would refuse"
    assert plan.columns == tuple(sorted(plan.columns)), "not deterministic"


def test_plan_columns_narrow_to_what_the_registry_uses():
    """The point of the narrowing. If this ever equals all nine again, the plan is
    coercing values nothing will ask for, twice per event, per column."""
    assert set(match._plan(REGISTRY).columns) == {"action", "log_type", "product",
                                                 "vendor"}
    assert len(match._TERM_COLUMN_NAMES) == 9        # the un-narrowed default


def test_plan_columns_follow_a_registry_that_reads_something_else():
    """Narrowing must be derived, not hard-coded — a registry reading `user_name` has to
    get `user_name` coerced, or its term reads None and the model matches nothing."""
    reg = one_model(CimTerm(source=CimSource.column_of("user_name"),
                            values=("alice",), label="u"))
    assert match._plan(reg).columns == ("user_name",)
    assert match.tags_for(evt(user_name="Alice"), reg) == ["t"]


def test_a_registry_of_only_raw_terms_narrows_to_no_columns():
    """`_column_texts` must return an empty mapping rather than fall back to all nine."""
    reg = one_model(CimTerm(source=CimSource.raw_of(("event_id",)),
                            values=("4625",), label="r"))
    assert match._plan(reg).columns == ()
    assert match.tags_for(evt(raw={"event_id": 4625}), reg) == ["t"]


def test_compiled_and_reference_walks_agree_on_the_whole_corpus():
    """The narrowed compiled path (four columns) against the reference walk (all nine),
    over every sample event. Two implementations of one rule drift silently; this is what
    catches it."""
    for name, e, tags in corpus_tags():
        ref = sorted(m.tag for m in REGISTRY.models if match.model_matches(m, e))
        assert ref == tags, (
            f"{name}: the reference walk says {ref} and the compiled plan says {tags}")


# ── plan cache: bounded, and safe to evict from concurrently ──────────────────
def test_plan_cache_eviction_survives_a_concurrent_clear(monkeypatch):
    """`_plan` evicts with a size check and a `next(iter(...))` that are two separate
    steps on an unlocked dict.

    This is the ingest hot path -- INGEST_WORKERS writers plus the threadpool entrants
    behind /upload and /api/ingest -- and a `clear_plan_cache()` landing between the two
    steps left `next` looking at an emptied dict, where a BARE `next` raises
    StopIteration: out of `tags_for`, out of `cim_models_for`, into `db._row` mid-flush,
    over an eviction that did not even need to happen.

    The window is FORCED, not waited for: a dict that reads its size and then parks
    inside `__len__` reproduces exactly the state the racing thread saw. Sleeping and
    hoping would be worse than no test at all on this path.
    """
    import threading

    checked, cleared = threading.Event(), threading.Event()

    class _Tripwire(dict):
        armed = True

        def __len__(self):
            n = super().__len__()               # the size the racing thread read...
            if type(self).armed and n >= match._PLAN_CACHE_MAX:
                type(self).armed = False        # ...trip once, not on the way out
                checked.set()
                assert cleared.wait(10), "the evictor was never released"
            return n                            # ...and still believes, one step later

    monkeypatch.setattr(match, "_plan_cache",
                        _Tripwire((i, (None, None)) for i in range(match._PLAN_CACHE_MAX)))

    reg = one_model(CimTerm(source=CimSource.column_of("vendor"), values=("acme",),
                            label="v"))
    out, errors = [], []

    def compiler():
        try:
            out.append(match._plan(reg))
        except BaseException as exc:            # noqa: BLE001 — reported, not swallowed
            errors.append(exc)

    t = threading.Thread(target=compiler, name="cim-plan")
    t.start()
    assert checked.wait(10), "the evictor never reached its size check"
    match.clear_plan_cache()                    # the dict empties between the two steps
    cleared.set()                               # release BEFORE asserting - never hangs
    t.join(10)

    assert not errors, f"eviction raised on a cache emptied under it: {errors!r}"
    assert not t.is_alive() and len(out) == 1, "the compiler never returned a plan"
    assert match.tags_for(evt(vendor="acme"), reg) == ["t"], "the plan is unusable"


def test_plan_cache_stays_bounded():
    """The eviction still evicts -- a fix for the race above that simply stopped
    evicting would leak one compiled plan per registry the process ever sees."""
    match.clear_plan_cache()
    try:
        for i in range(match._PLAN_CACHE_MAX * 3):
            match._plan(one_model(CimTerm(source=CimSource.column_of("vendor"),
                                          values=(f"acme-{i}",), label="v")))
            assert len(match._plan_cache) <= match._PLAN_CACHE_MAX
    finally:
        match.clear_plan_cache()


# ── registry cache: one parse, however many callers ───────────────────────────
def test_concurrent_cold_start_parses_the_registry_once(monkeypatch):
    """`get_registry()` is the lazy singleton every consumer reaches through, and a cold
    start is genuinely concurrent: INGEST_WORKERS writers arrive via `pipeline` alongside
    /upload, /api/ingest and the workbench. Unlocked, each caller inside the window paid
    a full YAML parse and validation for a result it then threw away.

    The unlocked shape was not incorrect — `_cache` is both the flag and the value, so a
    racing thread saw either None or a complete registry, never a half-built one. This
    pins the cost, not the correctness.
    """
    import threading

    parses, start = [], threading.Event()
    real = cim_registry.load

    def slow_load(*a, **k):
        parses.append(1)
        start.wait(0.5)                       # hold the window open for the racers
        return real(*a, **k)

    monkeypatch.setattr(cim_registry, "load", slow_load)
    monkeypatch.setattr(cim_registry, "_cache", None)
    out, errors = [], []

    def racer():
        try:
            out.append(cim_registry.get_registry())
        except Exception as exc:              # noqa: BLE001 — reported, not swallowed
            errors.append(exc)

    threads = [threading.Thread(target=racer) for _ in range(4)]
    for t in threads:
        t.start()
    start.set()                               # release before any assert — never hangs
    for t in threads:
        t.join(5)

    assert not errors and len(out) == 4
    assert sum(parses) == 1, (
        f"models.yaml was parsed {sum(parses)} times by 4 concurrent first callers")
    assert all(r is out[0] for r in out), "callers got different registry objects"


# ── registry cache: the NEGATIVE half ─────────────────────────────────────────
@pytest.fixture
def registry_cache_reset():
    """Empty BOTH halves of the registry cache around a test, and restore the real one.

    `_failure` is process-global and time-boxed, so a test that arms it and walks away
    poisons every later caller of `get_registry()` for `_FAILURE_TTL_SECONDS` — including
    the module-level `REGISTRY` of any test file imported afterwards. `monkeypatch` cannot
    see the arming (it happens inside the call, not through `setattr`), so the reset is
    explicit and runs in a `finally` on both sides.

    Clearing is what matters and is unconditional; the re-warm is a courtesy and is
    allowed to fail. Fixture teardown order against `monkeypatch` is not something to
    depend on here — if `load` is still patched to raise when this runs, the cache simply
    stays cold and the next caller re-parses, which is the lazy singleton's normal cold
    start. An un-cleared `_failure`, by contrast, would be a real leak.
    """
    cim_registry._cache = cim_registry._failure = None
    try:
        yield
    finally:
        cim_registry._cache = cim_registry._failure = None
        try:
            cim_registry.get_registry()         # re-warm for whatever runs next
        except Exception:                       # noqa: BLE001 — see the docstring
            cim_registry._cache = cim_registry._failure = None


def test_a_broken_registry_is_parsed_once_however_many_events_arrive(monkeypatch,
                                                                    registry_cache_reset):
    """The failure handler must not become the outage.

    `_cache` alone memoizes only success, so a registry that will not parse left it None
    and the NEXT caller re-parsed — and on the degraded write path the next caller is the
    next EVENT (`db._cim_tags` swallows this exception so a broken registry costs the tags
    and never the event, which means the ingest loop calls straight back in). A 27KB YAML
    that fails validation therefore cost a full parse-and-validate per event, serialized
    behind the process-global lock, which is strictly worse than the defect it handles.
    """
    parses = []

    def broken_load(*a, **k):
        parses.append(1)
        raise CimError("models.yaml is broken")

    monkeypatch.setattr(cim_registry, "load", broken_load)
    errors = []
    for _ in range(500):
        with pytest.raises(CimError) as caught:
            cim_registry.get_registry()
        errors.append(caught.value)

    assert sum(parses) == 1, (
        f"a broken models.yaml was parsed {sum(parses)} times by 500 callers")
    assert len(errors) == 500, "every caller must still be told the registry is broken"
    assert all(str(e) == "models.yaml is broken" for e in errors)


def test_the_replayed_failure_is_a_fresh_exception_every_time(monkeypatch,
                                                              registry_cache_reset):
    """The cached exception is never re-`raise`d as the same OBJECT.

    Python appends the raising frames to an exception's own `__traceback__`, so replaying
    one instance to every event on the ingest path would grow that traceback without
    bound — an unbounded leak inside the handler for a defect. The clone has to read
    identically where it is reported: `db._cim_tags` records `f"{type(exc).__name__}:
    {exc}"`, which is the string /health shows.
    """
    monkeypatch.setattr(cim_registry, "load",
                        lambda *a, **k: (_ for _ in ()).throw(CimError("boom")))
    seen = []
    for _ in range(50):
        with pytest.raises(CimError) as caught:
            cim_registry.get_registry()
        seen.append(caught.value)

    assert len({id(e) for e in seen}) == 50, "the same exception object was replayed"
    assert all(type(e) is CimError and str(e) == "boom" for e in seen), (
        "the replay lost the type or the message db._cim_tags reports to /health")
    # `seen[0]` is the ORIGINAL, raised through `load` and so a few frames deeper; every
    # one after it is a clone raised from the same line. Their depths must be CONSTANT —
    # a growing tail is the unbounded leak the clone exists to prevent, and it would show
    # here as depths that climb with the loop counter.
    replays = [len(traceback.extract_tb(e.__traceback__)) for e in seen[1:]]
    assert len(set(replays)) == 1, f"traceback grew across replays: {replays}"
    assert seen[0].__traceback__ is not seen[1].__traceback__


def test_the_negative_entry_expires_so_a_fixed_file_recovers_without_a_restart(
        monkeypatch, registry_cache_reset):
    """Bounded, not permanent: an operator who fixes models.yaml recovers on their own.

    The window is a module constant precisely so this test can collapse it instead of
    waiting on a clock.
    """
    monkeypatch.setattr(cim_registry, "_FAILURE_TTL_SECONDS", 0.0)
    monkeypatch.setattr(cim_registry, "load",
                        lambda *a, **k: (_ for _ in ()).throw(CimError("boom")))
    with pytest.raises(CimError):
        cim_registry.get_registry()

    monkeypatch.undo()                          # the operator fixed the file
    assert cim_registry.get_registry() is not None
    assert cim_registry._failure is None, "a successful load must drop the negative entry"


def test_reload_clears_the_negative_entry_rather_than_answering_out_of_it(
        monkeypatch, registry_cache_reset):
    """`reload()` is the EXPLICIT retry an operator reaches for after fixing the YAML, so
    it must not be served from the failure `get_registry()` remembered."""
    monkeypatch.setattr(cim_registry, "load",
                        lambda *a, **k: (_ for _ in ()).throw(CimError("boom")))
    with pytest.raises(CimError):
        cim_registry.get_registry()
    assert cim_registry._failure is not None, "the failure was not remembered at all"

    monkeypatch.undo()                          # the operator fixed the file
    reg = cim_registry.reload()
    assert reg is not None and cim_registry._failure is None
    assert cim_registry.get_registry() is reg, "reload did not publish what it loaded"


def test_a_failed_reload_re_arms_the_negative_entry(monkeypatch, registry_cache_reset):
    """`reload()` empties both halves before loading, so a load that fails in turn leaves
    the cache cold — and the ingest path is about to start calling `get_registry()` per
    event again. It has to re-arm, or the per-event parse is back."""
    parses = []

    def broken_load(*a, **k):
        parses.append(1)
        raise CimError("still broken")

    monkeypatch.setattr(cim_registry, "load", broken_load)
    with pytest.raises(CimError):
        cim_registry.reload()

    assert cim_registry._failure is not None, "a failed reload left the cache un-armed"
    for _ in range(100):
        with pytest.raises(CimError):
            cim_registry.get_registry()
    assert sum(parses) == 1, (
        f"{sum(parses)} parses after a failed reload — the negative entry was not re-armed")


# ── registry drift: restart-required vs backfill-due ──────────────────────────
@pytest.fixture
def drift_reset():
    """`registry_drift` memoizes the on-disk fingerprint on the file's CONTENT hash, so a
    test that swaps the LOADER instead of the file has to invalidate it by hand. A real
    operator edit changes the content and invalidates the entry by itself."""
    db.reset_registry_disk_cache()
    yield
    db.reset_registry_disk_cache()


def test_registry_drift_is_clean_when_disk_matches_the_loaded_registry(drift_reset):
    assert db.registry_drift()["restart_required"] is False


def test_registry_drift_sees_an_edit_the_running_process_has_not_loaded(monkeypatch,
                                                                       drift_reset):
    """`get_registry()` caches for the process lifetime, so between an operator's edit and
    the restart the live rule and the file are two different things. That window used to
    read as green."""
    edited = one_model(CimTerm(source=CimSource.column_of("vendor"), values=("zzz",),
                               label="v"))
    monkeypatch.setattr(db, "load_registry", lambda *a, **k: edited)
    drift = db.registry_drift()
    assert drift["restart_required"] is True and drift["disk_error"] is None


def test_registry_drift_reports_an_unreadable_file_without_raising(monkeypatch,
                                                                  drift_reset):
    """The admin page that shows this is exactly where someone is told the file is
    broken, so a broken file must not take the page down with it."""
    monkeypatch.setattr(db, "load_registry", _boom)
    drift = db.registry_drift()
    assert drift["restart_required"] is None and "boom" in drift["disk_error"]


def test_registry_drift_does_not_memoize_a_failure(monkeypatch, drift_reset):
    """A broken file is the state an operator is actively fixing. Caching the failure
    would leave the page reporting it after the fix, until a restart."""
    monkeypatch.setattr(db, "load_registry", _boom)
    assert db.registry_drift()["restart_required"] is None
    monkeypatch.undo()                                  # they fixed the file
    assert db.registry_drift()["restart_required"] is False


def test_registry_drift_reparses_only_when_the_file_content_changes(monkeypatch,
                                                                    drift_reset):
    """Parsing models.yaml costs ~88ms and this runs on every /admin and /datamodels
    render, so an unedited file must cost a read and a hash, not a parse."""
    parses = []
    real = db.load_registry

    def counting(*a, **k):
        parses.append(1)
        return real(*a, **k)

    monkeypatch.setattr(db, "load_registry", counting)
    for _ in range(5):
        db.registry_drift()
    assert sum(parses) == 1, (
        f"models.yaml was parsed {sum(parses)} times across 5 unedited drift checks")


def test_ddl_statements_drop_before_create_for_every_model():
    stmts = cim_sql.ddl_statements(REGISTRY)
    assert len(stmts) == 2 * len(REGISTRY.models)
    for i, model in enumerate(REGISTRY.models):
        drop, create = stmts[2 * i], stmts[2 * i + 1]
        assert drop == f"DROP VIEW IF EXISTS cim_{model.tag}"
        assert create.startswith(f"CREATE VIEW cim_{model.tag} AS")


def test_ddl_statements_emit_views_only():
    """Decision 1's structural guard. Membership is a PLAIN `text[]` column declared in
    schema.sql and filled in Python, so no DDL here may touch the table or an index."""
    for stmt in cim_sql.ddl_statements(REGISTRY):
        assert stmt.startswith(("DROP VIEW", "CREATE VIEW")), stmt
        upper = stmt.upper()
        assert "ALTER TABLE" not in upper
        assert "GENERATED" not in upper
        assert "CREATE INDEX" not in upper


@pytest.mark.parametrize("gone", ["generated_expr", "add_column_ddl", "index_ddl"])
def test_the_generated_column_emitters_have_not_come_back(gone):
    """PostgreSQL 16 freezes a generation expression at ADD COLUMN (rewriting it needs
    ALTER COLUMN ... SET EXPRESSION, which is PG17+), and detection needs membership BEFORE
    the INSERT. If one of these reappears, Decision 1 has been quietly reversed."""
    assert not hasattr(cim_sql, gone)


def test_schema_declares_the_column_and_its_gin_index():
    """`sql.index_ddl()` was deleted, so schema.sql is the index's only home."""
    schema = (ROOT / "schema.sql").read_text(encoding="utf-8")
    assert "ADD COLUMN IF NOT EXISTS cim_models text[]" in schema
    assert ("CREATE INDEX IF NOT EXISTS events_cim_models_idx ON events "
            "USING GIN (cim_models)") in schema
    assert "CREATE TABLE IF NOT EXISTS cim_meta" in schema


@pytest.mark.parametrize("existing,expected", [
    (["cim_web", "cim_gone"], ["cim_gone"]),
    (["cimbogus"], []),                       # not our naming shape
    (["CIM_Upper"], []),                      # upper case — a human made this
    (["other_view"], []),
    (["cim_web"], []),
])
def test_orphan_view_diff_only_claims_names_this_module_emits(existing, expected):
    assert db._orphan_cim_views(existing, ["cim_web"]) == expected


def test_orphan_reconciliation_emits_an_explicit_drop():
    """Given a faked pg_views result, the stale view is dropped by name — and only it."""
    class FakeConn:
        def __init__(self, views):
            self.views = [{"viewname": v} for v in views]
            self.sql: list[str] = []

        def execute(self, sql, params=None):
            self.sql.append(sql)
            rows = self.views
            return type("Cur", (), {"fetchall": staticmethod(lambda: rows)})()

        @contextmanager
        def transaction(self):
            yield self

    conn = FakeConn(["cim_web", "cim_gone", "cimbogus"])
    dropped = db._drop_orphan_cim_views(conn, ["cim_web"])
    assert dropped == ["cim_gone"]
    assert "DROP VIEW IF EXISTS cim_gone" in conn.sql
    assert not [s for s in conn.sql if "cim_web" in s or "cimbogus" in s]


def test_backfill_select_reads_every_column_membership_can_test():
    """A row fetched without `raw` matches no `raw:` term and raises nothing, which would
    quietly un-tag every Windows, Sysmon and Zeek event in the store."""
    sql, params = db._cim_backfill_query()
    assert params == {}
    for column in sorted(cim_sql._TERM_COLUMNS) + ["raw", "cim_models", "id", "event_time"]:
        assert re.search(rf"\b{column}\b", sql), column


def test_backfill_select_is_keyset_paginated_and_bounded():
    sql, _ = db._cim_backfill_query()
    assert "id > %(_after)s" in sql
    assert sql.rstrip().endswith("ORDER BY id LIMIT %(_limit)s")


def test_backfill_select_binds_its_time_bounds():
    sql, params = db._cim_backfill_query(since=_T, until=_T)
    assert set(re.findall(r"%\((\w+)\)s", sql)) == {"_after", "_since", "_until", "_limit"}
    assert params == {"_since": _T, "_until": _T}


def test_backfill_update_is_never_an_unqualified_full_table_write():
    """One UPDATE per row, keyed by id, with `event_time` in the predicate purely so the
    planner prunes to the one partition that holds the row."""
    assert db._CIM_UPDATE == ("UPDATE events SET cim_models = %(tags)s::text[] "
                              "WHERE id = %(id)s AND event_time = %(event_time)s")
    for name in dir(db):
        if not name.startswith("_CIM"):
            continue
        value = getattr(db, name)
        if isinstance(value, str) and "UPDATE events" in value:
            assert " WHERE " in value, name


def test_membership_fingerprint_is_stable_and_order_insensitive():
    """It answers exactly one question — is a backfill due? — so it must change when the
    rule set changes and NOT when someone reorders models.yaml."""
    a = cim_registry.load(cim_registry._REGISTRY_PATH)
    b = cim_registry.load(cim_registry._REGISTRY_PATH)
    assert db.cim_membership_fingerprint(a) == db.cim_membership_fingerprint(b)

    shuffled = CimRegistry(version=a.version, models=tuple(reversed(a.models)))
    assert db.cim_membership_fingerprint(shuffled) == db.cim_membership_fingerprint(a)


def test_membership_fingerprint_changes_when_a_clause_is_added():
    base = one_model(CimTerm(source=CimSource.column_of("vendor"), values=("okta",)))
    model = base.models[0]
    wider = CimRegistry(version=1, models=(CimModel(
        name=model.name, tag=model.tag, version=model.version,
        description=model.description,
        clauses=model.clauses + (CimClause(terms=(
            CimTerm(source=CimSource.column_of("log_type"), values=("signin",)),)),),
        fields=model.fields),))
    assert db.cim_membership_fingerprint(base) != db.cim_membership_fingerprint(wider)


def test_membership_fingerprint_ignores_a_fields_only_edit():
    """A `fields:` edit only changes the views, which `init_cim` rebuilds on the next
    boot; it must not claim that every stored `cim_models` value is stale."""
    base = one_model(CimTerm(source=CimSource.column_of("vendor"), values=("okta",)))
    model = base.models[0]
    renamed = CimRegistry(version=1, models=(CimModel(
        name=model.name, tag=model.tag, version=model.version,
        description=model.description, clauses=model.clauses,
        fields=(CimField(name="dvc", source=CimSource.column_of("host_name")),)),))
    assert db.cim_membership_fingerprint(base) == db.cim_membership_fingerprint(renamed)


def test_schema_splits_into_executable_statements():
    """Every chunk this scanner emits must be a real statement, so a bad split cannot
    reach init_schema as a syntax error in the integration job.

    This docstring used to assert a history that did not happen — that `script.split(';')`
    had cut a `--` comment in half, left its tail as bare SQL, and stopped every table
    after that point from being created. It never did: both implementations produce the
    same 77 statements over today's schema.sql and the executable SQL is identical. The
    real position (written up in `db.split_statements`) is a near-miss — schema.sql does
    have a `;` inside a `--` comment in two places, and the naive split survives them only
    because both sit at the end of their line. The assertions below are the point and are
    unchanged; only the story was wrong.
    """
    stmts = db.split_statements(db._SCHEMA)
    assert len(stmts) > 50
    for stmt in stmts:
        code = [ln.strip() for ln in stmt.splitlines()
                if ln.strip() and not ln.strip().startswith("--")]
        assert code, stmt
        assert code[0].upper().startswith(
            ("CREATE", "ALTER", "DROP", "INSERT", "COMMENT", "GRANT", "SET")), code[0]


def test_split_statements_ignores_semicolons_in_comments_and_literals():
    script = ("-- one; two; three\nCREATE TABLE a (x text);\n"
              "INSERT INTO a VALUES ('semi; colon');\n")
    stmts = db.split_statements(script)
    assert len(stmts) == 2
    assert stmts[0].endswith("CREATE TABLE a (x text)")
    assert "'semi; colon'" in stmts[1]


def test_split_statements_handles_the_doubled_quote_escape():
    stmts = db.split_statements("INSERT INTO a VALUES ('it''s; fine'); SELECT 1;")
    assert len(stmts) == 2 and "'it''s; fine'" in stmts[0]


# ── templates ─────────────────────────────────────────────────────────────────
def test_datamodels_template_compiles():
    """A page route is only reachable in the integration job, so compile the template
    here — a stray `{% endif %}` would otherwise surface as a 500 in production."""
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(TEMPLATES)),
                             autoescape=True)
    env.filters["ist"] = lambda value, fmt=None: value      # registered by app.main
    env.get_template("base.html")
    env.get_template("datamodels.html")


def test_the_nav_links_to_the_datamodels_page():
    assert '/datamodels' in (TEMPLATES / "base.html").read_text(encoding="utf-8")
