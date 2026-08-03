# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""LOQL — the piped analytics query language.

The parser + compiler are pure (query text -> AST -> parameterized SQL), so they are
tested here without a database, including the load-bearing security invariant: every
user value is a bound parameter and never appears in the SQL text. One integration
test (skipped unless DB_DSN is set) runs a handful of queries end-to-end.
"""
from __future__ import annotations

import re
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.loql import LoqlError, compile_query, parse
from app.loql import nodes as N
# s0's own column list, read from the compiler rather than restated: the structural
# helpers below expand a `SELECT *` back to the base table, and a test that hard-coded
# the shape would go quietly stale the first time a column was added to `events`.
from app.loql.compiler import _BASE_COLS, _PASSTHRU_COLS


def sql_of(q, **kw):
    sql, params = compile_query(q, **kw)
    return " ".join(sql.split()), params


def assert_bindable(sql: str, params) -> None:
    """The standing guard on every emitted statement — BOTH halves, always together.

    ``sql.count("%s") == len(params)`` catches a dangling or duplicated placeholder, but
    it is completely blind to a *bare* ``%``: psycopg treats ``%`` as the start of a
    placeholder, so ``| eval x = a % b`` reported a contented ``1 == 1`` while psycopg
    refused the statement outright with ``incomplete placeholder: '%'; … use '%%'`` —
    and it refuses the WHOLE statement, so one modulo took every other parameter with it.
    ``sql % tuple(…)`` is the half that sees it (Python's ``%`` operator has the same
    escaping rule as psycopg's placeholder scanner), which is why this helper exists
    rather than the two assertions being re-typed per test: a guard applied ad hoc is a
    guard that is missing exactly where nobody looked.
    """
    assert sql.count("%s") == len(params), f"placeholder/param mismatch in: {sql}"
    sql % tuple("x" for _ in params)                 # raises on a stray or bare `%`


# ── parser ────────────────────────────────────────────────────────────────────
def test_parse_implicit_search_and_pipeline():
    q = parse('vendor=paloalto action=deny | stats count by src_ip | head 5')
    assert isinstance(q.stages[0], N.Search)
    assert isinstance(q.stages[1], N.Stats) and q.stages[1].by == ("src_ip",)
    assert isinstance(q.stages[2], N.Head) and q.stages[2].n == 5


def test_parse_leading_pipe_is_match_all():
    q = parse('| stats count')
    assert isinstance(q.stages[0], N.Search) and q.stages[0].predicate is None


@pytest.mark.parametrize("bad", [
    "", "   ", "| boguscmd", "a | stats count by", "a = = b", "foo | head",
    "x | timechart span=1 count", "x | fields", "x | where",
])
def test_parse_rejects_malformed(bad):
    with pytest.raises(LoqlError):
        compile_query(bad)


# ── the security invariant: user values are ALWAYS bound parameters ───────────
def test_injection_value_is_parameter_never_inline():
    payload = "x'; DROP TABLE events; --"
    sql, params = compile_query(f'user_name="{payload}"')
    assert payload not in sql and "DROP" not in sql
    assert params == [payload]


def test_raw_field_key_is_bound():
    sql, params = sql_of('customfield=42')
    assert "(raw ->> %s)" in sql and params == ["customfield", 42]


def test_glob_becomes_bound_ilike():
    sql, params = sql_of('host_name="web*"')
    assert "ILIKE %s" in sql and params == ["web%"]
    assert "web*" not in sql


# ── search / where / eval ─────────────────────────────────────────────────────
def test_known_column_vs_raw_field():
    sql, params = sql_of('vendor=cisco unknownfield=1')
    assert "(vendor = %s)" in sql                       # known column, direct
    assert "(raw ->> %s)" in sql                        # unknown -> raw jsonb
    assert params == ["cisco", "unknownfield", 1]


def test_time_relative_literal_is_inlined_interval():
    sql, _ = sql_of('_time > "-24h"')
    assert "event_time > (now() - interval '24 hours')" in sql


def test_numeric_comparison_casts():
    sql, params = sql_of('bytes_total > 1000')
    assert "(bytes_total)::double precision > %s" in sql and params == [1000]


def test_fts_bareword():
    sql, params = sql_of('failed')
    assert "search_tsv @@ plainto_tsquery('simple', %s)" in sql and params == ["failed"]


def test_where_and_eval_functions():
    sql, params = sql_of('a=1 | where length(user_name) > 3 | eval tag = lower(vendor)')
    assert "length(user_name)" in sql and "lower(vendor)" in sql
    assert params[0] == "a"


def test_in_list():
    sql, params = sql_of('* | where src_port in (22, 443, 3389)')
    assert "IN (%s, %s, %s)" in sql and params == [22, 443, 3389]


# ── stats / timechart / top ───────────────────────────────────────────────────
def test_stats_aggregations_and_group():
    sql, _ = sql_of('* | stats count as n, dc(user_name) as users, avg(bytes_total) as ab by vendor')
    assert "count(*) AS n" in sql
    assert "count(DISTINCT user_name) AS users" in sql
    assert "avg((bytes_total)::double precision) AS ab" in sql
    assert "GROUP BY vendor" in sql


def test_timechart_buckets_time():
    sql, params = sql_of('vendor=x | timechart span=1h count by severity')
    assert "date_bin(%s::interval, event_time" in sql
    assert "1 hours" in params and "GROUP BY 1, 2" in sql


def test_top_produces_count_and_percent():
    sql, _ = sql_of('* | top 5 action')
    assert "count(*) AS count" in sql and "AS percent" in sql
    assert "ORDER BY count DESC LIMIT 5" in sql


def test_rare_is_ascending():
    sql, _ = sql_of('* | rare action')
    assert "ORDER BY count ASC LIMIT 10" in sql


# ── projection / order / limit ────────────────────────────────────────────────
def test_fields_projection_and_final_limit():
    sql, _ = sql_of('a=1 | fields vendor, user_name', default_limit=250)
    assert "SELECT vendor, user_name FROM s1 LIMIT 250" in sql


def test_sort_and_head_order_preserved_to_final():
    sql, _ = sql_of('a=1 | sort -bytes_total | head 3')
    assert "ORDER BY bytes_total DESC NULLS LAST" in sql
    assert "LIMIT 3" in sql


def test_default_limit_always_applied():
    sql, _ = sql_of('vendor=x', default_limit=777)
    assert sql.rstrip().endswith("LIMIT 777")


def test_base_where_injected_with_its_params():
    sql, params = compile_query('vendor=x', base_where="tenant_id = %s", base_params=["t1"])
    assert "(tenant_id = %s)" in sql and "t1" in params


# ── full text: the search vector has to be in scope where it is matched ───────
# A bareword compiles to `search_tsv @@ plainto_tsquery('simple', %s)`, and `search_tsv`
# is a column of `events` — not of a CTE. So every stage a search can sit ABOVE has to
# carry it forward, exactly as it carries `raw`. `_BASE_SELECT` projected only `raw`:
# fine for a FIRST-stage search (it is folded into s0's WHERE, over `events` itself) and
# broken for `… | search <word>`. `fields` and `rename` re-project an explicit list and
# had the same hole.

_STAR_HEAD = re.compile(r"^SELECT (?:\*|DISTINCT ON \(.*?\) \*)(?:,|$)")


def cte_bodies(sql: str) -> dict:
    """``{cte name: its one-line body}`` for the emitted ``WITH s0 AS (…), s1 AS (…)``
    chain. The compiler writes one body per line, which is what makes this readable."""
    out, name = {}, None
    for line in sql.splitlines():
        m = re.match(r"(?:WITH )?(s\d+) AS \($", line)
        if m:
            name = m.group(1)
        elif name is not None:
            out[name] = line.strip()
            name = None
    return out


def carries_tsv(bodies: dict, src: str) -> bool:
    """True if relation ``src`` still exposes ``search_tsv`` — either by projecting it, or
    by riding a ``SELECT *`` back to something that does. ``events`` is the real table."""
    if src == "events":
        return True
    head, _, rest = bodies[src].partition(" FROM ")
    if "search_tsv" in head:
        return True
    if not _STAR_HEAD.match(head):
        return False                                 # an explicit projection that dropped it
    return carries_tsv(bodies, rest.split()[0])


def assert_fts_is_in_scope(sql: str) -> None:
    """Every CTE that matches on ``search_tsv`` must read from a relation that has it."""
    bodies = cte_bodies(sql)
    matched = [n for n, b in bodies.items() if "search_tsv @@" in b]
    assert matched, f"no full-text predicate was emitted at all: {sql}"
    for name in matched:
        src = bodies[name].partition(" FROM ")[2].split()[0]
        assert carries_tsv(bodies, src), \
            f"{name} matches search_tsv over {src}, which does not project it: {sql}"


@pytest.mark.parametrize("q", [
    'certutil',                                       # first stage — folded into s0's WHERE
    'vendor=x certutil',
    'vendor=x | search certutil',                     # BASE path, as a later stage
    'vendor=x | fields vendor | search certutil',     # explicit projection…
    'vendor=x | rename vendor as v | search certutil',
    'vendor=x | sort -event_time | search certutil',  # …and every `SELECT *` stage
    'vendor=x | head 3 | search certutil',
    'vendor=x | dedup src_ip | search certutil',
    'vendor=x | eval n = 1 | search certutil',
    'vendor=x | bin span=5m _time | search certutil',
])
def test_a_bareword_search_can_always_reach_the_search_vector(q):
    sql, params = compile_query(q)
    assert_fts_is_in_scope(sql)
    assert_bindable(sql, params)


def test_the_base_projection_carries_the_vector_too():
    sql, params = sql_of('vendor=x | search certutil')
    assert "bytes_total, message, raw, search_tsv FROM events" in sql
    assert "SELECT * FROM s0 WHERE (search_tsv @@" in sql
    assert params == ["x", "certutil"]
    assert "search_tsv" not in sql.rsplit(") SELECT ", 1)[-1]


def test_an_explicit_projection_re_emits_every_carried_column():
    # `fields`/`rename` write out a column list, so they are the two stages that can drop
    # a carried name by simply not mentioning it. Projecting only `raw` is what made
    # `| fields vendor | search certutil` a 42703 at execution.
    for q in ('vendor=x | fields vendor', 'vendor=x | rename vendor as v'):
        sql, _ = sql_of(q)
        assert f", {', '.join(_PASSTHRU_COLS)} FROM s0" in sql


@pytest.mark.parametrize("q", [
    '* | stats count | search failed',
    '* | stats count by vendor | search failed',
    '* | timechart span=1h count | search failed',
    '* | top 5 action | search failed',
    '* | rare action | search failed',
])
def test_a_full_text_search_after_an_aggregation_is_a_clean_error(q):
    # an aggregation throws the event row away, so there is no vector left to match. That
    # has to be a positioned 400 at compile time, not `column "search_tsv" does not exist`
    # rewritten by run.py into "query failed: …" — which reads as the analyst's mistake.
    with pytest.raises(LoqlError) as e:
        compile_query(q)
    assert "full-text search" in e.value.message and "aggregation" in e.value.message


# ── regressions from the adversarial-verify pass ──────────────────────────────
@pytest.mark.parametrize("q", [
    '* | top foo', '* | top foo by bar', '* | rare uri by src_ip', '* | top user_name',
    '* | top 5 url by user_name',
])
def test_top_rare_param_count_matches_placeholders(q):
    # was: top/rare resolved a raw field once but emitted its %s twice -> dangling placeholder.
    assert_bindable(*compile_query(q))


def test_top_by_percent_is_per_group():
    sql, _ = sql_of('* | top 3 action by protocol')
    assert "PARTITION BY" in sql                         # per-by-group percent, not the grand total


@pytest.mark.parametrize("q", [
    'a=1 | where ' + '(' * 5000 + '1' + ')' * 5000,     # deep parens
    'a=1 | where ' + 'not ' * 5000 + 'x=1',             # deep NOT chain
    'a=1 | where ' + 'lower(' * 500 + 'x' + ')' * 500,  # deep function nesting
])
def test_deep_nesting_fails_closed(q):
    # was: RecursionError -> HTTP 500; must be a clean LoqlError (400) via the depth cap.
    with pytest.raises(LoqlError):
        compile_query(q)


def test_values_and_list_arrays_are_capped():
    sql, _ = sql_of('* | stats list(message) as m, values(user_name) as u', max_agg_elems=5000)
    assert sql.count("[1:5000]") == 2                    # a single grouped row can't array_agg unbounded


# ── the driver contract: one %s per parameter, and no OTHER % anywhere ────────
# psycopg scans the statement for `%` to find placeholders, so `%` is not just an
# operator here. `| eval x = a % b` emitted it verbatim and psycopg refused the whole
# statement — `incomplete placeholder: '%'; … use '%%'` — for ANY query executed with
# parameters, i.e. every LOQL query that reaches the modulo. Modulo is documented
# (docs/LOQL.md, "where/eval expressions") and no test had ever compiled one, because the
# guard everyone reached for (`sql.count("%s") == len(params)`) reports a happy `1 == 1`
# for it. `assert_bindable` asserts both halves so a new emitter cannot pick the blind
# one by accident.

def test_modulo_emits_the_doubled_placeholder_escape():
    sql, params = sql_of('a=1 | eval odd = bytes_total % 2')
    assert "%% " in sql
    assert sql.count("%s") == len(params) == 3       # the old guard: blind, and contented
    assert_bindable(sql, params)                     # the one that sees it
    assert " % " not in sql.replace("%%", "")        # no bare modulo survives anywhere


def test_two_modulos_in_one_expression_stay_escaped():
    # the escape has to be per-emission, not a single tidy-up pass over the finished SQL.
    sql, params = sql_of('* | eval x = bytes_total % 7 | eval y = src_port % 3')
    assert sql.count("%%") == 2
    assert_bindable(sql, params)


@pytest.mark.parametrize("q, both", [
    ('a=1 | eval odd = bytes_total % 2', "((bytes_total)::numeric %% (%s)::numeric)"),
    ('* | eval x = unknown_key % 8', "(((raw ->> %s))::numeric %% (%s)::numeric)"),
    ('* | eval x = 5.5 % bytes_total', "((%s)::numeric %% (bytes_total)::numeric)"),
    ('* | eval x = bytes_total % src_port', "((bytes_total)::numeric %% (src_port)::numeric)"),
])
def test_modulo_operands_are_numeric_because_postgres_has_no_float8_modulo(q, both):
    # `%` is declared for smallint/integer/bigint/numeric and NOTHING else, and
    # float8 -> numeric is an assignment cast, so operator resolution finds no candidate:
    # `(x)::double precision % 2` is SQLSTATE 42883 "operator does not exist". Escaping
    # the `%` was necessary and not sufficient — modulo still could not execute. BOTH
    # sides are cast, so a bound float literal cannot re-introduce a float8 operand.
    sql, _ = sql_of(q)
    assert both in sql
    assert "double precision %%" not in sql and "%% (%s)::double" not in sql


def test_the_other_arithmetic_operators_keep_their_float8_cast():
    # only `%` moves — `+ - * /` are all defined for double precision and division must
    # stay float (`5 / 2` = 2.5, not numeric-truncated integer division).
    sql, _ = sql_of('* | eval a = bytes_total / 2 | eval b = bytes_total * 2')
    assert "((bytes_total)::double precision / %s)" in sql
    assert "((bytes_total)::double precision * %s)" in sql


# every stage and every operator the language documents, compiled and checked for
# bindability. A new emitter that interpolates a literal `%` — or drops/duplicates a
# placeholder — fails here rather than on an analyst's first query.
_BINDABLE_CORPUS = [
    'vendor=cisco', 'unknown_key=42', 'host_name="web*"', 'host_name!="web*"',
    'user_name="a\'b"', 'user_name="100%"', 'unknown_key=*',
    '_time > "-24h"', '_time >= "now"', '_time = 1700000000', '_time < "2026-01-01"',
    'certutil', 'vendor=x certutil', 'vendor=x or vendor=y', 'not vendor=x',
    '* | search certutil', '* | where src_port in (22, 443)',
    '* | where message like "%adm%"', '* | where isnull(app) or isnotnull(user_name)',
    '* | eval a = bytes_total + 1', '* | eval a = bytes_total - 1',
    '* | eval a = bytes_total * 2', '* | eval a = bytes_total / 2',
    '* | eval a = bytes_total % 2',                  # the operator nothing covered
    '* | eval a = bytes_total % 2 + src_port % 3',   # …twice, in one expression
    '* | eval a = unknown_key % 8',                  # …over a schema-on-read jsonb key
    '* | head 5 | eval a = bytes_total % src_port',  # …in a query that binds NOTHING
    '* | eval a = -bytes_total', '* | eval a = vendor . "-" . product',
    '* | eval a = round(bytes_total / 1024, 2)', '* | eval a = round(bytes_total)',
    '* | eval a = if(bytes_total > 0, "y", "n")', '* | eval a = lower(vendor)',
    '* | eval a = substr(message, 1, 5) | eval b = replace(a, "x", "y")',
    '* | fields vendor, unknown_key', '* | fields -message',
    '* | rename user_name as account', '* | sort -bytes_total, +vendor', '* | head 5',
    '* | dedup src_ip, dst_ip',
    '* | stats count, dc(user_name) as u, values(app) as a, list(message) as l by vendor',
    '* | timechart span=5m count by severity', '* | bin span=1d _time as day',
    '* | top 5 url by user_name', '* | rare action',
]


@pytest.mark.parametrize("q", _BINDABLE_CORPUS)
def test_every_emitted_statement_is_bindable(q):
    assert_bindable(*compile_query(q))


def test_the_apps_own_base_where_stays_bindable_too():
    assert_bindable(*compile_query('* | eval x = bytes_total % 2',
                                   base_where="tenant_id = %s", base_params=["t1"]))


# ── reserved identifiers ──────────────────────────────────────────────────────
# Values are bound; identifiers cannot be, so an output label that collides with a
# Postgres keyword has to be double-quoted or the server silently re-parses it. `user`
# is the one that bites: bare, it is CURRENT_USER, so the query returns the database
# login in every row and raises nothing. `| rename user_name as user` is docs/LOQL.md's
# own example, so this is not a hypothetical.

# every site that emits an output label, paired with the stage that reads it back
_RESERVED_ROUNDTRIPS = [
    ('* | eval user = lower(vendor)', 'lower(vendor) AS "user"', ', message, "user" FROM s1'),
    ('* | fields user', '(raw ->> %s) AS "user"', 'SELECT "user" FROM s1'),
    ('* | rename user_name as user', 'user_name AS "user"', ', app, "user", host_name,'),
    ('* | eval user = vendor | sort -user', 'vendor AS "user"', 'ORDER BY "user" DESC NULLS LAST'),
    ('* | eval user = vendor | dedup user', 'vendor AS "user"', 'DISTINCT ON ("user")'),
    ('* | stats count as user', 'count(*) AS "user"', 'SELECT "user" FROM s1'),
    ('* | stats dc(user_name) by user', '(raw ->> %s) AS "user"', 'SELECT "user", dc_user_name'),
    ('* | timechart span=1h count by user', '(raw ->> %s) AS "user"', 'SELECT _time, "user", count'),
    ('* | timechart span=1h count as user', 'count(*) AS "user"', 'SELECT _time, "user" FROM s1'),
    ('* | bin span=5m _time as user', 'timestamptz) AS "user"', ', message, "user" FROM s1'),
    ('* | top 5 user', '(raw ->> %s) AS "user"', 'SELECT "user", count, percent'),
    ('* | rare 5 action by user', '(raw ->> %s) AS "user"', 'SELECT action, "user", count'),
]


def bare_ident(sql: str, word: str) -> bool:
    """True if `word` appears as an UNQUOTED identifier — i.e. exposed to the keyword rules."""
    return re.search(rf'(?<!"){word}\b(?!")', sql) is not None


def test_stats_by_reserved_word_is_quoted():
    # was: `SELECT user, count FROM s1`, which Postgres reads as CURRENT_USER — a wrong
    # answer in every row, with no error to notice it by.
    sql, params = sql_of('vendor="okta" | stats count by user')
    assert '(raw ->> %s) AS "user"' in sql               # the label
    assert sql.endswith('SELECT "user", count FROM s1 LIMIT 1000')   # the reference
    assert not bare_ident(sql, "user")
    assert params == ["okta", "user", "user"]            # key bound twice: projection + GROUP BY


def test_rename_to_reserved_word_round_trips_through_stages():
    # docs/LOQL.md's documented rename example, carried through two more stages: the label
    # written in stage N must be character-for-character what stage N+1 references.
    sql, _ = sql_of('a=1 | rename user_name as user | stats count by user | sort -count')
    assert 'user_name AS "user"' in sql                  # s1 emits the label
    assert '"user" AS "user"' in sql and 'GROUP BY "user"' in sql        # s2 reads it back
    assert 'SELECT "user", count FROM s3' in sql                         # final projection
    assert not bare_ident(sql, "user")
    assert "ORDER BY count DESC NULLS LAST" in sql       # `count` is no keyword -> still bare


@pytest.mark.parametrize("q, label, ref", _RESERVED_ROUNDTRIPS)
def test_every_label_site_quotes_a_reserved_name(q, label, ref):
    # eval / fields / rename / sort / dedup / stats / timechart / bin / top / rare — quoting
    # one site is worthless if the next stage's reference to it is still bare.
    sql, _ = sql_of(q)
    assert label in sql and ref in sql
    assert not bare_ident(sql, "user")


def test_type_func_name_keyword_is_quoted_too():
    # `left` is reserved-for-functions: bare it is a syntax error, not a wrong answer, but
    # it is just as plausible a field name.
    sql, params = sql_of('* | fields user, left')
    assert '(raw ->> %s) AS "left"' in sql and 'SELECT "user", "left" FROM s1' in sql
    assert params == ["user", "left"]


def test_mixed_case_label_is_quoted_so_postgres_keeps_the_case():
    # docs/LOQL.md advertises `stats count by eventName`. Bare, Postgres folds the column to
    # `eventname`, so the API's `fields` (read off cur.description) stops matching what was typed.
    sql, params = sql_of('* | stats count by eventName | sort -eventName')
    assert '(raw ->> %s) AS "eventName"' in sql
    assert 'ORDER BY "eventName" DESC NULLS LAST' in sql
    assert params == ["eventName", "eventName"]


@pytest.mark.parametrize("q", [
    'vendor=x | stats count as n, dc(user_name) as users by src_ip',
    'a=1 | eval mb = bytes_total / 1048576 | fields src_ip, mb',
    'a=1 | rename user_name as account | sort -bytes_total | head 3',
    '* | top 10 src_ip by protocol', '* | rare action',
    '* | timechart span=1h count by severity',
    '* | bin span=5m _time | dedup src_ip',
])
def test_ordinary_identifiers_stay_unquoted(q):
    # quoting is only for names that need it; everything else stays bare, so the emitted SQL
    # stays readable and every other assertion in this file keeps meaning what it says.
    sql, _ = sql_of(q)
    assert '"' not in sql


@pytest.mark.parametrize("q", [q for q, _, _ in _RESERVED_ROUNDTRIPS] + [
    'vendor="okta" | stats count by user',
    'a=1 | rename user_name as user | stats count by user | sort -count',
    '* | stats count by eventName | sort -eventName',
])
def test_reserved_labels_keep_params_aligned(q):
    # the standing guard: a quoter that emitted a stray %s (or a bare %) would corrupt every
    # parameter after it — psycopg binds positionally.
    assert_bindable(*compile_query(q))


# ── every name a stage emits has to still be in scope where it is read ────────
# Quoting a label correctly is worthless if the column it names is GONE by the time the
# next stage references it. `self.cols` is what the compiler resolves a bare name against,
# and the invariant over it that only fails at EXECUTION is a green compile followed by
# SQLSTATE 42703 / 42702, rewritten by run.py into "query failed" — which reads as the
# analyst's mistake. The result order was held as finished SQL frozen at `| sort` time, so
# `| sort -bytes_total | fields - bytes_total` put a dangling `ORDER BY bytes_total` in the
# final tail AND in `dedup`'s inner ORDER BY. Same shape as `search_tsv` vanishing from
# `_BASE_SELECT` one round earlier. The structural helpers below re-derive the invariant
# from the emitted SQL, so a NEW stage gets it for free instead of needing its own
# hand-written case.

_SELECT_HEAD_RE = re.compile(r"^SELECT (?:DISTINCT ON \(.*?\) )?")
_ORDER_BY_RE = re.compile(r" ORDER BY (.*?)(?: LIMIT \d+)?$")
_LABEL_RE = re.compile(r' AS ("(?:[^"]|"")+"|\w+)$')


def split_top_level(items: str) -> list:
    """Split a SELECT/ORDER BY list on its TOP-LEVEL commas. `date_bin(%s, event_time,
    'epoch')` and `round(…, 2)` both carry commas of their own inside parentheses."""
    out, depth, cur = [], 0, ""
    for ch in items:
        depth += (ch == "(") - (ch == ")")
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    return out + ([cur.strip()] if cur.strip() else [])


def unquote(name: str) -> str:
    return name[1:-1].replace('""', '"') if name.startswith('"') else name


def source_of(body: str) -> str:
    return body.partition(" FROM ")[2].split()[0]


def output_names(bodies: dict, body: str) -> list:
    """The output column names of ONE select body, in order and KEEPING duplicates — the
    duplicate is the point, since two columns of one name is what 42702 is."""
    names = []
    for item in split_top_level(_SELECT_HEAD_RE.sub("", body.partition(" FROM ")[0])):
        if item == "*":
            names.extend(projected_names(bodies, source_of(body)))
            continue
        m = _LABEL_RE.search(item)
        names.append(unquote(m.group(1) if m else item))
    return names


def projected_names(bodies: dict, src: str) -> list:
    """The output column names of relation `src`. `events` is the real table."""
    if src == "events":
        return list(_BASE_COLS) + list(_PASSTHRU_COLS)
    return output_names(bodies, bodies[src])


def order_key_names(body: str) -> list:
    """The column names an ORDER BY in `body` sorts on. A positional ordinal (timechart's
    `ORDER BY 1`) names no column and cannot dangle, so it is skipped."""
    m = _ORDER_BY_RE.search(body)
    if not m:
        return []
    keys = [part.split()[0] for part in split_top_level(m.group(1))]
    return [unquote(k) for k in keys if not k.isdigit()]


def assert_every_name_is_in_scope(sql: str) -> None:
    """No relation exposes one name twice, and every name a relation READS BACK — an
    ORDER BY key, a final projection — resolves somewhere it is allowed to.

    The two clauses get DIFFERENT scopes, because SQL gives them different scopes. A
    SELECT list may only read its source: `top`'s `count(*) AS count` cannot be reached
    from the same select list. An ORDER BY may additionally name one of its own SELECT's
    output labels — PostgreSQL resolves a bare ORDER BY name against the output list
    FIRST — and `top` relies on it (`… count(*) AS count … ORDER BY count DESC`). Holding
    ORDER BY to the stricter rule would have failed every `top`/`rare` query for being
    correct.
    """
    bodies = cte_bodies(sql)
    for name, body in bodies.items():
        out = projected_names(bodies, name)
        dupes = sorted({c for c in out if out.count(c) > 1})
        assert not dupes, f"{name} exposes {dupes} twice, which is ambiguous: {sql}"

    tail = sql.splitlines()[-1]
    for name, body in list(bodies.items()) + [("the final SELECT", tail)]:
        src = source_of(body)
        if src == "events":
            continue                                  # the real table, not a projection
        cols = projected_names(bodies, src) + output_names(bodies, body)
        for key in order_key_names(body):
            assert key in cols, \
                f"{name} orders by {key!r}, which neither {src} nor its own select " \
                f"list projects: {sql}"
    for col in output_names(bodies, tail):
        assert col in projected_names(bodies, source_of(tail)), \
            f"the final SELECT reads {col!r}, which {source_of(tail)} does not project: {sql}"


# the shapes where a later stage moves the ground under an earlier stage's reference
_SCOPE_CORPUS = [
    'a=1 | sort -bytes_total | rename bytes_total as bytes',
    'a=1 | sort -bytes_total | rename bytes_total as bytes | head 3',
    'a=1 | sort -bytes_total | rename bytes_total as b | dedup vendor',
    'a=1 | sort -bytes_total, +vendor | rename vendor as v | rename bytes_total as b',
    '* | sort -bytes_total | fields vendor, bytes_total',        # the key is kept
    '* | sort -bytes_total | fields - message | dedup vendor',
    '* | top 5 action | fields action',                          # implicit order, dropped
    '* | top 5 action | rename count as hits',                   # implicit order, carried
    '* | rare action by protocol | fields action',
    '* | timechart span=1h count | fields count',
    '* | timechart span=1h count by severity | rename count as n',
    '* | stats count by vendor | sort -count | fields vendor, count',
    '* | eval t = _time | where t > "-24h"',
    '* | fields - raw',                          # a carried name is not a column to remove…
    '* | stats count as raw by vendor',          # …and stops being reserved once dropped
    '* | bin span=1h _time',
    '* | bin span=5m _time as day | sort -day | dedup vendor',
    '* | bin span=1h _time | stats count by _time',
    '* | bin span=1h _time | sort -_time | head 3',
    '* | fields - _time',
]


@pytest.mark.parametrize("q", _SCOPE_CORPUS + _BINDABLE_CORPUS)
def test_every_emitted_name_resolves_against_the_stage_that_projects_it(q):
    sql, params = compile_query(q)
    assert_every_name_is_in_scope(sql)
    assert_bindable(sql, params)


def test_the_helper_would_have_caught_the_dangling_order_by():
    # the guard has to fail on the shape it exists for, or it guards nothing. This is the
    # exact SQL the compiler used to emit for `| sort -bytes_total | fields - bytes_total`.
    broken = ("WITH s0 AS (\n  SELECT id, bytes_total, raw, search_tsv FROM events\n),\n"
              "s1 AS (\n  SELECT * FROM s0 ORDER BY bytes_total DESC NULLS LAST\n),\n"
              "s2 AS (\n  SELECT id, raw, search_tsv FROM s1\n)\n"
              "SELECT id FROM s2 ORDER BY bytes_total DESC NULLS LAST LIMIT 1000")
    with pytest.raises(AssertionError, match="orders by 'bytes_total'"):
        assert_every_name_is_in_scope(broken)


def test_the_helper_allows_an_order_by_on_the_selects_own_label():
    # …and the allowance is not a hole: `top` sorts by an aggregate it labels in the SAME
    # select list, which PostgreSQL resolves against the output list. Holding ORDER BY to
    # the SELECT list's stricter rule would fail this — correct SQL — as a dangle.
    fine = ("WITH s0 AS (\n  SELECT action, raw, search_tsv FROM events\n),\n"
            "s1 AS (\n  SELECT action AS action, count(*) AS count FROM s0 "
            "GROUP BY 1 ORDER BY count DESC LIMIT 5\n)\n"
            "SELECT action, count FROM s1 LIMIT 1000")
    assert_every_name_is_in_scope(fine)                # no assertion is raised

    # the SELECT LIST keeps the strict rule, because SQL does: a select list cannot read
    # its own labels.
    with pytest.raises(AssertionError, match="final SELECT reads 'percent'"):
        assert_every_name_is_in_scope(fine.replace("SELECT action, count FROM s1",
                                                   "SELECT action, percent FROM s1"))


@pytest.mark.parametrize("q, gone", [
    ('a=1 | sort -bytes_total | fields - bytes_total', 'bytes_total'),
    ('a=1 | sort -bytes_total | fields vendor, user_name', 'bytes_total'),
    ('a=1 | sort -bytes_total | fields - bytes_total | dedup vendor', 'bytes_total'),
    ('a=1 | sort -bytes_total | fields - bytes_total | head 3', 'bytes_total'),
    ('* | stats count by vendor | sort -count | fields vendor', 'count'),
    ('* | eval e = eventName | sort -e | fields vendor', 'e'),
])
def test_sorting_by_a_field_that_fields_removes_is_a_compile_error(q, gone):
    # the analyst NAMED this key, so there is no honest way to drop the clause: the rows
    # would come back in whatever order the planner felt like and the query would look
    # like it worked. Refusing beats a 42703 that run.py reports as "query failed".
    with pytest.raises(LoqlError) as e:
        compile_query(q)
    assert repr(gone) in e.value.message and "sort" in e.value.message
    assert "fields list" in e.value.message           # …and says how to fix it


def test_sorting_by_a_schema_on_read_field_is_refused_at_the_sort_stage():
    # `| sort -eventName` never reaches the `fields` guard above: the order is held as a
    # column NAME and rendered late, and `(raw ->> 'eventName')` is an expression, not a
    # name. That is a real limit of the design, so it has to be its own positioned error
    # naming the workaround — not a stray parametrize case on a test about `fields`.
    with pytest.raises(LoqlError) as e:
        compile_query('* | sort -eventName | fields vendor')
    assert e.value.message == "cannot sort by unknown field 'eventName' (eval it first)"
    assert_bindable(*compile_query('* | eval eventName = eventName | sort -eventName'))


def test_a_rename_carries_the_sort_to_the_new_label_everywhere_it_is_read():
    # the same data under a new name is not a reason to refuse the query — but the ORDER BY
    # has to follow, in the final tail and in every stage that re-asserts it.
    sql, _ = sql_of('a=1 | sort -bytes_total | rename bytes_total as b | head 3')
    assert "ORDER BY bytes_total DESC NULLS LAST" in sql       # s1, before the rename
    assert "bytes_total AS b" in sql
    assert "ORDER BY b DESC NULLS LAST LIMIT 3" in sql         # head re-asserts the NEW name
    assert sql.rstrip().endswith("ORDER BY b DESC NULLS LAST LIMIT 1000")
    assert "ORDER BY bytes_total" not in sql.split("AS b", 1)[1]


def test_a_rename_carries_the_sort_into_dedups_inner_order_by():
    # `DISTINCT ON` picks the row that sorts first, so a dangling key here does not just
    # fail — it decides WHICH row survives.
    sql, _ = sql_of('a=1 | sort -bytes_total | rename bytes_total as b | dedup vendor')
    assert "DISTINCT ON (vendor) * FROM s2 ORDER BY vendor, b DESC NULLS LAST" in sql


@pytest.mark.parametrize("q, cte_order", [
    ('* | top 5 action | fields action', 'ORDER BY count DESC LIMIT 5'),
    ('* | rare action | fields action', 'ORDER BY count ASC LIMIT 10'),
    ('* | timechart span=1h count | fields count', 'ORDER BY 1'),   # by ORDINAL, not by name
])
def test_an_order_no_one_asked_for_by_name_is_dropped_rather_than_refused(q, cte_order):
    # timechart's `_time` and top's `count` are orders those stages set for themselves and
    # already enforce in their own CTE (top's with a LIMIT, timechart's by output ordinal).
    # Nobody named them, so a later `fields` that drops the key loses a re-assertion, not
    # the analyst's instruction — and `| top 5 action | fields action` stays a query you
    # are allowed to write.
    sql, params = sql_of(q)
    assert "ORDER BY" not in sql.rsplit(") ", 1)[-1]   # gone from the final tail…
    assert cte_order in sql                           # …still enforced inside the CTE
    assert_every_name_is_in_scope(compile_query(q)[0])
    assert_bindable(sql, params)


def test_eval_of_a_new_name_takes_the_cheap_append_form():
    # an ordinary new field rides the `SELECT *`, which is what keeps `raw`/`search_tsv`
    # in scope through the stage for free.
    sql, _ = sql_of('* | eval mb = bytes_total / 1048576')
    assert "SELECT *, ((bytes_total)::double precision / %s) AS mb" in sql


def test_bucketing_still_works_wherever_the_time_column_survived():
    # `date_bin(…, event_time, …)` names an events column against the CURRENT stage's
    # output, so the shapes that keep it have to stay compilable: `SELECT *` stages carry
    # `event_time`, and an explicit projection can name it by its alias.
    for q in ('* | where vendor="x" | timechart span=1h count',
              '* | dedup src_ip | bin span=5m _time',
              '* | eval n = 1 | timechart span=1h count by severity',
              '* | fields vendor, _time | timechart span=1h count'):
        assert_bindable(*compile_query(q))


# ── a carried column is a name no stage may LABEL ─────────────────────────────
# `raw` and `search_tsv` ride along on every row-level projection and are output by none,
# which is exactly why they are absent from `self.cols` — the only list a duplicate-name
# check can see. Every row-level projection appends them anyway (`_passthru`, or the `*`
# in `SELECT *, … AS x`), so a stage that LABELS one of those names emits it twice,
# compiles clean, and dies at the next reference with 42702 `column reference "raw" is
# ambiguous` — an execution-time failure that run.py reports as "query failed", i.e. as
# the analyst's mistake. `_reject_carried` is the guard that makes it a positioned 400.

@pytest.mark.parametrize("q, stage", [
    ('* | fields {c}', 'fields'),                 # a schema-on-read miss, aliased back to it
    ('* | fields vendor, {c}', 'fields'),
    ('* | eval {c} = 1', 'eval'),
    ('* | rename vendor as {c}', 'rename'),
])
@pytest.mark.parametrize("col", _PASSTHRU_COLS)
def test_no_stage_may_label_a_column_the_pipeline_is_still_carrying(q, stage, col):
    with pytest.raises(LoqlError) as e:
        compile_query(q.format(c=col))
    assert e.value.message.startswith(f"{stage} cannot output")
    assert repr(col) in e.value.message           # names the collision…
    assert "pick another label" in e.value.message            # …and how to get past it


def test_the_carried_columns_are_the_one_thing_the_column_list_cannot_see():
    # why this needed a guard of its own rather than a line in the ordinary duplicate check:
    # that check compares against `self.cols`, and neither carried name is in it. This is
    # the SQL the compiler emitted for `| fields raw`.
    broken = ("WITH s0 AS (\n  SELECT vendor, raw, search_tsv FROM events\n),\n"
              "s1 AS (\n  SELECT (raw ->> %s) AS raw, raw, search_tsv FROM s0\n)\n"
              "SELECT raw FROM s1 LIMIT 1000")
    with pytest.raises(AssertionError, match=r"s1 exposes \['raw'\] twice"):
        assert_every_name_is_in_scope(broken)


def test_removing_a_carried_name_is_the_no_op_it_always_was():
    # `| fields - raw` names something that is not a column, so there is nothing to remove
    # and nothing to reject — the guard is about LABELS, not about mentions.
    sql, params = compile_query('* | fields - raw')
    assert_every_name_is_in_scope(sql)
    assert_bindable(sql, params)


# ── `_time` is s0's vocabulary ────────────────────────────────────────────────
# `_ALIASES` ({_time: event_time, _raw: message}) describes the `events` TABLE, and s0 is
# where it is meant to fire. Every stage that resolves a name — `_resolve`, `fields`,
# `rename`, `sort`, `dedup` — has to agree on that, because the label one stage writes is
# what the next one reads back.

def test_the_time_alias_resolves_to_the_events_column_at_every_stage_that_reads_a_name():
    # one alias, five call sites: a stage that spelled it differently would emit a label
    # its successor cannot find.
    assert "event_time > (now() - interval '24 hours')" in sql_of('_time > "-24h"')[0]
    assert "SELECT event_time, message, raw, search_tsv FROM s0" in sql_of('* | fields _time, _raw')[0]
    assert "event_time AS ts" in sql_of('* | rename _time as ts')[0]
    assert "ORDER BY event_time DESC" in sql_of('* | sort -_time')[0]
    assert "DISTINCT ON (event_time)" in sql_of('* | dedup _time')[0]


def test_an_expression_over_the_stamp_is_a_number_not_a_stamp():
    # `_num` casts every arithmetic operand to double precision, so the RESULT of one is a
    # number however it started — and the comparison after it must follow the numeric path.
    sql, params = sql_of('* | eval t = _time | eval u = t + 0 | where u > 5')
    assert "((u)::double precision > %s)" in sql
    assert_bindable(sql, params)


# ── the execution boundary: what run.py actually sends to PostgreSQL ──────────
# `SET LOCAL statement_timeout = %s` had never once executed. psycopg3 binds SERVER-side,
# so PostgreSQL received `SET LOCAL statement_timeout = $1` — and `SET` is a utility
# statement whose grammar (`var_value: opt_boolean_or_string | NumericOnly`) has no
# ParamRef production at all, so it failed to PARSE with SQLSTATE 42601 before the query
# itself was ever sent. run.py's `except` then rewrote it as "query failed: …", which
# reads as a bad query rather than a runner that cannot run anything. Every LOQL query.
# There is no PostgreSQL in the unit environment (and the integration job reported green
# while executing zero tests for ~70 commits), so the statements are captured instead.

_UTILITY_RE = re.compile(r"\s*(SET|RESET|SHOW|BEGIN|COMMIT|ROLLBACK|LISTEN|NOTIFY|"
                         r"DISCARD|PREPARE|DEALLOCATE|VACUUM|EXPLAIN\s+ANALYZE)\b", re.I)


class _FakeCursor:
    """Records every (sql, params) pair and answers one row for the compiled query."""

    def __init__(self, sent):
        self.sent = sent
        self.description = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.sent.append((sql, params))
        # only the compiled query is a result set worth describing
        self.description = [SimpleNamespace(name="vendor")] if sql.startswith("WITH ") else None

    def fetchmany(self, n):
        return [{"vendor": "acme"}] if self.description else []


class _FakeConn:
    def __init__(self, sent):
        self.sent = sent

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    @contextmanager
    def transaction(self):
        yield self

    def cursor(self, **kw):
        return _FakeCursor(self.sent)


class _FakePool:
    def __init__(self, sent):
        self.sent = sent

    def connection(self):
        return _FakeConn(self.sent)


def run_capturing(monkeypatch, query, **kw):
    """Run `run_query` against a fake pool; return (result, [(sql, params), …])."""
    from app import db
    from app.loql import run_query
    sent = []
    monkeypatch.setattr(db, "pool", lambda: _FakePool(sent))
    return run_query(query, **kw), sent


def test_the_timeout_is_set_with_a_statement_that_can_take_a_parameter(monkeypatch):
    res, sent = run_capturing(monkeypatch, 'vendor=acme | fields vendor',
                              limit=10, timeout_ms=30_000)
    (t_sql, t_params), (q_sql, _) = sent
    assert t_sql == "SELECT set_config('statement_timeout', %s, true)"
    assert t_params == ("30000",)                    # set_config is (text, TEXT, bool)
    assert q_sql.startswith("WITH s0 AS")
    assert res["fields"] == ["vendor"] and res["count"] == 1


@pytest.mark.parametrize("q", [
    'vendor=acme', 'vendor=acme | stats count by user_name',
    'certutil', '* | top 5 url',
    '* | head 5 | eval x = bytes_total % src_port',   # a `%%` with ZERO parameters
])
def test_no_parameterized_statement_is_a_utility_statement(monkeypatch, q):
    # the actual rule that was broken: PostgreSQL cannot bind a parameter into SET/RESET/
    # SHOW/… — only into a real query. Anything run.py executes WITH parameters must
    # therefore be an ordinary statement, whatever it is being used to configure.
    _res, sent = run_capturing(monkeypatch, q)
    assert len(sent) == 2
    for sql, params in sent:
        # A parameter SEQUENCE is always passed, even when it is empty — psycopg only
        # un-escapes `%%` when it is given one (`convert(sql, [])` yields `%`, but
        # `convert(sql, None)` leaves `%%` on the wire). The last query above emits a
        # doubled `%` and binds nothing, so `cur.execute(sql)` would ship it literally.
        assert params is not None, f"executed without a parameter sequence: {sql}"
        assert not _UTILITY_RE.match(sql), f"cannot bind a parameter into: {sql}"
        assert_bindable(sql, list(params))


@pytest.mark.parametrize("given, expect", [
    (30_000, "30000"), (0, "0"),                     # 0 is PostgreSQL's "no timeout"
    (-5, "0"),                                       # negative is out of range -> clamp
    (1500.9, "1500"),                                # a float budget from main.py
])
def test_the_timeout_value_is_text_and_never_out_of_range(monkeypatch, given, expect):
    _res, sent = run_capturing(monkeypatch, 'vendor=acme', timeout_ms=given)
    assert sent[0][1] == (expect,)


def test_the_timeout_is_transaction_local(monkeypatch):
    # `true` is set_config's is_local flag — the SET LOCAL half of the original intent.
    # Without it the timeout would leak onto the pooled connection for every later caller.
    _res, sent = run_capturing(monkeypatch, 'vendor=acme')
    assert sent[0][0].endswith(", true)")


def test_a_loql_error_from_the_compiler_passes_through_unchanged():
    from app.loql import run as loql_run
    with pytest.raises(LoqlError) as e:
        loql_run.run_query('* | sort -eventName')
    # not re-wrapped as "query failed: …", which is the execution guard's wording
    assert e.value.message.startswith("cannot sort by unknown field")


# ── integration (real DB; skipped unless DB_DSN is set) ───────────────────────
@pytest.mark.integration
def test_loql_end_to_end(clean_db):
    from app.loql import run_query
    from app.models import NormalizedEvent
    db = clean_db
    now = datetime.now(timezone.utc)
    events = []
    for i in range(9):
        events.append(NormalizedEvent(
            event_time=now - timedelta(minutes=i), vendor="acme",
            action="deny" if i % 3 else "allow", user_name=f"u{i % 3}",
            bytes_total=100 * (i + 1), host_name="h1", raw={"api": f"Call{i}", "vendor": "acme"}))
    with db.pool().connection() as conn:
        db.insert_events(conn, events, 1)
        conn.commit()

    r = run_query('vendor=acme action=deny | stats count as n by user_name | sort -n')
    assert r["fields"] == ["user_name", "n"]
    assert sum(row["n"] for row in r["rows"]) == 6         # 6 of 9 are 'deny'

    r2 = run_query('vendor=acme | stats count as c, sum(bytes_total) as total')
    assert r2["rows"][0]["c"] == 9 and r2["rows"][0]["total"] == 100 * (1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 + 9)

    r3 = run_query('Call5')                                # full-text over the raw jsonb tsvector
    assert r3["count"] == 1

    r4 = run_query('vendor=acme | top 2 user_name')
    assert r4["fields"][:2] == ["user_name", "count"] and len(r4["rows"]) <= 2
