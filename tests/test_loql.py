# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""LOQL — the piped analytics query language.

The parser + compiler are pure (query text -> AST -> parameterized SQL), so they are
tested here without a database, including the load-bearing security invariant: every
user value is a bound parameter and never appears in the SQL text. One integration
test (skipped unless DB_DSN is set) runs a handful of queries end-to-end.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.loql import LoqlError, compile_query, parse
from app.loql import nodes as N


def sql_of(q, **kw):
    sql, params = compile_query(q, **kw)
    return " ".join(sql.split()), params


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


# ── regressions from the adversarial-verify pass ──────────────────────────────
@pytest.mark.parametrize("q", [
    '* | top foo', '* | top foo by bar', '* | rare uri by src_ip', '* | top user_name',
    '* | top 5 url by user_name',
])
def test_top_rare_param_count_matches_placeholders(q):
    # was: top/rare resolved a raw field once but emitted its %s twice -> dangling placeholder.
    sql, params = compile_query(q)
    assert sql.count("%s") == len(params)
    sql % tuple("x" for _ in params)                    # would raise if misaligned


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
