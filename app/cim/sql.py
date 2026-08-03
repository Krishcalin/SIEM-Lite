# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Turn the CIM registry into SQL — the *only* place CIM concepts become SQL text.

One artifact is emitted here: a ``CREATE VIEW cim_<tag>`` per model, projecting the
model's CIM field names over the events that belong to it. ``db.init_cim`` applies the
statements (drop + create, so a registry edit takes effect on the next startup).

Membership itself is NOT emitted as DDL. ``events.cim_models text[]`` is a plain column
declared statically in ``schema.sql`` and populated per row in Python at ingest from
:func:`app.cim.match.tags_for` — mirroring exactly how ``search_tsv`` is populated from
``normalize.tsv_text``. It is a plain column and not ``GENERATED … STORED`` for two
reasons: PostgreSQL 16 freezes a generation expression at ``ADD COLUMN`` (rewriting it
needs ``ALTER COLUMN … SET EXPRESSION``, which is PG17+, and docker-compose pins 16), and
detection needs membership BEFORE the INSERT — the detection engine's ``evaluate_event``
runs per event inside ``pipeline.write_stream`` while rows are only flushed to the table
in chunks. One evaluator, in Python, not two.

:func:`membership_sql` therefore stays as the readable, executable *spec* of membership
(a set-based backfill or an ad-hoc audit query can run it), but :mod:`app.cim.match` is
the authoritative runtime evaluator; rows ingested before a model existed are refreshed
by ``db.backfill_cim``.

Because these strings become DDL (a view body cannot be parameterized), every identifier
is validated against a whitelist, every output label is double-quoted, and every literal
is single-quote escaped — the registry is trusted config, but this is the same
defence-in-depth the LOQL compiler applies. Membership expressions use only IMMUTABLE
operators (``lower``, ``->>``, ``#>>``, ``COALESCE``, ``IN``); field expressions need
not be — ``concat_ws`` in ``_NAMED_EXPR`` is STABLE, which is legal in a view and would
be illegal in a generated column. That asymmetry is why fields live in views only.
"""
from __future__ import annotations

import re
from typing import List

from .spec import CimClause, CimError, CimField, CimModel, CimRegistry, CimSource, CimTerm

# Columns of `events` a CIM field may read directly (src_ip/dst_ip are inet → host()).
_FIELD_COLUMNS = {
    "id", "event_time", "ingested_at", "vendor", "product", "log_type", "severity",
    "action", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "app",
    "user_name", "host_name", "rule_name", "bytes_total", "message",
}
_INET_COLUMNS = {"src_ip", "dst_ip"}
# Columns a membership term may test (text/enum columns only; keyed case-insensitively).
_TERM_COLUMNS = {"vendor", "product", "log_type", "severity", "action", "protocol",
                 "app", "user_name", "host_name"}
# ── the column vocabulary a CIM projection produces (ONE list per concept) ────
# A CIM projection emits columns in three groups, and the difference between them is the
# whole reason the lists below are separate:
#
#   UNCONDITIONAL — always emitted, so a field of the same name is a duplicate column:
#     IDENTITY_COLUMNS, first (drill-down + the time axis every stage needs), and
#     PASSTHROUGH_COLUMNS, last. Both feed :data:`_RESERVED_FIELDS`.
#   CONDITIONAL   — CIM_PASSTHROUGH_COLUMNS, appended only when no field claimed the name,
#     so a field MAY take one of these and the projection then skips its own.
#
# The two groups must stay disjoint (a reserved column is already in the projection, so
# "append it if free" would emit it twice) — asserted in tests/test_loql.py.
IDENTITY_COLUMNS = ("id", "event_time")
# Columns that ride along on every row a CIM projection emits but are never CIM FIELDS:
# ``raw`` (drill-down, and the LOQL schema-on-read fallback) and ``search_tsv`` (the
# GIN-indexed full-text vector a bareword search matches). ``app.loql.compiler`` builds
# its row-level passthrough tail FROM this tuple rather than restating it, because the
# reserved-field guard below is derived from it too — one list, so a column added to the
# projection cannot silently skip the guard the way ``search_tsv`` did.
PASSTHROUGH_COLUMNS = ("raw", "search_tsv")
# Columns appended AFTER a model's own fields, and only when no field has claimed the
# name. Shared with the LOQL ``datamodel:`` source so ``| datamodel X`` and
# ``SELECT * FROM cim_x`` project one shape, in one order.
CIM_PASSTHROUGH_COLUMNS = ("vendor", "product", "log_type", "severity", "message")
# Names a CIM field may NOT take: every column a projection emits UNCONDITIONALLY, plus
# the membership column the WHERE reads. A field named ``search_tsv`` used to pass this
# guard and then compile — in the LOQL projection, which appends ``raw, search_tsv`` after
# the fields — to TWO columns of that name, so the very next bareword search failed with
# 42702 ``column reference "search_tsv" is ambiguous``. Derived, not restated: adding a
# column to either unconditional group reserves it in the same edit.
_RESERVED_FIELDS = frozenset({*IDENTITY_COLUMNS, *PASSTHROUGH_COLUMNS, "cim_models"})
# Whitelisted named SQL snippets a field may use (kind: expr). No user input reaches these.
# NOTE: concat_ws is STABLE, not IMMUTABLE — fine in a view, never in a generated column.
_NAMED_EXPR = {
    "vendor_product": "concat_ws(':', vendor, product)",
}

_IDENT_RE = re.compile(r"^[a-z][a-z0-9_]*$")          # tags + CIM field names
_KEY_RE = re.compile(r"^[A-Za-z0-9_.\-/ ]+$")         # jsonb keys (then escaped anyway)


# ── low-level, injection-safe emitters ────────────────────────────────────────
def _ident(name: str) -> str:
    if not _IDENT_RE.match(name or ""):
        raise CimError(f"invalid identifier {name!r}")
    return name


def _quote_ident(name: str) -> str:
    """Double-quote an identifier emitted as an OUTPUT LABEL (``<expr> AS <label>``).

    Quoting is UNCONDITIONAL and deliberately not keyword-aware. ``user`` is today the
    only PostgreSQL reserved word among the CIM field names, and an unquoted
    ``user_name AS user`` is a silent data-corruption bug: ``CREATE VIEW`` accepts the
    label, but a later bare ``SELECT user`` parses as ``CURRENT_USER`` and returns the
    connection role on every row. A keyword list would be one more thing to keep in step
    with the server version, so we quote everything instead.

    The name is validated by :func:`_ident` first (so it is already ``[a-z][a-z0-9_]*``
    and can contain no quote); doubling any embedded quote is defence in depth. Because
    our identifiers are already lower-case, quoting does not change how consumers resolve
    them — a quoted lower-case label is the same column as the unquoted, case-folded one.
    """
    return '"' + _ident(name).replace('"', '""') + '"'


def _lit(value) -> str:
    """A single-quoted SQL string literal (standard_conforming_strings=on → doubling
    the quote is sufficient)."""
    return "'" + str(value).replace("'", "''") + "'"


def _field_column(col: str) -> str:
    if col not in _FIELD_COLUMNS:
        raise CimError(f"unknown events column {col!r} in a CIM field")
    return f"host({col})" if col in _INET_COLUMNS else col


def _key(raw_key: str) -> str:
    if not _KEY_RE.match(raw_key or ""):
        raise CimError(f"unsafe jsonb key {raw_key!r}")
    return raw_key


def view_name(model: CimModel) -> str:
    return "cim_" + _ident(model.tag)


# ── value source → SQL (used by the views AND the LOQL datamodel projection) ───
def _path_sql(path: tuple) -> str:
    """One jsonb lookup. A single segment is a TOP-LEVEL key read with ``->>`` — the key
    is used verbatim, dots and all, because Zeek stores literal dotted top-level keys
    (``id.orig_h``). Two or more segments descend with ``#>>`` and an ARRAY constructor
    (not a ``'{a,b}'`` array literal, whose own quoting rules would bite on a key
    containing a space or a comma). Both operators are IMMUTABLE."""
    if not path:
        raise CimError("a raw source needs at least one path segment")
    segs = [_key(s) for s in path]
    if len(segs) == 1:
        return f"(raw ->> {_lit(segs[0])})"
    return "(raw #>> ARRAY[" + ", ".join(_lit(s) for s in segs) + "])"


def _raw_sql(src: CimSource) -> str:
    """Ordered alternatives collapse to ``COALESCE`` — vendors spell the same concept
    differently (``EventID`` / ``event_id``), and the first non-null wins."""
    if not src.paths:
        raise CimError("a raw source needs at least one jsonb key")
    parts = [_path_sql(p) for p in src.paths]
    return parts[0] if len(parts) == 1 else "COALESCE(" + ", ".join(parts) + ")"


def source_sql(src: CimSource) -> str:
    """The SQL expression for a value source in FIELD position. No parameters — the
    key/column/const comes from the trusted registry and is validated + escaped inline
    (a view body can't bind params). User-supplied comparison *values* are still bound
    by the caller."""
    if src.kind == "column":
        return _field_column(src.name)
    if src.kind == "raw":
        return _raw_sql(src)
    if src.kind == "const":
        return _lit(src.name)
    if src.kind == "expr":
        sql = _NAMED_EXPR.get(src.name)
        if sql is None:
            raise CimError(f"unknown named expression {src.name!r}")
        return sql
    raise CimError(f"unknown source kind {src.kind!r}")


def field_value_sql(field: CimField) -> str:
    """The SQL expression for a CIM field's value."""
    return source_sql(field.source)


# ── membership predicate → SQL ────────────────────────────────────────────────
def _term_sql(term: CimTerm) -> str:
    src = term.source
    if src.kind == "raw":
        lhs = _raw_sql(src)
    elif src.kind == "column":
        if src.name not in _TERM_COLUMNS:
            raise CimError(f"column {src.name!r} is not allowed in a membership term "
                           f"(allowed: {sorted(_TERM_COLUMNS)})")
        lhs = src.name
    else:
        raise CimError(f"a membership term cannot read a {src.kind!r} source "
                       f"({term.label or src.describe()})")
    if not term.values:
        raise CimError(f"membership term {term.label or src.describe()} needs at least one value")
    vals = ", ".join(_lit(v) for v in term.values)          # values are pre-lowercased
    inner = f"lower({lhs}) = {_lit(term.values[0])}" if len(term.values) == 1 \
        else f"lower({lhs}) IN ({vals})"
    return f"({inner})"


def _clause_sql(clause: CimClause) -> str:
    if not clause.terms:
        raise CimError("a membership clause needs at least one term")
    return "(" + " AND ".join(_term_sql(t) for t in clause.terms) + ")"


def membership_sql(model: CimModel) -> str:
    """The boolean predicate that decides whether an event belongs to ``model``
    (OR of clauses).

    This is the readable SQL spec of membership and stays runnable — a set-based
    backfill or an ad-hoc audit query can execute it against ``events``. The evaluator
    that actually stamps ``events.cim_models`` at ingest is :mod:`app.cim.match`; the two
    read the same :mod:`app.cim.spec` objects, which is what keeps them in step.
    """
    if not model.clauses:
        raise CimError(f"model {model.name!r} has no membership clauses")
    return "(" + " OR ".join(_clause_sql(c) for c in model.clauses) + ")"


def membership_predicate(tag: str) -> str:
    """The index-usable predicate for 'this event is a member of <tag>' — used by the
    LOQL ``datamodel:`` compiler and the views (the GIN index on ``cim_models``
    declared in schema.sql supports ``@>``)."""
    return f"cim_models @> ARRAY[{_lit(_ident(tag))}]::text[]"


# ── DDL ───────────────────────────────────────────────────────────────────────
def drop_view_ddl(model: CimModel) -> str:
    return f"DROP VIEW IF EXISTS {view_name(model)}"


def create_view_ddl(model: CimModel) -> str:
    """A view projecting the model's CIM field names over its members, plus id/event_time/
    raw (drill-down) and the :data:`CIM_PASSTHROUGH_COLUMNS` that don't collide with a
    field name. Every field label is double-quoted — see :func:`_quote_ident`.

    ``search_tsv`` is deliberately NOT projected here even though it is a passthrough for
    the LOQL compiler: a view is a destination, not a pipeline stage, so nothing reads the
    vector back off it. It is still reserved (see :data:`_RESERVED_FIELDS`) because the
    LOQL ``datamodel:`` projection of the same registry DOES carry it."""
    # A conditional passthrough is skipped when the name is ALREADY PROJECTED — asked of
    # `names`, the projection's own output, rather than of a separately assembled set. The
    # LOQL side (`compiler._cim_select`) asks the same question the same way, so the two
    # cannot answer differently.
    names = list(IDENTITY_COLUMNS) + [f.name for f in model.fields]
    proj = list(IDENTITY_COLUMNS)
    for f in model.fields:
        proj.append(f"{field_value_sql(f)} AS {_quote_ident(f.name)}")
    for c in CIM_PASSTHROUGH_COLUMNS:
        if c not in names:
            proj.append(c)
    proj.append("raw")
    return (f"CREATE VIEW {view_name(model)} AS\n"
            f"SELECT {', '.join(proj)}\n"
            f"FROM events\nWHERE {membership_predicate(model.tag)}")


def ddl_statements(registry: CimRegistry) -> List[str]:
    """Every CIM DDL statement, in apply order: for each model, DROP VIEW then CREATE
    VIEW. Idempotent and safe to run on every startup, so a ``fields:`` edit in the
    registry takes effect on the next boot.

    The ``events.cim_models`` column and its GIN index are NOT emitted here — they are
    declared statically in ``schema.sql`` and the column is filled per row at ingest
    (see the module docstring)."""
    out: List[str] = []
    for m in registry.models:
        out.append(drop_view_ddl(m))
        out.append(create_view_ddl(m))
    return out
