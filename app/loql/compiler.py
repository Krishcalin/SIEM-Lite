# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Compile a LOQL ``nodes.Query`` AST to **parameterized SQL** over the ``events`` table.

The pipeline becomes a chain of CTEs (``s0`` = the search over ``events``; each later
stage selects from the previous one). The output is ``(sql, params)`` where every
user-supplied literal, jsonb key, and glob is a bound ``%s`` parameter — the compiler
emits only fixed SQL skeletons. That is the entire injection-safety story, and it is
why this module is a pure function unit-tested by asserting the emitted SQL + params.

Field resolution is schema-on-read: a name that is a known ``events`` column resolves
to that column (``src_ip`` rendered as ``host(src_ip)`` text); anything else is read
from the ``raw`` jsonb as ``(raw ->> %s)`` with the key BOUND as a parameter. Comparisons
against ``_time``/``event_time`` are timestamp-typed and understand relative literals
(``-24h``, ``now``); numeric comparisons/arithmetic cast operands to ``double precision``
(``%`` to ``numeric`` — PostgreSQL has no float8 modulo, see :meth:`_Compiler._numeric`);
``=`` / ``!=`` against a value containing ``*``/``?`` become bound ``ILIKE`` globs.

Identifiers are values' quieter cousin: they cannot be bound as parameters, so every
name this compiler *emits* — an ``AS`` label, and every later stage that references one
— goes through :func:`_out_ident`, which double-quotes anything Postgres would re-parse.
Without it ``| stats count by user`` compiles to ``SELECT user``, which Postgres reads
as ``CURRENT_USER``: a wrong answer in every row and not one error to notice it by.

Which names are in scope is the other half of that, and the half that only fails at
execution. ``self.cols`` is what every stage resolves a bare name against, so it carries
two invariants that no single stage can be trusted to keep on its own: the names in it are
DISTINCT (:meth:`_Compiler._set_cols` — a duplicate label is 42702 ``column reference "x"
is ambiguous`` at the first reference), and anything the compiler still references —
notably the result order, held as (name, descending) pairs and rendered late by
:meth:`_Compiler._order_by`, and ``event_time`` under ``bin``/``timechart`` — is still in
it (otherwise 42703 ``column "x" does not exist``). Both are SQLSTATEs that reach the
analyst as "query failed", which reads as their mistake; refusing at compile time makes
them a positioned 400 that names the column.

``self.cols`` is also the only vocabulary a bare name is read against. ``_time`` and
``_raw`` are aliases for columns of ``events`` — a fact about ``s0``, not about whatever
relation stage N happens to be reading — so they are consulted only when the alias name
is not itself a live column and the column it points at still is
(:meth:`_Compiler._live`). Applied blind the same alias was wrong in both directions:
``| timechart`` OUTPUTS a column called ``_time``, so ``| timechart span=1h count | sort
-_time`` was refused as an unknown field the analyst could see in their own result table;
and ``| bin span=1h _time`` adds the bucket BESIDE the raw stamp, so every later ``_time``
resolved to the unbinned one and ``| bin span=1h _time | stats count by _time`` grouped
per microsecond and raised nothing at all.

A query may instead source a CIM data model (``| datamodel Authentication`` or ``from
datamodel:Authentication``). ``s0`` then filters on the index-usable membership
predicate ``cim_models @> ARRAY[%s]::text[]`` — the tag BOUND, like every other value —
and projects the model's CIM field names, the same shape ``cim.sql.create_view_ddl``
gives the ``cim_<tag>`` view. Downstream stages therefore see the model's vocabulary:
``user``, not ``user_name``. A normalized column the model replaced is a hard error
rather than a schema-on-read miss, because ``(raw ->> 'user_name')`` would answer NULL
in every row and look like an empty result set.
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

# `cim.sql` is the emitter side of the CIM registry and imports nothing from `app.loql`,
# so naming it here is safe and costs no YAML read — only `get_registry()` (which parses
# `models.yaml`) stays lazy, inside `_cim_model`. What it exports are the two column lists
# both sides of the CIM boundary have to agree on, byte for byte:
#   * PASSTHROUGH_COLUMNS     — carried by every row-level stage, output by none
#   * CIM_PASSTHROUGH_COLUMNS — appended after a model's own fields, so `| datamodel X`
#                               and `SELECT * FROM cim_x` return one shape. A model that
#                               defines a field of the same name keeps its own.
from ..cim.sql import CIM_PASSTHROUGH_COLUMNS as _CIM_PASSTHROUGH
from ..cim.sql import PASSTHROUGH_COLUMNS as _PASSTHRU_COLS
from . import nodes as N
from .errors import LoqlError

# base columns exposed by s0 (order matters for `SELECT *`-free projection); src_ip/dst_ip
# are inet, rendered to text via host(). `raw`/`search_tsv` ride along (see _PASSTHRU_SQL)
# but are not output columns.
_BASE_COLS = ["id", "event_time", "vendor", "product", "log_type", "severity", "action",
              "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "app", "user_name",
              "host_name", "rule_name", "bytes_total", "message"]
# The columns every row-level stage CARRIES but never outputs: `raw` (schema-on-read for a
# key no column maps) and `search_tsv` (the GIN-indexed full-text vector a bareword search
# matches). A stage that projects an explicit list must re-emit ALL of them — a stage that
# projects only `raw` compiles `| search certutil` into a reference to a column that is no
# longer in scope, and Postgres answers `column "search_tsv" does not exist`.
#
# The names come from `cim.sql` rather than being spelled here because the SAME list is
# what a CIM field name may not collide with (`cim.sql._RESERVED_FIELDS`), and the two
# drifted once already: `search_tsv` was added to this projection and not to that guard,
# so a registry declaring a field of that name compiled to two columns of one name.
# Direction matters — `app.cim` never imports `app.loql` (see `_cim_model`), so the shared
# vocabulary has to live on the CIM side and be read from here.
#
# Being carried and not listed is also why these names are the ONE thing `_set_cols` cannot
# see, so `| fields raw` / `| eval raw = 1` / `| rename x as raw` reached the same 42702 the
# registry guard exists to prevent, through the pipeline door instead of the registry one.
# `_Compiler._reject_carried` is that guard on this side, over this same tuple.
_PASSTHRU_SQL = ", ".join(_PASSTHRU_COLS)
_BASE_SELECT = ("id, event_time, vendor, product, log_type, severity, action, "
                "host(src_ip) AS src_ip, host(dst_ip) AS dst_ip, src_port, dst_port, "
                "protocol, app, user_name, host_name, rule_name, bytes_total, message, "
                + _PASSTHRU_SQL)
# The analyst's spelling of two `events` columns. This is s0's vocabulary and NOTHING
# else's, so it is never applied directly at a call site — see `_Compiler._live`, which
# tries the live column list first and only then the alias.
_ALIASES = {"_time": "event_time", "_raw": "message"}
_IDENT_RE = re.compile(r"^[A-Za-z_]\w*$")
# A name safe to emit bare: lower-case ASCII, which Postgres stores verbatim. Anything
# else (mixed case, a digit-led tail, a unicode letter) folds or errors, so it is quoted.
_BARE_RE = re.compile(r"^[a-z_][a-z0-9_]*$")
_SPAN_UNIT = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
_AGG_SQL = {"count": "count", "sum": "sum", "avg": "avg", "min": "min", "max": "max"}
_FUNC_SQL = {"lower": "lower", "upper": "upper", "length": "length", "abs": "abs",
             "ceil": "ceil", "floor": "floor", "btrim": "btrim", "coalesce": "coalesce",
             "substr": "substr", "replace": "replace", "round": "round"}


# PostgreSQL keywords that must never be emitted bare. This is PG16's keyword table
# minus the plain `non-reserved` category — i.e. `reserved`, `reserved (can be function
# or type name)`, and `non-reserved (cannot be function or type name)`. Bare `user`
# silently becomes CURRENT_USER, bare `left` is a syntax error, and both are things an
# analyst names a field. Data, not code: the set only ever grows, and over-quoting costs
# nothing — a quoted lower-case identifier is identical to the bare one.
_PG_KEYWORDS = frozenset("""
all analyse analyze and any array as asc asymmetric authorization
between bigint binary bit boolean both
case cast char character check coalesce collate collation column concurrently
constraint create cross current_catalog current_date current_role current_schema
current_time current_timestamp current_user
dec decimal default deferrable desc distinct do
else end except exists extract
false fetch float for foreign freeze from full
grant greatest group grouping
having
ilike in initially inner inout int integer intersect interval into is isnull
join json json_array json_arrayagg json_exists json_object json_objectagg
json_query json_scalar json_serialize json_table json_value
lateral leading least left like limit localtime localtimestamp
national natural nchar none normalize not notnull null nullif numeric
offset on only or order out outer overlaps overlay
placing position precision primary
real references returning right row
select session_user setof similar smallint some substring symmetric system_user
table tablesample then time timestamp to trailing treat trim true
union unique user using
values varchar variadic verbose
when where window with
xmlattributes xmlconcat xmlelement xmlexists xmlforest xmlnamespaces xmlparse
xmlpi xmlroot xmlserialize xmltable
""".split())


def _brief(exc: BaseException) -> str:
    """A foreign exception rendered as ONE bounded line, fit for an HTTP 400 body.

    A ``yaml`` parse error carries a multi-line problem mark (the snippet, a caret, and
    two source positions) and this string is returned to the caller verbatim, so it is
    squashed and capped rather than passed through."""
    return " ".join(str(exc).split())[:200] or type(exc).__name__


def _ident(name: str) -> str:
    if not _IDENT_RE.match(name or ""):
        raise LoqlError(f"invalid identifier {name!r}")     # defence in depth; lexer already gates
    return name


def _out_ident(name: str) -> str:
    """Render ``name`` as an OUTPUT identifier: an ``AS`` label, or a later stage's
    reference to one.

    Bare is the default so the emitted SQL stays readable (and assertable), but a name
    Postgres would re-parse gets double-quoted — otherwise ``| stats count by user``
    emits ``SELECT user`` and every row reports the database login. Both halves of a
    round trip call this, so the label written in stage N always matches the reference
    read in stage N+1. Embedded quotes are doubled: ``_ident`` makes that unreachable
    today, but a quoter that only works on pre-validated input is not a quoter.
    """
    _ident(name)
    if _BARE_RE.match(name) and name not in _PG_KEYWORDS:
        return name
    return '"' + name.replace('"', '""') + '"'


class _Compiler:
    def __init__(self, query: N.Query, *, base_where: str = "", base_params=None,
                 default_limit: int = 1000, max_agg_elems: int = 10000):
        self.q = query
        self.base_where = base_where
        self.base_params = list(base_params or [])
        self.default_limit = max(1, int(default_limit))
        self.agg_cap = max(1, int(max_agg_elems))
        self.params: List[object] = []
        self.ctes: List[str] = []
        self.cols: List[str] = list(_BASE_COLS)
        # True while the row-level passthrough columns (`raw` AND `search_tsv`) are still
        # in scope. An aggregation drops both at once, which is why one flag covers them.
        self.raw_avail = True
        # The result order as (column NAME, descending) pairs — never as finished SQL; see
        # `_order_by`. `order_named` is True only when the analyst wrote `| sort`.
        self.order: List[Tuple[str, bool]] = []
        self.order_named = False
        # Which of `self.cols` are TIMESTAMP-typed, so `_is_time` can answer for a bucket a
        # stage produced (`timechart`'s `_time`, `bin`'s output) and not only for
        # `events.event_time`. Kept in step with `self.cols` by `_set_cols`, exactly as
        # `self.order` is — and for the same reason: mis-typing a comparison here is 42846
        # "cannot cast timestamp with time zone to double precision" at execution.
        self.time_cols = {"event_time"}
        self.cur = "s0"
        self.model = None                        # the resolved CimModel, when sourced from one

    def _passthru(self) -> str:
        """The trailing ``, raw, search_tsv`` an EXPLICIT projection has to re-emit so the
        next stage can still read a jsonb key or run a bareword search. Empty once an
        aggregation has thrown the row away."""
        return f", {_PASSTHRU_SQL}" if self.raw_avail else ""

    def _reject_carried(self, names, stage: str) -> None:
        """Refuse an output label that collides with a column this stage CARRIES.

        The carried columns are the one blind spot in :meth:`_set_cols`, and they are
        blind precisely BECAUSE they are carried: ``raw`` and ``search_tsv`` are plumbing,
        not fields, so they are deliberately absent from ``self.cols`` — which is the only
        list the duplicate-name check can see. Every row-level projection then appends
        them anyway (:meth:`_passthru`, or the ``*`` in ``SELECT *, … AS x``), so a stage
        that LABELS one of those names emits it twice:

            | fields raw          ->  SELECT (raw ->> %s) AS raw, raw, search_tsv FROM s0
            | eval raw = 1        ->  SELECT *, %s AS raw FROM s0
            | rename vendor as raw

        all compiled clean and died at the next reference with 42702 ``column reference
        "raw" is ambiguous`` — the same execution-time failure, reading as the analyst's
        mistake, that ``_set_cols`` exists to convert into a positioned 400.

        ``cim.sql._RESERVED_FIELDS`` already refuses these two names on the REGISTRY door,
        out of the same ``PASSTHROUGH_COLUMNS`` tuple and for the same reason. This is that
        guard on the PIPELINE door; a third passthrough added tomorrow closes both at once.

        Only while they are actually being carried. After an aggregation ``_passthru`` is
        empty and ``SELECT *`` reads a relation that has no ``raw`` in it, so nothing is
        emitted beside the label and ``| stats count as raw by vendor`` is legal.
        """
        if not self.raw_avail:
            return
        clash = [n for n in dict.fromkeys(names) if n in _PASSTHRU_COLS]
        if clash:
            noun = "a column named" if len(clash) == 1 else "columns named"
            raise LoqlError(
                f"{stage} cannot output {noun} {', '.join(repr(c) for c in clash)} - every "
                f"row-level stage carries {', '.join(repr(c) for c in _PASSTHRU_COLS)} "
                f"beside its own columns (the raw event and its full-text vector), so a "
                f"second column of that name is ambiguous to every stage after this one; "
                f"read a key out of the raw event by naming the key, or pick another label")

    # ── the column list, and the order over it ───────────────────────────────
    def _set_cols(self, names, stage: str) -> None:
        """Adopt ``names`` as this stage's output columns, refusing a duplicate NAME.

        Every later stage — and the final projection, and ``ORDER BY`` — resolves a bare
        name against this list, so two columns answering to one name is not cosmetic.
        PostgreSQL accepts the duplicate label inside the CTE and then fails the FIRST
        reference to it with 42703/42702 ``column reference "x" is ambiguous``, which
        ``run.py`` rewrites into "query failed" — i.e. at execution, reading as the
        analyst's mistake. ``| rename vendor as product`` (``product`` already exists),
        ``| fields vendor, vendor`` and ``| stats count as vendor by vendor`` all landed
        there. Refused here, they are a compile-time 400 that names the collision.
        """
        seen, dupes = set(), []
        for n in names:
            if n in seen and n not in dupes:
                dupes.append(n)
            seen.add(n)
        if dupes:
            raise LoqlError(f"{stage} would produce two columns named "
                            f"{', '.join(repr(d) for d in dupes)} - a duplicate name is "
                            f"ambiguous to every stage after it; rename one of them")
        self.cols = list(names)
        self.time_cols &= set(names)        # a column this stage dropped is no longer a time column

    def _live(self, name: str) -> Optional[str]:
        """The column IN THE CURRENT SCOPE that ``name`` refers to, or ``None``.

        ``_ALIASES`` describes ``events``: ``_time`` is what an analyst calls
        ``event_time``, ``_raw`` what they call ``message``. That is a fact about ``s0``'s
        vocabulary and not about whatever relation stage N is reading, so the alias is
        consulted only AFTER ``self.cols`` — and only when what it points at is still
        there. Spelled ``_ALIASES.get(name, name)`` at each call site instead, it was wrong
        in both directions:

        * ``| timechart`` OUTPUTS a column named ``_time``. Rewriting the name to
          ``event_time`` — which timechart itself replaced — made ``| timechart span=1h
          count | sort -_time`` (and ``fields`` / ``rename`` / ``dedup`` / ``where`` on
          ``_time``) a compile error naming a field the analyst can see in their own
          result table.
        * ``| bin span=1h _time`` ADDS the bucket beside the raw stamp, so both names are
          live. The rewrite sent every later ``_time`` to the unbinned ``event_time``:
          ``| bin span=1h _time | stats count by _time`` emitted ``GROUP BY event_time``,
          one group per microsecond, and raised nothing. A wrong answer with no symptom is
          the one failure mode this compiler exists to refuse.

        Same defect as the dangling ``ORDER BY`` and the vanished ``search_tsv``: a name
        resolved against a scope an earlier stage has since moved.
        """
        if name in self.cols:
            return name
        real = _ALIASES.get(name)
        return real if real is not None and real in self.cols else None

    def _time_col(self) -> Optional[str]:
        """The column that IS the event timestamp here — the bucket a previous ``bin`` or
        ``timechart`` produced if there is one, else ``events.event_time`` — or ``None``
        once a projection has dropped it."""
        col = self._live("_time")
        return col if col in self.time_cols else None

    def _timed_by(self, names) -> set:
        """Which of an aggregation's group keys are timestamps.

        A ``by`` key is the SAME value the source column held, under a name the analyst
        chose, so ``| stats count by _time`` keeps the group key time-typed. Without this
        the key survives as a column (``_live`` finds it) but stops being a *time* column,
        and ``| stats count by _time | where _time > "-24h"`` casts a ``timestamptz`` to
        ``double precision`` — a runtime 42846 where the old blind alias at least gave a
        compile error."""
        return {n for n in names if self._live(n) in self.time_cols}

    def _order_by(self) -> str:
        """The ORDER BY body, rendered LATE from live column names.

        The order is held as (name, descending) pairs rather than finished SQL because a
        later stage moves the ground under it: ``| rename`` relabels the sort key and
        ``| fields`` can drop it. A string frozen at ``| sort`` time still named the old
        column in the final tail (and in ``dedup``'s inner ORDER BY), so
        ``| sort -bytes_total | fields - bytes_total`` compiled clean and died at execution
        with 42703 ``column "bytes_total" does not exist``. Rendering here means the names
        are whatever ``self.cols`` says they are at the moment of emission.

        ``NULLS LAST`` trails the whole list, exactly as it did before — on PostgreSQL it
        attaches to the final key only, which is pre-existing behaviour and not this
        method's business to change.
        """
        parts = [f"{_out_ident(n)} {'DESC' if d else 'ASC'}" for n, d in self.order]
        return ", ".join(parts) + " NULLS LAST"

    def _reorder(self, mapping: dict) -> None:
        """Carry the result order through a ``| rename``: the sort key is the same data
        under a new label, so the order follows it rather than becoming an error."""
        self.order = [(mapping.get(n, n), d) for n, d in self.order]

    def _drop_order(self, kept, stage: str) -> None:
        """Reconcile the result order with a projection that keeps only ``kept``.

        An ORDER BY over a column the projection removed is a dangling reference, and
        there are only two honest outcomes. If the analyst NAMED the key (``| sort``),
        refusing is the right one: silently dropping the clause would answer in whatever
        order the planner felt like and look like a working query. If the order is one a
        transform set for itself (``timechart``'s ``_time``, ``top``'s ``count`` — both
        already enforced by that stage's own ORDER BY, and ``top``'s by its LIMIT), then
        nobody asked for it by name and re-asserting it at the tail is a nicety we can
        drop rather than reject ``| top 5 action | fields action``.
        """
        keep = set(kept)
        gone = list(dict.fromkeys(n for n, _ in self.order if n not in keep))
        if not gone:
            return
        if self.order_named:
            raise LoqlError(
                f"{stage} would remove {', '.join(repr(n) for n in gone)}, which the "
                f"preceding sort orders the result by - add it to the {stage} list, or "
                f"sort by a field you are keeping")
        self.order = []

    # ── field / literal resolution ───────────────────────────────────────────
    def _reject_shadowed(self, name: str) -> None:
        """Inside a data model, a normalized ``events`` column name is a MISTAKE, not a
        jsonb key: the model deliberately replaced that namespace (``user_name`` became
        ``user``, ``src_ip`` became ``src``). Left to the schema-on-read fallback it would
        read a key that is not there and answer NULL in every row — a failure with no
        symptom, which is the one kind this compiler refuses to produce.

        ``_ALIASES`` is applied raw here on purpose: this asks whether the name is one of
        the BASE table's normalized columns, which is exactly what the alias map describes.
        It is only ever reached once ``_live`` has already missed."""
        if self.model is not None and _ALIASES.get(name, name) in _BASE_COLS:
            raise LoqlError(f"{name!r} is not in data model {self.model.name!r} "
                            f"(available: {', '.join(self.cols)})")

    def _resolve(self, name: str) -> str:
        real = self._live(name)
        if real is not None:
            return _out_ident(real)
        if self.raw_avail:
            self._reject_shadowed(name)
            self.params.append(name)
            return "(raw ->> %s)"
        raise LoqlError(f"unknown field {name!r}")

    def _is_time(self, e: N.Expr) -> bool:
        return isinstance(e, N.Field) and self._live(e.name) in self.time_cols

    def _time_literal(self, e: N.Expr) -> str:
        if isinstance(e, N.Lit) and e.kind == "num":
            self.params.append(e.value)
            return "to_timestamp(%s)"
        if isinstance(e, N.Lit) and e.kind == "str":
            v = e.value.strip()
            if v.lower() == "now":
                return "now()"
            m = re.fullmatch(r"([+-]?)(\d+)([smhd])", v)
            if m:                                  # relative: -24h, +30m (digits regex-validated → inline-safe)
                sign = "-" if m.group(1) == "-" else "+"
                return f"(now() {sign} interval '{int(m.group(2))} {_SPAN_UNIT[m.group(3)]}')"
            self.params.append(v)
            return "%s::timestamptz"
        raise LoqlError("a time comparison needs a timestamp, a date string, or a relative value like -24h")

    def _num(self, e: N.Expr) -> str:
        if isinstance(e, N.Lit) and e.kind == "num":
            self.params.append(e.value)
            return "%s"
        return f"({self._expr(e)})::double precision"

    def _numeric(self, e: N.Expr) -> str:
        """An operand of ``%``, cast to ``numeric`` — NOT to ``double precision``.

        PostgreSQL's modulo operator is declared for ``smallint``, ``integer``, ``bigint``
        and ``numeric`` and for nothing else: there is no ``double precision %`` at all,
        and ``float8 -> numeric`` is an assignment cast, so operator resolution finds no
        candidate and fails with SQLSTATE 42883 ``operator does not exist: double
        precision % ...``. Modulo therefore cannot reuse ``_num`` the way ``+ - * /`` do.
        The literal side is cast too, so ``2.5 % x`` cannot re-introduce a float8 operand
        through a bound parameter. ``numeric`` comes back as a ``Decimal``, which
        ``run.py:_cell`` already renders as a float.
        """
        return f"({self._expr(e)})::numeric"

    def _glob(self, pattern: str) -> Optional[str]:
        if "*" not in pattern and "?" not in pattern:
            return None
        out = pattern.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        return out.replace("*", "%").replace("?", "_")

    # ── expression compiler (where / eval / search predicate) ────────────────
    def _expr(self, e: N.Expr) -> str:
        if isinstance(e, N.Lit):
            if e.kind == "null":
                return "NULL"
            if e.kind == "bool":
                return "TRUE" if e.value else "FALSE"
            self.params.append(e.value)
            return "%s"
        if isinstance(e, N.Field):
            return self._resolve(e.name)
        if isinstance(e, N.Unary):
            if e.op == "not":
                return f"(NOT {self._expr(e.operand)})"
            return f"(-{self._num(e.operand)})"
        if isinstance(e, N.InList):
            tgt = self._expr(e.target)
            items = ", ".join(self._expr(it) for it in e.items)
            return f"({tgt} IN ({items}))"
        if isinstance(e, N.Func):
            return self._func(e)
        if isinstance(e, N.Binary):
            return self._binary(e)
        raise LoqlError("unsupported expression")   # pragma: no cover

    def _binary(self, e: N.Binary) -> str:
        op = e.op
        if op in ("and", "or"):
            return f"({self._expr(e.left)} {op.upper()} {self._expr(e.right)})"
        if op == "%":
            # Modulo is documented (docs/LOQL.md) and had never once compiled in a test,
            # which hid TWO independent reasons it could not run:
            #
            # 1. `%` is psycopg's placeholder marker, not just an operator. Emitted bare
            #    it aborts the WHOLE statement with "incomplete placeholder: '%'; … use
            #    '%%'" — every parameter in the query, not only this one. `%%` is the
            #    escape, exactly as `_cim_select` doubles a `%` out of a registry
            #    expression. The suite's `sql.count("%s") == len(params)` invariant is
            #    BLIND to it (a bare `%` is not a `%s`); `sql % tuple(...)` is what sees
            #    it. psycopg only undoes the escape when a parameter SEQUENCE is passed
            #    (`execute(sql, [])` yields `%`, `execute(sql)` leaves `%%`), and a modulo
            #    between two columns binds nothing at all — so `run.py` must keep passing
            #    `params` even when it is empty.
            # 2. PostgreSQL has no float8 modulo, so `_num`'s cast is the wrong one —
            #    see `_numeric`.
            return f"({self._numeric(e.left)} %% {self._numeric(e.right)})"
        if op in ("+", "-", "*", "/"):
            return f"({self._num(e.left)} {op} {self._num(e.right)})"
        if op == ".":
            return f"(({self._expr(e.left)})::text || ({self._expr(e.right)})::text)"
        if op == "like":
            return f"({self._expr(e.left)} LIKE {self._expr(e.right)})"
        if op in ("<", "<=", ">", ">="):
            if self._is_time(e.left):
                return f"({self._resolve(e.left.name)} {op} {self._time_literal(e.right)})"
            if self._is_time(e.right):
                return f"({self._time_literal(e.left)} {op} {self._resolve(e.right.name)})"
            return f"({self._num(e.left)} {op} {self._num(e.right)})"
        if op in ("=", "!="):
            sql_op = "=" if op == "=" else "<>"
            # time equality
            if self._is_time(e.left):
                return f"({self._resolve(e.left.name)} {sql_op} {self._time_literal(e.right)})"
            # wildcard glob -> ILIKE (bound pattern)
            for fieldside, litside in ((e.left, e.right), (e.right, e.left)):
                if isinstance(litside, N.Lit) and litside.kind == "str":
                    g = self._glob(litside.value)
                    if g is not None:
                        neg = "NOT " if op == "!=" else ""
                        col = self._expr(fieldside)
                        self.params.append(g)
                        return f"({col} {neg}ILIKE %s)"
            return f"({self._expr(e.left)} {sql_op} {self._expr(e.right)})"
        raise LoqlError(f"unsupported operator {op!r}")   # pragma: no cover

    def _func(self, e: N.Func) -> str:
        fn = e.name
        if fn == "_fts":                            # search bareword -> full-text match (GIN index)
            if not self.raw_avail:
                # After stats/timechart/top there is no event row left to match — the
                # emitted reference would be to a column that is not in scope, i.e. a
                # runtime `column "search_tsv" does not exist` dressed up as a bad query.
                raise LoqlError("a full-text search cannot follow an aggregation - put the "
                                "search before the stats/timechart/top stage, or compare "
                                "one of its output fields by name")
            self.params.append(e.args[0].value)
            return "(search_tsv @@ plainto_tsquery('simple', %s))"
        if fn == "__if__":
            return f"(CASE WHEN {self._expr(e.args[0])} THEN {self._expr(e.args[1])} ELSE {self._expr(e.args[2])} END)"
        if fn == "__isnull__":
            return f"({self._expr(e.args[0])} IS NULL)"
        if fn == "__isnotnull__":
            return f"({self._expr(e.args[0])} IS NOT NULL)"
        if fn == "round":
            inner = self._num(e.args[0])
            if len(e.args) == 2:
                self.params.append(int(e.args[1].value) if isinstance(e.args[1], N.Lit) else 0)
                return f"round(({inner})::numeric, %s)"
            return f"round(({inner})::numeric)"
        sql = _FUNC_SQL.get(fn)
        if not sql:
            raise LoqlError(f"unsupported function {fn!r}")   # pragma: no cover
        args = ", ".join(self._expr(a) for a in e.args)
        return f"{sql}({args})"

    # ── the CIM data-model source ────────────────────────────────────────────
    def _cim_model(self, name: str):
        """Resolve a CIM data model by display name or tag, case-insensitively.

        The registry is imported lazily so the compiler stays importable — and
        unit-testable — without it, and a query with no data model never reads the YAML.
        Every failure becomes a ``LoqlError`` because that is this module's whole
        contract: callers handle exactly one exception type, so an unknown model is a
        clean 400 with the known names in it, never an opaque 500.

        That is why the guard is ``Exception`` and not ``CimError``. Loading the registry
        reads and parses a YAML file, so it can also raise ``yaml.YAMLError`` (a ``<<:``
        merge key gives a ConstructorError), ``ValueError`` from ``int(version)`` on
        ``version: abc``, or ``OSError`` if ``models.yaml`` is missing — and
        ``compile_query`` is called OUTSIDE the ``run.py`` execution guard, by callers
        (``api.py``) that catch only ``LoqlError``. Catching one subclass of "the registry
        is broken" turned a registry typo into a 500 with a traceback.
        """
        try:
            from ..cim import get_registry          # inside the guard: even the import can fail
            reg = get_registry()
            model = reg.by_name(name)
            known = ", ".join(reg.names)
        except Exception as exc:  # noqa: BLE001 — CimError / yaml.YAMLError / ValueError / OSError…
            # `app.cim` never imports `app.loql`, so nothing in here can be a LoqlError
            # that this would swallow and re-word.
            raise LoqlError(f"the CIM registry is unavailable: {_brief(exc)}")
        if model is None:
            raise LoqlError(f"unknown data model {name!r} (known: {known})")
        return model

    def _cim_select(self, model) -> str:
        """``s0``'s SELECT list for a data model: the model's CIM field names over
        ``events``, and the column list they become.

        This mirrors ``cim.sql.create_view_ddl`` so ``| datamodel X`` and ``SELECT * FROM
        cim_x`` project one shape — the analyst should not be able to tell which door they
        came in by. ``raw`` rides along, which keeps schema-on-read working for the jsonb
        keys a model does not map, and ``search_tsv`` rides along with it: a model's search
        predicate is lifted into a CTE ABOVE this projection (see :meth:`compile`), so a
        bareword like ``from datamodel:Web certutil`` matches the vector here, not on
        ``events``. Neither is an output column — both are appended after ``cols``.
        """
        from ..cim.spec import CimError
        from ..cim.sql import IDENTITY_COLUMNS, field_value_sql
        proj = list(IDENTITY_COLUMNS)
        cols = list(IDENTITY_COLUMNS)
        try:
            for f in model.fields:
                # Registry expressions carry no placeholders, but a literal '%' in one
                # would be read as the start of a placeholder by psycopg and shift every
                # later binding — doubling it costs nothing and closes that off.
                proj.append(f"{field_value_sql(f).replace('%', '%%')} AS {_out_ident(f.name)}")
                cols.append(f.name)
        except CimError as exc:                       # registry validated this at load; belt + braces
            raise LoqlError(f"data model {model.name!r} is malformed: {exc}")
        # Skipped when the name is ALREADY PROJECTED — asked of `cols`, what this
        # projection has actually emitted, exactly as `cim.sql.create_view_ddl` asks it of
        # its own. Asked instead of a hand-assembled `taken` set, the two sides could
        # answer differently for the same registry, which is the shape of drift that put
        # `search_tsv` in one list and not the other.
        for c in _CIM_PASSTHROUGH:
            if c not in cols:
                proj.append(c)
                cols.append(c)
        proj.append(_PASSTHRU_SQL)                    # carried, never listed in `cols`
        # The registry already refuses a duplicate field name and reserves id/event_time/
        # raw/search_tsv, so neither of these can fire today — which is the point: they are
        # the same two invariants every other stage is held to (one name one column, and no
        # label that collides with what `_PASSTHRU_SQL` just appended), asserted where a
        # registry edit would otherwise be the one way around them.
        self._reject_carried(cols, f"data model {model.name!r}")
        self._set_cols(cols, f"data model {model.name!r}")
        return ", ".join(proj)

    # ── stage compilation ────────────────────────────────────────────────────
    def _next(self, body: str) -> None:
        name = f"s{len(self.ctes)}"                   # s0 already appended -> next is s1
        self.ctes.append(f"{name} AS (\n  {body}\n)")
        self.cur = name

    def compile(self) -> Tuple[str, List[str]]:
        stages = list(self.q.stages)
        first = stages[0]
        assert isinstance(first, N.Search)
        if first.datamodel is not None:
            self.model = self._cim_model(first.datamodel)
        # s0: the search over events — or over a CIM data model's projection of them
        where = []
        if self.model is not None:
            select = self._cim_select(self.model)     # emits no params; also sets self.cols
            self.params.append(self.model.tag)        # BOUND, never interpolated
            where.append("cim_models @> ARRAY[%s]::text[]")   # GIN-indexed containment
        else:
            select = _BASE_SELECT
            if first.predicate is not None:
                where.append(self._expr(first.predicate))
        if self.base_where:
            # base_where is trusted (built by the app, e.g. an RBAC/time predicate) with its own params
            self.params.extend(self.base_params)
            where.append(f"({self.base_where})")
        w = (" WHERE " + " AND ".join(where)) if where else ""
        self.ctes.append(f"s0 AS (\n  SELECT {select} FROM events{w}\n)")
        if self.model is not None and first.predicate is not None:
            # A predicate over a data model reads the model's FIELD names, and SQL cannot
            # reference a SELECT's own output labels from its own WHERE — so the search
            # becomes its own CTE over s0 instead of being folded into it.
            self._next(f"SELECT * FROM {self.cur} WHERE {self._expr(first.predicate)}")

        for st in stages[1:]:
            self._stage(st)

        sel = ", ".join(_out_ident(c) for c in self.cols)
        tail = f"\nSELECT {sel} FROM {self.cur}"
        if self.order:
            tail += f" ORDER BY {self._order_by()}"
        tail += f" LIMIT {self.default_limit}"
        return "WITH " + ",\n".join(self.ctes) + tail, self.params

    def _stage(self, st: N.Stage) -> None:
        getattr(self, "_st_" + type(st).__name__.lower())(st)

    def _st_search(self, st: N.Search) -> None:
        if st.datamodel is not None:
            # The parser folds every data model into stages[0], so this only fires for a
            # hand-built AST — where silently ignoring the source would be far worse.
            raise LoqlError("a data model is a query's source, not a pipeline stage")
        if st.predicate is None:
            return
        self._next(f"SELECT * FROM {self.cur} WHERE {self._expr(st.predicate)}")

    def _st_where(self, st: N.Where) -> None:
        self._next(f"SELECT * FROM {self.cur} WHERE {self._expr(st.expr)}")

    def _add_column(self, name: str, expr: str, stage: str) -> None:
        """Emit ``SELECT *, <expr> AS name`` — or, when ``name`` is ALREADY a column, a
        full projection with that one column REPLACED.

        ``SELECT *, … AS vendor`` over a relation that already has ``vendor`` leaves the
        CTE holding two columns of that name, and the next reference to it (the final
        projection, at the very least) is 42702 ``column reference "vendor" is ambiguous``
        — at execution, long after this compiled. Which matters because overwriting a
        field is the ordinary use, not a mistake: ``| eval vendor = lower(vendor)`` is a
        normalization and ``| bin span=1h _time`` names ``_time`` by default. ``expr``
        still reads the INPUT column, because a SELECT's own output labels are not visible
        to its own select list.

        ``name`` is checked against the CARRIED columns too, because both branches emit
        them beside the label — the ``*`` in the append branch, ``_passthru`` in the
        replace branch — and ``self.cols`` cannot see them.
        """
        self._reject_carried([name], stage)
        label = _out_ident(name)
        if name in self.cols:
            proj = ", ".join(f"{expr} AS {label}" if c == name else _out_ident(c)
                             for c in self.cols)
            self._next(f"SELECT {proj}{self._passthru()} FROM {self.cur}")
        else:
            self._next(f"SELECT *, {expr} AS {label} FROM {self.cur}")
            self.cols.append(name)

    def _st_eval(self, st: N.Eval) -> None:
        # Whether the RESULT is a timestamp, read BEFORE `_add_column` moves the scope —
        # and settled by the same rule `_timed_by` applies to a `by` key: the value is the
        # one the source column held only when the expression IS that column. Everything
        # else `_expr` can emit is text, boolean, or a `_num`/`_numeric` cast.
        #
        # `self.time_cols` is metadata over `self.cols`, so it decays exactly like the
        # column list and the result order do — and `_add_column` was the one stage that
        # REPLACES a column without touching it. Stale in both directions, both at
        # execution: `| eval event_time = vendor | timechart span=1h count` kept the name
        # marked time-typed and emitted `date_bin(interval, event_time, …)` over text
        # (42883, no such function), while `| eval t = _time | where t > "-24h"` left a
        # genuine timestamptz unmarked and compiled `(t)::double precision` (42846).
        timed = self._is_time(st.expr)
        self._add_column(st.name, self._expr(st.expr), "eval")   # _expr binds its params first
        if timed:
            self.time_cols.add(st.name)
        else:
            self.time_cols.discard(st.name)

    def _st_fields(self, st: N.Fields) -> None:
        for n in st.names:
            _ident(n)                     # validate up front; emission happens via _resolve_named
        if st.remove:
            # The names being REMOVED go through the same live resolution as the ones being
            # kept: `| fields - _time` has to drop `event_time`. Compared against `self.cols`
            # unresolved it matched nothing and quietly removed no column at all.
            drop = {self._live(n) or n for n in st.names}
            keep = [c for c in self.cols if c not in drop]
        else:
            resolved = [(n, self._live(n)) for n in st.names]
            missing = [n for n, real in resolved if real is None and not self.raw_avail]
            if missing:
                raise LoqlError(f"unknown field(s) in fields: {', '.join(missing)}")
            keep = [real or n for n, real in resolved]   # a miss survives as a raw jsonb key
        if not keep:
            raise LoqlError("fields would remove every column")
        # Only the KEEP path can reach this: the remove path draws `keep` from `self.cols`,
        # which never holds a carried name. `| fields raw` does — as a schema-on-read miss
        # aliased back to `raw`, right next to the `raw` that `_passthru` appends.
        self._reject_carried(keep, "fields")
        self._drop_order(keep, "fields")
        proj = ", ".join(self._resolve_named(c) for c in keep)   # reads the OLD self.cols
        self._next(f"SELECT {proj}{self._passthru()} FROM {self.cur}")
        self._set_cols(keep, "fields")

    def _resolve_named(self, name: str) -> str:
        """A column for a projection/rename: a real column, or a raw field aliased to name."""
        real = self._live(name)
        if real is not None:
            return _out_ident(real)
        self._reject_shadowed(name)
        self.params.append(name)
        return f"(raw ->> %s) AS {_out_ident(name)}"

    def _st_rename(self, st: N.Rename) -> None:
        mapping = {}
        for src, dst in st.pairs:
            _ident(src); _ident(dst)      # validate; the projection below emits via _out_ident
            real = self._live(src)
            if real is None:
                raise LoqlError(f"cannot rename unknown field {src!r}")
            mapping[real] = dst
        self._reject_carried(mapping.values(), "rename")
        proj = ", ".join(f"{_out_ident(c)} AS {_out_ident(mapping[c])}" if c in mapping
                         else _out_ident(c) for c in self.cols)
        self._next(f"SELECT {proj}{self._passthru()} FROM {self.cur}")
        # Both of the things tracked ALONGSIDE `self.cols` follow the new label; the
        # time set is remapped BEFORE `_set_cols`, which intersects it with the new names.
        self.time_cols = {mapping.get(c, c) for c in self.time_cols}
        self._set_cols([mapping.get(c, c) for c in self.cols], "rename")
        self._reorder(mapping)            # the sort key follows its new label

    def _st_sort(self, st: N.Sort) -> None:
        keys = []
        for name, desc in st.keys:
            real = self._live(name)
            if real is None:
                raise LoqlError(f"cannot sort by unknown field {name!r} (eval it first)")
            keys.append((real, desc))
        self.order, self.order_named = keys, True
        self._next(f"SELECT * FROM {self.cur} ORDER BY {self._order_by()}")

    def _st_head(self, st: N.Head) -> None:
        n = max(0, int(st.n))
        order = f" ORDER BY {self._order_by()}" if self.order else ""
        self._next(f"SELECT * FROM {self.cur}{order} LIMIT {n}")

    def _st_dedup(self, st: N.Dedup) -> None:
        reals = []
        for name in st.fields:
            real = self._live(name)
            if real is None:
                raise LoqlError(f"cannot dedup unknown field {name!r}")
            reals.append(real)
        keys = ", ".join(_out_ident(r) for r in reals)
        order = f"{keys}, {self._order_by()}" if self.order else keys
        self._next(f"SELECT DISTINCT ON ({keys}) * FROM {self.cur} ORDER BY {order}")

    def _agg_sql(self, a: N.Agg) -> str:
        if a.func == "count":
            return "count(*)" if a.arg is None else f"count({self._resolve(a.arg)})"
        if a.func == "dc":
            return f"count(DISTINCT {self._resolve(a.arg)})"
        if a.func == "values":     # [1:cap] bounds the cell so one group can't array_agg unbounded memory
            return f"(array_agg(DISTINCT {self._resolve(a.arg)}))[1:{self.agg_cap}]"
        if a.func == "list":
            return f"(array_agg({self._resolve(a.arg)}))[1:{self.agg_cap}]"
        if a.func in ("sum", "avg"):
            return f"{a.func}(({self._resolve(a.arg)})::double precision)"
        return f"{_AGG_SQL[a.func]}({self._resolve(a.arg)})"   # min / max

    def _st_stats(self, st: N.Stats) -> None:
        timed = self._timed_by(st.by)                 # read BEFORE _set_cols moves the scope
        by_sel = [f"{self._resolve(b)} AS {_out_ident(b)}" for b in st.by]
        agg_sel = [f"{self._agg_sql(a)} AS {_out_ident(a.out)}" for a in st.aggs]
        group = ""
        if st.by:
            group = " GROUP BY " + ", ".join(self._resolve(b) for b in st.by)
        out = list(st.by) + [a.out for a in st.aggs]
        self._set_cols(out, "stats")
        self.time_cols |= timed
        self._next(f"SELECT {', '.join(by_sel + agg_sel)} FROM {self.cur}{group}")
        self.raw_avail = False
        self.order, self.order_named = [], False

    def _interval(self, span: Optional[str], default: str = "1h") -> str:
        m = re.fullmatch(r"(\d+)([smhd])", span or default)
        if not m:
            raise LoqlError(f"invalid span {span!r}")
        self.params.append(f"{int(m.group(1))} {_SPAN_UNIT[m.group(2)]}")
        return "%s::interval"

    def _bucket(self, span: Optional[str], stage: str) -> str:
        """``date_bin(<span>, <the live time column>, …)`` — with that column checked to
        still BE there.

        The column name is emitted bare and resolved against the CURRENT stage's output,
        not against ``events``: after ``| fields vendor`` (or any aggregation) it is gone,
        and the bucket compiled to 42703 ``column "event_time" does not exist`` at
        execution. WHICH column comes from :meth:`_time_col`, so a second bucketing
        re-buckets the bucket rather than silently re-reading the raw stamp beside it. A
        data model always has one — ``_cim_select`` projects id/event_time first, exactly
        as the ``cim_<tag>`` view does.

        Removed is not the only way to lose it: ``| eval event_time = vendor`` keeps the
        NAME and replaces the value, so the miss here is over ``_time_col`` — which asks
        ``self.time_cols``, not ``self.cols`` — and the message has to say both."""
        col = self._time_col()
        if col is None:
            raise LoqlError(f"{stage} needs the _time field, which an earlier stage removed "
                            f"or overwrote with a non-timestamp value "
                            f"(available: {', '.join(self.cols)})")
        return f"date_bin({self._interval(span)}, {_out_ident(col)}, 'epoch'::timestamptz)"

    def _st_timechart(self, st: N.Timechart) -> None:
        bucket = self._bucket(st.span, "timechart")
        cols = [f"{bucket} AS {_out_ident('_time')}"]
        group = ["1"]
        out = ["_time"]
        if st.by:
            cols.append(f"{self._resolve(st.by)} AS {_out_ident(st.by)}")
            group.append("2")
            out.append(st.by)
        for a in st.aggs:
            cols.append(f"{self._agg_sql(a)} AS {_out_ident(a.out)}")
            out.append(a.out)
        self._set_cols(out, "timechart")
        self.time_cols = {"_time"}        # the bucket IS the timestamp from here on
        self._next(f"SELECT {', '.join(cols)} FROM {self.cur} GROUP BY {', '.join(group)} ORDER BY 1")
        self.raw_avail = False
        self.order, self.order_named = [("_time", False)], False

    def _st_bin(self, st: N.Bin) -> None:
        # `_ALIASES` raw, deliberately: this asks whether the analyst NAMED the time field,
        # which is a question about spelling. Whether that field is still in scope — and
        # which column it is now — is `_bucket`/`_time_col`'s job.
        if _ALIASES.get(st.field, st.field) != "event_time":
            raise LoqlError("bin currently supports only the _time field")
        out = st.out or st.field
        self._add_column(out, self._bucket(st.span, "bin"), "bin")
        self.time_cols.add(out)           # `| bin span=1h _time` ADDS a second timestamp column

    def _st_top(self, st: N.Top) -> None:
        # resolve the field ONCE (its %s is bound one param); GROUP BY by output ordinal so the
        # field expression is never re-emitted (which would leave a dangling %s). percent is per
        # by-group when a `by` is present, else the grand total.
        timed = self._timed_by([st.field, *st.by])     # read BEFORE _set_cols moves the scope
        field_sql = self._resolve(st.field)
        by_sel = [f"{self._resolve(b)} AS {_out_ident(b)}" for b in st.by]
        direction = "ASC" if st.rare else "DESC"
        n = max(1, int(st.n))
        over = ("PARTITION BY " + ", ".join(self._resolve(b) for b in st.by)) if st.by else ""
        percent = (f"round(100.0 * count(*) / NULLIF(sum(count(*)) OVER ({over}), 0), 2) "
                   f"AS {_out_ident('percent')}")
        cols = ([f"{field_sql} AS {_out_ident(st.field)}"] + by_sel
                + [f"count(*) AS {_out_ident('count')}", percent])
        group = ", ".join(str(i) for i in range(1, 2 + len(st.by)))    # GROUP BY 1, 2, … (ordinals)
        # `count` and `percent` are labels this stage adds unconditionally, so a field (or
        # a `by`) of either name is a collision — and `ORDER BY count` below would already
        # be ambiguous inside this very CTE. _set_cols says so, in one place, for `top`
        # exactly as for `stats` and `fields`.
        self._set_cols([st.field] + list(st.by) + ["count", "percent"], "top")
        self.time_cols |= timed
        self._next(f"SELECT {', '.join(cols)} FROM {self.cur} GROUP BY {group} "
                   f"ORDER BY {_out_ident('count')} {direction} LIMIT {n}")
        self.raw_avail = False
        self.order, self.order_named = [("count", not st.rare)], False


def compile_query(query, *, base_where: str = "", base_params=None,
                  default_limit: int = 1000, max_agg_elems: int = 10000) -> Tuple[str, List[str]]:
    """Compile LOQL (text or a parsed ``Query``) to ``(sql, params)``. Pure — no DB."""
    if isinstance(query, str):
        from .parser import parse
        query = parse(query)
    if not query.stages or not isinstance(query.stages[0], N.Search):
        raise LoqlError("a query must begin with a search")
    return _Compiler(query, base_where=base_where, base_params=base_params,
                     default_limit=default_limit, max_agg_elems=max_agg_elems).compile()
