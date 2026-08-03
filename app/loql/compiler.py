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
(``-24h``, ``now``); numeric comparisons/arithmetic cast operands to ``double precision``;
``=`` / ``!=`` against a value containing ``*``/``?`` become bound ``ILIKE`` globs.

Identifiers are values' quieter cousin: they cannot be bound as parameters, so every
name this compiler *emits* — an ``AS`` label, and every later stage that references one
— goes through :func:`_out_ident`, which double-quotes anything Postgres would re-parse.
Without it ``| stats count by user`` compiles to ``SELECT user``, which Postgres reads
as ``CURRENT_USER``: a wrong answer in every row and not one error to notice it by.

Two more things have to still be in SCOPE where they are read, and both used to fail only
at execution — a green compile, then an SQLSTATE that ``run.py`` rewrites into "query
failed", which reads as the analyst's mistake:

* ``search_tsv``, the GIN-indexed vector a bareword search matches. It is a column of
  ``events``, not of a CTE, so every row-level projection has to carry it forward
  (:meth:`_Compiler._passthru`) — otherwise ``| fields vendor | search certutil``
  references a column no longer in scope (42703).
* the result order, which is held as (name, descending) pairs and rendered LATE by
  :meth:`_Compiler._order_by`. Frozen as finished SQL at ``| sort`` time it still named
  the old column after a ``| rename`` or a ``| fields`` that dropped it.
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

from . import nodes as N
from .errors import LoqlError

# base columns exposed by s0 (order matters for `SELECT *`-free projection); src_ip/dst_ip
# are inet, rendered to text via host(). `raw`/`search_tsv` ride along (see _PASSTHRU_SQL)
# but are not output columns.
_BASE_COLS = ["id", "event_time", "vendor", "product", "log_type", "severity", "action",
              "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "app", "user_name",
              "host_name", "rule_name", "bytes_total", "message"]
# The columns every row-level stage CARRIES but never outputs: `raw` (schema-on-read for a
# key no column maps) and `search_tsv` (the full-text vector a bareword search matches). A
# stage that projects an explicit list must re-emit ALL of them — a stage that projects
# only `raw` compiles `| fields vendor | search certutil` into a reference to a column that
# is no longer in scope, and Postgres answers `column "search_tsv" does not exist`.
_PASSTHRU_COLS = ("raw", "search_tsv")
_PASSTHRU_SQL = ", ".join(_PASSTHRU_COLS)
_BASE_SELECT = ("id, event_time, vendor, product, log_type, severity, action, "
                "host(src_ip) AS src_ip, host(dst_ip) AS dst_ip, src_port, dst_port, "
                "protocol, app, user_name, host_name, rule_name, bytes_total, message, "
                + _PASSTHRU_SQL)
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
        self.cur = "s0"

    def _reject_carried(self, names, stage: str) -> None:
        """Refuse an output label that collides with a column this stage CARRIES.

        The carried columns are the blind spot in the duplicate-name check, and they are
        blind precisely BECAUSE they are carried: ``raw`` and ``search_tsv`` are plumbing,
        not fields, so they are deliberately absent from ``self.cols`` — the only list that
        check can see. Every row-level projection then appends them anyway
        (:meth:`_passthru`, or the ``*`` in ``SELECT *, … AS x``), so a stage that LABELS
        one of those names emits it twice:

            | fields raw          ->  SELECT (raw ->> %s) AS raw, raw, search_tsv FROM s0
            | eval raw = 1        ->  SELECT *, %s AS raw FROM s0
            | rename vendor as search_tsv

        all compile clean and die at the next reference with 42702 ``column reference
        "raw" is ambiguous`` — an execution-time failure that reads as the analyst's
        mistake. This converts it into a positioned 400.
        """
        clash = [n for n in dict.fromkeys(names) if n in _PASSTHRU_COLS]
        if clash:
            noun = "a column named" if len(clash) == 1 else "columns named"
            raise LoqlError(
                f"{stage} cannot output {noun} {', '.join(repr(c) for c in clash)} - every "
                f"row-level stage carries {', '.join(repr(c) for c in _PASSTHRU_COLS)} "
                f"beside its own columns (the raw event and its full-text vector), so a "
                f"second column of that name is ambiguous to every stage after this one; "
                f"read a key out of the raw event by naming the key, or pick another label")

    def _passthru(self) -> str:
        """The trailing ``, raw, search_tsv`` an EXPLICIT projection has to re-emit so the
        next stage can still read a jsonb key or run a bareword search. Empty once an
        aggregation has thrown the row away."""
        return f", {_PASSTHRU_SQL}" if self.raw_avail else ""

    # ── the order over the column list ───────────────────────────────────────
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
    def _resolve(self, name: str) -> str:
        real = _ALIASES.get(name, name)
        if real in self.cols:
            return _out_ident(real)
        if self.raw_avail:
            self.params.append(name)
            return "(raw ->> %s)"
        raise LoqlError(f"unknown field {name!r}")

    def _is_time(self, e: N.Expr) -> bool:
        return isinstance(e, N.Field) and _ALIASES.get(e.name, e.name) == "event_time" \
            and "event_time" in self.cols

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
            # `%` is psycopg's placeholder marker, not just an operator. Emitted bare it
            # aborts the WHOLE statement with "incomplete placeholder: '%'; … use '%%'" —
            # every parameter in the query, not only this one. `%%` is the escape.
            #
            # Modulo is documented (docs/LOQL.md, "where/eval expressions") and had never
            # once been compiled by a test, because the suite invariant everybody reaches
            # for — `sql.count("%s") == len(params)` — is BLIND to it: a bare `%` is not a
            # `%s`, so it reports a contented `1 == 1`. Interpolating the emitted SQL
            # against a dummy tuple (`sql % tuple(...)`, Python's own escaping rule) is
            # what sees it, which is why `tests/test_loql.py:assert_bindable` asserts both
            # halves together. psycopg only undoes the escape when a parameter SEQUENCE is
            # passed (`execute(sql, [])` yields `%`, `execute(sql)` leaves `%%`), and a
            # modulo between two columns binds nothing at all — so `run.py` must keep
            # passing `params` even when it is empty.
            # Both operands go through `_numeric`, not `_num`: PostgreSQL has no float8
            # modulo, so a `::double precision` cast turns the client-side placeholder
            # error into a server-side 42883 rather than fixing it. See `_numeric`.
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

    # ── stage compilation ────────────────────────────────────────────────────
    def _next(self, body: str) -> None:
        name = f"s{len(self.ctes)}"                   # s0 already appended -> next is s1
        self.ctes.append(f"{name} AS (\n  {body}\n)")
        self.cur = name

    def compile(self) -> Tuple[str, List[str]]:
        stages = list(self.q.stages)
        first = stages[0]
        assert isinstance(first, N.Search)
        # s0: the search over events
        where = []
        if first.predicate is not None:
            where.append(self._expr(first.predicate))
        if self.base_where:
            # base_where is trusted (built by the app, e.g. an RBAC/time predicate) with its own params
            self.params.extend(self.base_params)
            where.append(f"({self.base_where})")
        w = (" WHERE " + " AND ".join(where)) if where else ""
        self.ctes.append(f"s0 AS (\n  SELECT {_BASE_SELECT} FROM events{w}\n)")

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
        if st.predicate is None:
            return
        self._next(f"SELECT * FROM {self.cur} WHERE {self._expr(st.predicate)}")

    def _st_where(self, st: N.Where) -> None:
        self._next(f"SELECT * FROM {self.cur} WHERE {self._expr(st.expr)}")

    def _st_eval(self, st: N.Eval) -> None:
        # checked against the CARRIED columns too: the `*` emits them beside the label.
        self._reject_carried([st.name], "eval")
        expr = self._expr(st.expr)
        self._next(f"SELECT *, {expr} AS {_out_ident(st.name)} FROM {self.cur}")
        if st.name not in self.cols:
            self.cols.append(st.name)

    def _st_fields(self, st: N.Fields) -> None:
        for n in st.names:
            _ident(n)
        if st.remove:
            keep = [c for c in self.cols if c not in st.names]
        else:
            missing = [n for n in st.names if _ALIASES.get(n, n) not in self.cols and not self.raw_avail]
            if missing:
                raise LoqlError(f"unknown field(s) in fields: {', '.join(missing)}")
            keep = [_ALIASES.get(n, n) for n in st.names]
        if not keep:
            raise LoqlError("fields would remove every column")
        self._reject_carried(keep, "fields")
        self._drop_order(keep, "fields")
        proj = ", ".join(self._resolve_named(c) for c in keep)
        self._next(f"SELECT {proj}{self._passthru()} FROM {self.cur}")
        self.cols = keep

    def _resolve_named(self, name: str) -> str:
        """A column for a projection/rename: a real column, or a raw field aliased to name."""
        if name in self.cols:
            return _out_ident(name)
        self.params.append(name)
        return f"(raw ->> %s) AS {_out_ident(name)}"

    def _st_rename(self, st: N.Rename) -> None:
        mapping = {}
        for src, dst in st.pairs:
            _ident(src); _ident(dst)      # validate; the projection below emits via _out_ident
            if _ALIASES.get(src, src) not in self.cols:
                raise LoqlError(f"cannot rename unknown field {src!r}")
            mapping[_ALIASES.get(src, src)] = dst
        self._reject_carried(mapping.values(), "rename")
        proj = ", ".join(f"{_out_ident(c)} AS {_out_ident(mapping[c])}" if c in mapping
                         else _out_ident(c) for c in self.cols)
        self._next(f"SELECT {proj}{self._passthru()} FROM {self.cur}")
        self.cols = [mapping.get(c, c) for c in self.cols]
        self._reorder(mapping)            # the sort key follows its new label

    def _st_sort(self, st: N.Sort) -> None:
        keys = []
        for name, desc in st.keys:
            real = _ALIASES.get(name, name)
            if real not in self.cols:
                raise LoqlError(f"cannot sort by unknown field {name!r} (eval it first)")
            keys.append((real, desc))
        self.order, self.order_named = keys, True
        self._next(f"SELECT * FROM {self.cur} ORDER BY {self._order_by()}")

    def _st_head(self, st: N.Head) -> None:
        n = max(0, int(st.n))
        order = f" ORDER BY {self._order_by()}" if self.order else ""
        self._next(f"SELECT * FROM {self.cur}{order} LIMIT {n}")

    def _st_dedup(self, st: N.Dedup) -> None:
        for name in st.fields:
            if _ALIASES.get(name, name) not in self.cols:
                raise LoqlError(f"cannot dedup unknown field {name!r}")
        keys = ", ".join(_out_ident(_ALIASES.get(n, n)) for n in st.fields)
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
        by_sel = [f"{self._resolve(b)} AS {_out_ident(b)}" for b in st.by]
        agg_sel = [f"{self._agg_sql(a)} AS {_out_ident(a.out)}" for a in st.aggs]
        group = ""
        if st.by:
            group = " GROUP BY " + ", ".join(self._resolve(b) for b in st.by)
        self._next(f"SELECT {', '.join(by_sel + agg_sel)} FROM {self.cur}{group}")
        self.cols = list(st.by) + [a.out for a in st.aggs]
        self.raw_avail = False
        self.order, self.order_named = [], False

    def _interval(self, span: Optional[str], default: str = "1h") -> str:
        m = re.fullmatch(r"(\d+)([smhd])", span or default)
        if not m:
            raise LoqlError(f"invalid span {span!r}")
        self.params.append(f"{int(m.group(1))} {_SPAN_UNIT[m.group(2)]}")
        return "%s::interval"

    def _st_timechart(self, st: N.Timechart) -> None:
        bucket = f"date_bin({self._interval(st.span)}, event_time, 'epoch'::timestamptz)"
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
        self._next(f"SELECT {', '.join(cols)} FROM {self.cur} GROUP BY {', '.join(group)} ORDER BY 1")
        self.cols = out
        self.raw_avail = False
        self.order, self.order_named = [("_time", False)], False

    def _st_bin(self, st: N.Bin) -> None:
        real = _ALIASES.get(st.field, st.field)
        if real != "event_time":
            raise LoqlError("bin currently supports only the _time field")
        out = st.out or st.field
        bucket = f"date_bin({self._interval(st.span)}, event_time, 'epoch'::timestamptz)"
        self._next(f"SELECT *, {bucket} AS {_out_ident(out)} FROM {self.cur}")
        if out not in self.cols:
            self.cols.append(out)

    def _st_top(self, st: N.Top) -> None:
        # resolve the field ONCE (its %s is bound one param); GROUP BY by output ordinal so the
        # field expression is never re-emitted (which would leave a dangling %s). percent is per
        # by-group when a `by` is present, else the grand total.
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
        self._next(f"SELECT {', '.join(cols)} FROM {self.cur} GROUP BY {group} "
                   f"ORDER BY {_out_ident('count')} {direction} LIMIT {n}")
        self.cols = [st.field] + list(st.by) + ["count", "percent"]
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
