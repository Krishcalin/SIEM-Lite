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
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

from . import nodes as N
from .errors import LoqlError

# base columns exposed by s0 (order matters for `SELECT *`-free projection); src_ip/dst_ip
# are inet, rendered to text via host(); `raw` is carried but not a default output column.
_BASE_COLS = ["id", "event_time", "vendor", "product", "log_type", "severity", "action",
              "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "app", "user_name",
              "host_name", "rule_name", "bytes_total", "message"]
_BASE_SELECT = ("id, event_time, vendor, product, log_type, severity, action, "
                "host(src_ip) AS src_ip, host(dst_ip) AS dst_ip, src_port, dst_port, "
                "protocol, app, user_name, host_name, rule_name, bytes_total, message, raw")
_ALIASES = {"_time": "event_time", "_raw": "message"}
_IDENT_RE = re.compile(r"^[A-Za-z_]\w*$")
_SPAN_UNIT = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
_AGG_SQL = {"count": "count", "sum": "sum", "avg": "avg", "min": "min", "max": "max"}
_FUNC_SQL = {"lower": "lower", "upper": "upper", "length": "length", "abs": "abs",
             "ceil": "ceil", "floor": "floor", "btrim": "btrim", "coalesce": "coalesce",
             "substr": "substr", "replace": "replace", "round": "round"}


def _ident(name: str) -> str:
    if not _IDENT_RE.match(name or ""):
        raise LoqlError(f"invalid identifier {name!r}")     # defence in depth; lexer already gates
    return name


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
        self.raw_avail = True
        self.order_sql: Optional[str] = None     # ORDER BY body over current column NAMES only
        self.cur = "s0"

    # ── field / literal resolution ───────────────────────────────────────────
    def _resolve(self, name: str) -> str:
        real = _ALIASES.get(name, name)
        if real in self.cols:
            return _ident(real)
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
        if op in ("+", "-", "*", "/", "%"):
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

        sel = ", ".join(_ident(c) for c in self.cols)
        tail = f"\nSELECT {sel} FROM {self.cur}"
        if self.order_sql:
            tail += f" ORDER BY {self.order_sql}"
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
        expr = self._expr(st.expr)
        self._next(f"SELECT *, {expr} AS {_ident(st.name)} FROM {self.cur}")
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
        proj = ", ".join(self._resolve_named(c) for c in keep)
        self._next(f"SELECT {proj}{', raw' if self.raw_avail else ''} FROM {self.cur}")
        self.cols = keep

    def _resolve_named(self, name: str) -> str:
        """A column for a projection/rename: a real column, or a raw field aliased to name."""
        if name in self.cols:
            return _ident(name)
        self.params.append(name)
        return f"(raw ->> %s) AS {_ident(name)}"

    def _st_rename(self, st: N.Rename) -> None:
        mapping = {}
        for src, dst in st.pairs:
            _ident(src); _ident(dst)
            if _ALIASES.get(src, src) not in self.cols:
                raise LoqlError(f"cannot rename unknown field {src!r}")
            mapping[_ALIASES.get(src, src)] = dst
        proj = ", ".join(
            f"{_ident(c)} AS {_ident(mapping[c])}" if c in mapping else _ident(c) for c in self.cols)
        self._next(f"SELECT {proj}{', raw' if self.raw_avail else ''} FROM {self.cur}")
        self.cols = [mapping.get(c, c) for c in self.cols]

    def _st_sort(self, st: N.Sort) -> None:
        parts = []
        for name, desc in st.keys:
            real = _ALIASES.get(name, name)
            if real not in self.cols:
                raise LoqlError(f"cannot sort by unknown field {name!r} (eval it first)")
            parts.append(f"{_ident(real)} {'DESC' if desc else 'ASC'}")
        self.order_sql = ", ".join(parts) + " NULLS LAST"
        self._next(f"SELECT * FROM {self.cur} ORDER BY {self.order_sql}")

    def _st_head(self, st: N.Head) -> None:
        n = max(0, int(st.n))
        order = f" ORDER BY {self.order_sql}" if self.order_sql else ""
        self._next(f"SELECT * FROM {self.cur}{order} LIMIT {n}")

    def _st_dedup(self, st: N.Dedup) -> None:
        for name in st.fields:
            if _ALIASES.get(name, name) not in self.cols:
                raise LoqlError(f"cannot dedup unknown field {name!r}")
        keys = ", ".join(_ident(_ALIASES.get(n, n)) for n in st.fields)
        order = f"{keys}, {self.order_sql}" if self.order_sql else keys
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
        by_sel = [f"{self._resolve(b)} AS {_ident(b)}" for b in st.by]
        agg_sel = [f"{self._agg_sql(a)} AS {_ident(a.out)}" for a in st.aggs]
        group = ""
        if st.by:
            group = " GROUP BY " + ", ".join(self._resolve(b) for b in st.by)
        self._next(f"SELECT {', '.join(by_sel + agg_sel)} FROM {self.cur}{group}")
        self.cols = list(st.by) + [a.out for a in st.aggs]
        self.raw_avail = False
        self.order_sql = None

    def _interval(self, span: Optional[str], default: str = "1h") -> str:
        m = re.fullmatch(r"(\d+)([smhd])", span or default)
        if not m:
            raise LoqlError(f"invalid span {span!r}")
        self.params.append(f"{int(m.group(1))} {_SPAN_UNIT[m.group(2)]}")
        return "%s::interval"

    def _st_timechart(self, st: N.Timechart) -> None:
        bucket = f"date_bin({self._interval(st.span)}, event_time, 'epoch'::timestamptz)"
        cols = [f"{bucket} AS _time"]
        group = ["1"]
        out = ["_time"]
        if st.by:
            cols.append(f"{self._resolve(st.by)} AS {_ident(st.by)}")
            group.append("2")
            out.append(st.by)
        for a in st.aggs:
            cols.append(f"{self._agg_sql(a)} AS {_ident(a.out)}")
            out.append(a.out)
        self._next(f"SELECT {', '.join(cols)} FROM {self.cur} GROUP BY {', '.join(group)} ORDER BY 1")
        self.cols = out
        self.raw_avail = False
        self.order_sql = "_time ASC"

    def _st_bin(self, st: N.Bin) -> None:
        real = _ALIASES.get(st.field, st.field)
        if real != "event_time":
            raise LoqlError("bin currently supports only the _time field")
        out = st.out or st.field
        bucket = f"date_bin({self._interval(st.span)}, event_time, 'epoch'::timestamptz)"
        self._next(f"SELECT *, {bucket} AS {_ident(out)} FROM {self.cur}")
        if out not in self.cols:
            self.cols.append(out)

    def _st_top(self, st: N.Top) -> None:
        # resolve the field ONCE (its %s is bound one param); GROUP BY by output ordinal so the
        # field expression is never re-emitted (which would leave a dangling %s). percent is per
        # by-group when a `by` is present, else the grand total.
        field_sql = self._resolve(st.field)
        by_sel = [f"{self._resolve(b)} AS {_ident(b)}" for b in st.by]
        direction = "ASC" if st.rare else "DESC"
        n = max(1, int(st.n))
        over = ("PARTITION BY " + ", ".join(self._resolve(b) for b in st.by)) if st.by else ""
        percent = f"round(100.0 * count(*) / NULLIF(sum(count(*)) OVER ({over}), 0), 2) AS percent"
        cols = [f"{field_sql} AS {_ident(st.field)}"] + by_sel + ["count(*) AS count", percent]
        group = ", ".join(str(i) for i in range(1, 2 + len(st.by)))    # GROUP BY 1, 2, … (ordinals)
        self._next(f"SELECT {', '.join(cols)} FROM {self.cur} GROUP BY {group} "
                   f"ORDER BY count {direction} LIMIT {n}")
        self.cols = [st.field] + list(st.by) + ["count", "percent"]
        self.raw_avail = False
        self.order_sql = f"count {direction}"


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
