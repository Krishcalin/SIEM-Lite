# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""LOQL lexer + recursive-descent parser: query text -> a ``nodes.Query`` AST.

The parser is the SECURITY GATE: it accepts only the closed grammar and raises
``LoqlError`` on anything else, so a malformed/hostile query is a clean 400 before a
single character reaches SQL. It never evaluates anything — it only builds the tree.

Lexing is deliberately simple and unambiguous: identifiers are ``\\w+`` (field names
and keywords), and comparison/arithmetic operators are always their own tokens. A
value containing special characters (an IP, a path, a wildcard) must therefore be
quoted — ``src_ip="10.0.0.1"``, ``url="/admin*"`` — which keeps the grammar tiny and
leaves the wildcard/CIDR handling entirely to bound parameters.

``:`` is a token solely so ``from datamodel:<Name>`` can be spelled the way the roadmap
promises it. No other production accepts one, so a stray colon is still rejected — as a
positioned parse error now rather than an "unexpected character" from the lexer.
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

from . import nodes as N
from .errors import LoqlError

# multi-char operators must be tried before single-char ones
_TOKEN_RE = re.compile(r"""
    (?P<WS>\s+)
  | (?P<STR>'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")
  | (?P<NUM>\d+(?:\.\d+)?)
  | (?P<OP>!=|<=|>=|[=<>+\-*/%.])
  | (?P<PIPE>\|)
  | (?P<COMMA>,)
  | (?P<COLON>:)
  | (?P<LP>\()
  | (?P<RP>\))
  | (?P<ID>[A-Za-z_]\w*)
""", re.VERBOSE)

_KEYWORDS = {"and", "or", "not", "by", "as", "in", "true", "false", "null", "like"}
_CMP = {"=", "!=", "<", "<=", ">", ">="}
# functions allowed inside where/eval expressions -> (sql_name, argcount or None for varargs)
_FUNCS = {
    "lower": ("lower", 1), "upper": ("upper", 1), "len": ("length", 1),
    "length": ("length", 1), "abs": ("abs", 1), "round": ("round", None),
    "ceil": ("ceil", 1), "floor": ("floor", 1), "trim": ("btrim", None),
    "coalesce": ("coalesce", None), "substr": ("substr", None),
    "replace": ("replace", 3), "if": ("__if__", 3), "isnull": ("__isnull__", 1),
    "isnotnull": ("__isnotnull__", 1),
}
_COMMANDS = {"search", "where", "eval", "fields", "rename", "sort", "head",
             "dedup", "stats", "top", "rare", "bin", "timechart", "datamodel"}
_AGG_FUNCS = {"count", "sum", "avg", "min", "max", "dc", "distinct_count", "values", "list"}


class _Tok:
    __slots__ = ("kind", "val", "pos")

    def __init__(self, kind: str, val: str, pos: int):
        self.kind, self.val, self.pos = kind, val, pos

    def __repr__(self):  # pragma: no cover - debugging aid
        return f"{self.kind}:{self.val!r}"


def _lex(text: str) -> List[_Tok]:
    toks: List[_Tok] = []
    i = 0
    for m in _TOKEN_RE.finditer(text):
        if m.start() != i:
            raise LoqlError(f"unexpected character {text[i]!r}", i)
        i = m.end()
        kind = m.lastgroup
        if kind == "WS":
            continue
        val = m.group()
        if kind == "ID" and val.lower() in _KEYWORDS:
            toks.append(_Tok("KW", val.lower(), m.start()))
        else:
            toks.append(_Tok(kind, val, m.start()))
    if i != len(text):
        raise LoqlError(f"unexpected character {text[i]!r}", i)
    toks.append(_Tok("EOF", "", len(text)))
    return toks


def _unquote(s: str) -> str:
    inner = s[1:-1]
    return re.sub(r"\\(.)", r"\1", inner)


class _Parser:
    _MAX_DEPTH = 80           # cap expression nesting so a hostile query fails-closed (LoqlError,
                              # ~640 stack frames) well before Python's ~1000 recursion limit -> 500.
                              # No legitimate query nests parens/functions/NOTs anywhere near this deep.

    def __init__(self, toks: List[_Tok]):
        self.toks = toks
        self.i = 0
        self.depth = 0

    def _descend(self) -> None:
        self.depth += 1
        if self.depth > self._MAX_DEPTH:
            raise LoqlError("expression nested too deeply", self.cur.pos)

    # -- token helpers --------------------------------------------------------
    @property
    def cur(self) -> _Tok:
        return self.toks[self.i]

    def _at(self, kind: str, val: Optional[str] = None) -> bool:
        t = self.cur
        return t.kind == kind and (val is None or t.val == val)

    def _eat(self, kind: str, val: Optional[str] = None) -> _Tok:
        t = self.cur
        if t.kind != kind or (val is not None and t.val != val):
            want = val if val is not None else kind
            raise LoqlError(f"expected {want!r} but found {t.val or t.kind!r}", t.pos)
        self.i += 1
        return t

    def _ident_or_kw(self) -> str:
        """A field/name token: an ID, or a keyword used as a name (e.g. a field
        literally called `count`). Returns the text."""
        t = self.cur
        if t.kind in ("ID", "KW"):
            self.i += 1
            return t.val
        raise LoqlError(f"expected a field name but found {t.val or t.kind!r}", t.pos)

    # -- top level ------------------------------------------------------------
    def parse(self) -> N.Query:
        stages: List[N.Stage] = []
        dm = self._datamodel_prefix()                # `from datamodel:<Name>`, or None
        if self._at("PIPE"):
            stages.append(N.Search(None, dm))        # leading pipe -> match-all
        else:
            pred = self._search_expr()
            stages.append(N.Search(pred, dm))
        while self._at("PIPE"):
            self._eat("PIPE")
            pos = self.cur.pos
            stage = self._command()
            if isinstance(stage, N.Search) and stage.datamodel is not None:
                self._set_datamodel(stages, stage.datamodel, pos)   # `| datamodel <Name>`
                continue
            stages.append(stage)
        self._eat("EOF")
        return N.Query(tuple(stages))

    # -- the data-model source ------------------------------------------------
    def _datamodel_prefix(self) -> Optional[str]:
        """The roadmap-literal source spelling ``from datamodel:<Name>``.

        It desugars to the very same ``Search.datamodel`` field that ``| datamodel
        <Name>`` sets, so the two spellings are one AST and one compiler path — an alias
        that produced its own node would be a second dialect to keep in step forever.

        ``from`` stays an ordinary bareword everywhere else (mail logs really do carry a
        ``from`` field), so the prefix is recognised only by the three-token shape
        ``from`` ``datamodel`` ``:``. ``from datamodel`` WITHOUT a colon is rejected
        rather than read as a two-word full-text search: it is a typo with near-certainty,
        and the wrong reading would answer quietly instead of pointing at the mistake.
        """
        if not (self.cur.kind == "ID" and self.cur.val.lower() == "from"):
            return None
        nxt = self.toks[self.i + 1]
        if not (nxt.kind == "ID" and nxt.val.lower() == "datamodel"):
            return None
        self.i += 2
        if not self._at("COLON"):
            raise LoqlError("expected ':' after 'datamodel' "
                            "(write: from datamodel:Authentication)", self.cur.pos)
        self._eat("COLON")
        return self._model_name()

    def _model_name(self) -> str:
        """A CIM data-model name: a bareword (``Authentication``) or a quoted string.

        Deliberately NOT checked against the registry here — the parser stays pure
        grammar and importable without the YAML, and the compiler is the one place that
        resolves a name (and raises for an unknown one)."""
        t = self.cur
        if t.kind == "STR":
            self.i += 1
            name = _unquote(t.val).strip()
        elif t.kind in ("ID", "KW"):
            self.i += 1
            name = t.val
        else:
            raise LoqlError(f"expected a data model name but found {t.val or t.kind!r}", t.pos)
        if not name:
            raise LoqlError("a data model name cannot be empty", t.pos)
        return name

    def _set_datamodel(self, stages: List[N.Stage], name: str, pos: int) -> None:
        """Fold ``| datamodel <Name>`` into the query's source node.

        A data model chooses what the pipeline READS, so it can only be the first stage:
        after a ``stats`` there are no events left to re-source, and after a search term
        that term was written against the columns the model replaces. Both misuses are a
        positioned error rather than a silently different query."""
        head = stages[0]
        assert isinstance(head, N.Search)
        if len(stages) != 1 or head.datamodel is not None or head.predicate is not None:
            raise LoqlError("'datamodel' is a source and must come first - write "
                            "'| datamodel <Name> | ...' or 'from datamodel:<Name>'", pos)
        stages[0] = N.Search(None, name)

    # -- commands -------------------------------------------------------------
    def _command(self) -> N.Stage:
        if self.cur.kind not in ("ID", "KW"):
            raise LoqlError(f"expected a command after '|' but found {self.cur.val or self.cur.kind!r}", self.cur.pos)
        name = self.cur.val.lower()
        if name == "from":                            # the source spelling, in the wrong place
            raise LoqlError("'from datamodel:<Name>' must start the query, not follow a '|' "
                            "(use '| datamodel <Name>' as the first stage)", self.cur.pos)
        if name not in _COMMANDS:
            raise LoqlError(f"unknown command {name!r}", self.cur.pos)
        self.i += 1
        return getattr(self, f"_cmd_{name}")()

    def _cmd_datamodel(self) -> N.Stage:
        # A source, not a transform — `parse` folds this into stages[0] via _set_datamodel.
        return N.Search(None, self._model_name())

    def _cmd_search(self) -> N.Stage:
        return N.Search(self._search_expr())

    def _cmd_where(self) -> N.Stage:
        return N.Where(self._expr(fts=False))

    def _cmd_eval(self) -> N.Stage:
        name = self._ident_or_kw()
        self._eat("OP", "=")
        return N.Eval(name, self._expr(fts=False))

    def _cmd_fields(self) -> N.Stage:
        remove = False
        if self._at("OP", "-") or self._at("OP", "+"):
            remove = self.cur.val == "-"
            self.i += 1
        names = [self._ident_or_kw()]
        while self._at("COMMA"):
            self._eat("COMMA"); names.append(self._ident_or_kw())
        return N.Fields(tuple(names), remove)

    def _cmd_rename(self) -> N.Stage:
        pairs = [self._rename_pair()]
        while self._at("COMMA"):
            self._eat("COMMA"); pairs.append(self._rename_pair())
        return N.Rename(tuple(pairs))

    def _rename_pair(self) -> Tuple[str, str]:
        src = self._ident_or_kw()
        self._eat("KW", "as")
        return (src, self._ident_or_kw())

    def _cmd_sort(self) -> N.Stage:
        keys = [self._sort_key()]
        while self._at("COMMA"):
            self._eat("COMMA"); keys.append(self._sort_key())
        return N.Sort(tuple(keys))

    def _sort_key(self) -> Tuple[str, bool]:
        desc = False
        if self._at("OP", "-") or self._at("OP", "+"):
            desc = self.cur.val == "-"
            self.i += 1
        return (self._ident_or_kw(), desc)

    def _cmd_head(self) -> N.Stage:
        return N.Head(self._int("head"))

    def _cmd_dedup(self) -> N.Stage:
        names = [self._ident_or_kw()]
        while self._at("COMMA"):
            self._eat("COMMA"); names.append(self._ident_or_kw())
        return N.Dedup(tuple(names))

    def _cmd_stats(self) -> N.Stage:
        aggs = [self._agg()]
        while self._at("COMMA"):
            self._eat("COMMA"); aggs.append(self._agg())
        by = self._by_clause()
        return N.Stats(tuple(aggs), by)

    def _cmd_top(self) -> N.Stage:
        return self._top_like(rare=False)

    def _cmd_rare(self) -> N.Stage:
        return self._top_like(rare=True)

    def _top_like(self, *, rare: bool) -> N.Stage:
        n = 10
        if self._at("NUM"):
            n = self._int("top")
        field = self._ident_or_kw()
        by = self._by_clause()
        return N.Top(field, n, rare, by)

    def _cmd_bin(self) -> N.Stage:
        span = self._span_opt()
        field = self._ident_or_kw()
        out = None
        if self._at("KW", "as"):
            self._eat("KW", "as"); out = self._ident_or_kw()
        return N.Bin(field, span, out)

    def _cmd_timechart(self) -> N.Stage:
        span = self._span_opt()
        aggs = [self._agg()]
        while self._at("COMMA"):
            self._eat("COMMA"); aggs.append(self._agg())
        by = None
        if self._at("KW", "by"):
            self._eat("KW", "by"); by = self._ident_or_kw()
        return N.Timechart(tuple(aggs), span, by)

    # -- shared command bits --------------------------------------------------
    def _agg(self) -> N.Agg:
        func = self._ident_or_kw().lower()
        if func == "distinct_count":
            func = "dc"
        if func not in _AGG_FUNCS:
            raise LoqlError(f"unknown stats function {func!r}", self.cur.pos)
        arg = None
        if self._at("LP"):                            # parens optional for bare `count`
            self._eat("LP")
            if not self._at("RP"):
                arg = self._ident_or_kw()
            self._eat("RP")
        if func != "count" and arg is None:
            raise LoqlError(f"{func}() needs a field", self.cur.pos)
        out = f"{func}_{arg}" if arg else "count"
        if self._at("KW", "as"):
            self._eat("KW", "as"); out = self._ident_or_kw()
        return N.Agg(func, arg, out)

    def _by_clause(self) -> Tuple[str, ...]:
        if not self._at("KW", "by"):
            return ()
        self._eat("KW", "by")
        names = [self._ident_or_kw()]
        while self._at("COMMA"):
            self._eat("COMMA"); names.append(self._ident_or_kw())
        return tuple(names)

    def _span_opt(self) -> Optional[str]:
        # `span=1h` (span is a soft keyword: ID 'span' then '=' then value)
        if self.cur.kind == "ID" and self.cur.val.lower() == "span" and self.toks[self.i + 1].kind == "OP" and self.toks[self.i + 1].val == "=":
            self.i += 2
            t = self.cur
            if t.kind == "NUM":                       # `1h` lexes as NUM(1)+ID(h); recombine if adjacent
                nxt = self.toks[self.i + 1]
                if nxt.kind == "ID" and nxt.val in ("s", "m", "h", "d") and t.pos + len(t.val) == nxt.pos:
                    self.i += 2
                    return t.val + nxt.val
                raise LoqlError(f"span needs a unit (e.g. 30s, 5m, 1h, 1d), got {t.val!r}", t.pos)
            if t.kind == "STR":
                self.i += 1
                v = _unquote(t.val)
                if not re.fullmatch(r"\d+[smhd]", v):
                    raise LoqlError(f"invalid span {v!r} (use e.g. 30s, 5m, 1h, 1d)", t.pos)
                return v
            raise LoqlError("span needs a value like 1h", t.pos)
        return None

    def _int(self, ctx: str) -> int:
        t = self._eat("NUM")
        if "." in t.val:
            raise LoqlError(f"{ctx} needs a whole number", t.pos)
        return int(t.val)

    # -- expressions ----------------------------------------------------------
    def _search_expr(self) -> Optional[N.Expr]:
        if self._at("OP", "*"):                       # leading `*` = match all
            self.i += 1
        if self._at("PIPE") or self._at("EOF"):
            return None
        return self._expr(fts=True)

    def _expr(self, *, fts: bool) -> N.Expr:
        return self._or(fts)

    def _or(self, fts: bool) -> N.Expr:
        self._descend()                               # re-entered on every '(' / function arg
        try:
            left = self._and(fts)
            while self._at("KW", "or"):
                self._eat("KW", "or"); left = N.Binary("or", left, self._and(fts))
            return left
        finally:
            self.depth -= 1

    def _and(self, fts: bool) -> N.Expr:
        left = self._not(fts)
        while True:
            if self._at("KW", "and"):
                self._eat("KW", "and"); left = N.Binary("and", left, self._not(fts))
            elif self._starts_atom() and not self._at("KW", "or"):
                left = N.Binary("and", left, self._not(fts))   # implicit AND
            else:
                return left

    def _not(self, fts: bool) -> N.Expr:
        if self._at("KW", "not"):
            self._descend()                           # `not not not …` chains recurse here
            try:
                self._eat("KW", "not"); return N.Unary("not", self._not(fts))
            finally:
                self.depth -= 1
        return self._comparison(fts)

    def _starts_atom(self) -> bool:
        t = self.cur
        if t.kind in ("NUM", "STR", "LP"):
            return True
        if t.kind == "KW" and t.val in ("not", "true", "false", "null"):
            return True
        if t.kind == "ID":
            return True
        return False

    def _comparison(self, fts: bool) -> N.Expr:
        left = self._additive()
        t = self.cur
        if t.kind == "OP" and t.val in _CMP:
            self.i += 1
            return N.Binary(t.val, left, self._rhs(fts))
        if t.kind == "KW" and t.val == "like":
            self._eat("KW", "like"); return N.Binary("like", left, self._rhs(fts))
        if t.kind == "KW" and t.val == "in":
            return self._in_list(left, fts)
        # standalone atom (no comparison operator): in SEARCH mode a bare field/word/number
        # is a full-text term; elsewhere (where/eval/args) it is just a value expression.
        if fts:
            if isinstance(left, N.Field):
                return N.Func("_fts", (N.Lit(left.name, "str"),))
            if isinstance(left, N.Lit) and left.kind in ("str", "num"):
                return N.Func("_fts", (N.Lit(str(left.value), "str"),))
        return left

    def _rhs(self, fts: bool) -> N.Expr:
        """The right-hand side of a comparison. In SEARCH mode it is a VALUE (a bare
        word is the string value, not a field ref: ``vendor=cisco`` means the string
        "cisco"); in where/eval mode it is a full expression (fields allowed)."""
        return self._search_value() if fts else self._additive()

    def _search_value(self) -> N.Expr:
        t = self.cur
        if t.kind == "STR":
            self.i += 1; return N.Lit(_unquote(t.val), "str")
        if t.kind == "NUM":
            self.i += 1; return N.Lit(float(t.val) if "." in t.val else int(t.val), "num")
        if t.kind in ("ID", "KW"):
            self.i += 1; return N.Lit(t.val, "str")          # bareword -> string value
        if t.kind == "OP" and t.val == "*":
            self.i += 1; return N.Lit("*", "str")            # field=* -> "exists" (glob %)
        raise LoqlError("expected a value after the comparison operator", t.pos)

    def _in_list(self, target: N.Expr, fts: bool) -> N.Expr:
        self._eat("KW", "in"); self._eat("LP")
        items = [self._rhs(fts)]
        while self._at("COMMA"):
            self._eat("COMMA"); items.append(self._rhs(fts))
        self._eat("RP")
        return N.InList(target, tuple(items))

    def _additive(self) -> N.Expr:
        left = self._term()
        while self._at("OP") and self.cur.val in ("+", "-", "."):
            op = self.cur.val; self.i += 1
            left = N.Binary(op, left, self._term())
        return left

    def _term(self) -> N.Expr:
        left = self._factor()
        while self._at("OP") and self.cur.val in ("*", "/", "%"):
            op = self.cur.val; self.i += 1
            left = N.Binary(op, left, self._factor())
        return left

    def _factor(self) -> N.Expr:
        if self._at("OP", "-"):
            self._eat("OP", "-"); return N.Unary("-", self._factor())
        return self._primary()

    def _primary(self) -> N.Expr:
        t = self.cur
        if t.kind == "NUM":
            self.i += 1
            return N.Lit(float(t.val) if "." in t.val else int(t.val), "num")
        if t.kind == "STR":
            self.i += 1
            return N.Lit(_unquote(t.val), "str")
        if t.kind == "KW" and t.val in ("true", "false"):
            self.i += 1
            return N.Lit(t.val == "true", "bool")
        if t.kind == "KW" and t.val == "null":
            self.i += 1
            return N.Lit(None, "null")
        if t.kind == "LP":
            self._eat("LP"); e = self._or(fts=False); self._eat("RP"); return e
        if t.kind in ("ID", "KW"):
            name = t.val
            self.i += 1
            if self._at("LP"):                        # function call
                return self._func_call(name, t.pos)
            return N.Field(name)
        raise LoqlError(f"unexpected {t.val or t.kind!r} in expression", t.pos)

    def _func_call(self, name: str, pos: int) -> N.Expr:
        fn = name.lower()
        if fn not in _FUNCS:
            raise LoqlError(f"unknown function {name!r}", pos)
        self._eat("LP")
        args = []
        if not self._at("RP"):
            args.append(self._or(fts=False))
            while self._at("COMMA"):
                self._eat("COMMA"); args.append(self._or(fts=False))
        self._eat("RP")
        sqlname, argc = _FUNCS[fn]
        if argc is not None and len(args) != argc:
            raise LoqlError(f"{name}() takes {argc} argument(s), got {len(args)}", pos)
        return N.Func(sqlname, tuple(args))           # carry the compiler's SQL/internal name


def parse(text: str) -> N.Query:
    """Parse LOQL query text into a ``nodes.Query`` AST, or raise ``LoqlError`` (never an
    uncaught exception — a malformed/hostile query must be a clean 400, not a 500)."""
    if not text or not text.strip():
        raise LoqlError("empty query")
    try:
        return _Parser(_lex(text)).parse()
    except RecursionError:                            # belt-and-suspenders behind the depth cap
        raise LoqlError("query is too complex")
