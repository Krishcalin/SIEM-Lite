# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""The frozen LOQL parse tree (AST).

This is the STABLE CONTRACT between the parser and the compiler — every downstream
feature (dashboards, saved searches, RBAC row-filter injection, federation) reads
these node types, so they change rarely and deliberately. Expression nodes model a
closed, typed grammar (literals, field refs, unary/binary ops, whitelisted function
calls, IN-lists) that the compiler renders to parameterized SQL — never Python eval.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Union


# ── expressions (used by search / where / eval) ───────────────────────────────
@dataclass(frozen=True)
class Lit:
    value: object
    kind: str            # "num" | "str" | "bool" | "null"


@dataclass(frozen=True)
class Field:
    name: str


@dataclass(frozen=True)
class Unary:
    op: str              # "not" | "-"
    operand: "Expr"


@dataclass(frozen=True)
class Binary:
    op: str              # and or = != < <= > >= + - * / % . like
    left: "Expr"
    right: "Expr"


@dataclass(frozen=True)
class Func:
    name: str            # whitelisted (lower/upper/len/coalesce/round/abs/…) + internal _fts
    args: Tuple["Expr", ...]


@dataclass(frozen=True)
class InList:
    target: "Expr"
    items: Tuple["Expr", ...]


Expr = Union[Lit, Field, Unary, Binary, Func, InList]


# ── an aggregation term inside stats / timechart / top / rare ─────────────────
@dataclass(frozen=True)
class Agg:
    func: str                       # count sum avg min max dc values list
    arg: Optional[str]              # field name, or None for count(*)
    out: str                        # output column name


# ── pipeline stages ───────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Search:
    predicate: Optional[Expr]       # None -> match all


@dataclass(frozen=True)
class Where:
    expr: Expr


@dataclass(frozen=True)
class Eval:
    name: str
    expr: Expr


@dataclass(frozen=True)
class Fields:
    names: Tuple[str, ...]
    remove: bool = False            # `fields - a, b` drops columns


@dataclass(frozen=True)
class Rename:
    pairs: Tuple[Tuple[str, str], ...]   # (from, to)


@dataclass(frozen=True)
class Sort:
    keys: Tuple[Tuple[str, bool], ...]   # (field, descending)


@dataclass(frozen=True)
class Head:
    n: int


@dataclass(frozen=True)
class Dedup:
    fields: Tuple[str, ...]


@dataclass(frozen=True)
class Stats:
    aggs: Tuple[Agg, ...]
    by: Tuple[str, ...] = ()


@dataclass(frozen=True)
class Top:
    field: str
    n: int = 10
    rare: bool = False              # rare = ascending
    by: Tuple[str, ...] = ()


@dataclass(frozen=True)
class Bin:
    field: str
    span: Optional[str]             # e.g. "1h", "5m", "1d"; None -> auto for _time
    out: Optional[str] = None


@dataclass(frozen=True)
class Timechart:
    aggs: Tuple[Agg, ...]
    span: Optional[str] = None
    by: Optional[str] = None        # a single split-by field


Stage = Union[Search, Where, Eval, Fields, Rename, Sort, Head, Dedup, Stats, Top, Bin, Timechart]


@dataclass(frozen=True)
class Query:
    stages: Tuple[Stage, ...]
