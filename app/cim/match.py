# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Decide which CIM data models an event belongs to — the runtime membership evaluator.

This is the ONLY implementation of membership. ``events.cim_models`` is a plain
``text[]`` column declared in ``schema.sql`` and filled per row from :func:`tags_for`
at ingest, exactly the way ``search_tsv`` is filled from ``normalize.tsv_text`` — not a
generated column. That choice is what lets the detection engine see model membership
*before* the row is inserted (``pipeline.write_stream`` evaluates every event as it
streams, and only flushes to the table in chunks), and it keeps the rule rewritable on
PostgreSQL 16, which freezes a generation expression at ``ADD COLUMN``.

Because the rule is data, this module is pure: frozen :mod:`app.cim.spec` objects in,
booleans out. No SQL, no I/O, no database — so the whole CIM layer is unit-testable on
a machine with no PostgreSQL, which is most of them.

PARITY WITH THE SQL SPEC
------------------------
:func:`app.cim.sql.membership_sql` stays the readable, runnable *spec* of membership.
Two implementations of one rule diverge silently, so the points of contact are spelled
out here and should be read as a contract:

===========================================  ==========================================
SQL (``sql.membership_sql``)                 Python (this module)
===========================================  ==========================================
``lower(<lhs>) IN ('a', 'b')``               :func:`_text` lower-cases the event value
``raw ->> 'k'``                              :func:`_raw_value`, key used byte-exact
``raw #>> ARRAY['a', 'b']``                  segment walk, one dict level per segment
``COALESCE(p1, p2)``                         first alternative with a non-``None`` value
``NULL``                                     ``None`` — a term with no value never hits
``AND`` of terms / ``OR`` of clauses         :func:`clause_matches` / :func:`model_matches`
===========================================  ==========================================

Three differences are deliberate and documented rather than papered over:

1. **Whitespace.** Python ``.strip()``s the event value before comparing; the SQL does
   not (``lower(vendor) = 'okta'``). A value stored as ``" okta "`` therefore matches
   here and not there. Python is the authoritative evaluator, so this is a one-way
   looseness — but ``lower()`` in ``sql._term_sql`` would need to become ``lower(btrim(…))``
   for a set-based audit query to agree with the stored column.
2. **Array subscripts.** jsonb ``#>>`` can index INTO a JSON array with a numeric path
   segment; this walker only descends objects, so a numeric segment against an array
   yields no value. No shipped model indexes an array, and guessing at ``#>``'s
   subscript rules without a database to check against would put a silent disagreement
   in the one place we cannot afford one. If a model ever needs it, ``sql._path_sql``
   and :func:`_raw_value` must change together.
3. **Containers.** A raw value that is an object or an array renders as JSON *text*
   under ``->>``; here it yields no value. jsonb orders object keys by length then
   bytewise, which is not Python's serialization order, so any agreement between the
   two renderings would be accidental. A membership value is a string or an integer —
   never a container — so nothing reachable from the registry depends on this.

Note the DELIBERATE divergence from ``detection.engine.flatten_event``, which lower-cases
raw keys and dot-joins nested ones. Here a jsonb key is byte-exact and is NEVER split on
``.``, because Zeek writes literal dotted TOP-LEVEL keys (``id.orig_h``): lower-casing or
splitting would break every Zeek mapping and silently empty the Network model. It looks
like an inconsistency; it is the correct one.

USING IT
--------
* ingest — ``db._row`` binds ``cim_models_for(evt)`` (``None``, not ``[]``, when the event
  belongs to nothing, so the GIN index stays sparse). Membership is wanted TWICE per
  ingested event — once by the detection ``datamodels:`` gate as the event streams, once
  here when the chunk flushes — so ``pipeline.write_stream`` resolves it once per event
  and threads it to both: ``cim_models_for(evt, tags=<resolved>)`` skips the walk and
  only canonicalizes. Threading is optional on both sides, and omitting it derives the
  value here exactly as before.
* backfill — ``db.backfill_cim`` must re-evaluate **in Python** and ``UPDATE``, not run
  ``membership_sql``: one evaluator, per the design decision above. :func:`tags_for`
  therefore accepts a stored ``events`` row (any mapping with the nine term columns and
  ``raw``) as well as a :class:`~app.models.NormalizedEvent`.
* tests — :func:`model_matches` is the readable reference walk and :func:`tags_for` the
  compiled one; asserting they agree on a corpus is the guard that keeps them together.
  They share :func:`_term_hit`, so only the AND/OR nesting is written twice.
"""
from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Optional, Tuple, Union

from ..models import NormalizedEvent
from . import sql as cim_sql
from .registry import get_registry
from .spec import CimClause, CimError, CimModel, CimRegistry, CimTerm

# Stdlib logging, not structlog: the charter forbids new dependencies, and every other
# module in the tree (pipeline, db, detection.engine, main, api) takes this exact line.
log = logging.getLogger("logocean")

# What can be evaluated: a freshly parsed event, or a stored `events` row read back as
# a mapping (psycopg `dict_row`). Both expose the nine term columns by name and a `raw`
# mapping, which is all a membership term ever reads — so ONE evaluator serves both the
# ingest path and `db.backfill_cim`.
EventLike = Union[NormalizedEvent, Mapping[str, Any]]


# ── contract self-check ───────────────────────────────────────────────────────
# Every column a membership term may test must ALSO be a NormalizedEvent field, or
# `getattr` would quietly return None and the model would simply stop matching. That
# silent dead membership is the exact failure this backbone exists to fix, so the two
# whitelists are checked against each other at import — a mismatched edit to either
# side fails on the first test run instead of in production.
_UNKNOWN_TERM_COLUMNS: Tuple[str, ...] = tuple(sorted(
    c for c in cim_sql._TERM_COLUMNS if c not in NormalizedEvent.__dataclass_fields__))
if _UNKNOWN_TERM_COLUMNS:                                          # pragma: no cover
    raise CimError(
        "membership term column(s) " + ", ".join(_UNKNOWN_TERM_COLUMNS) +
        " are in app.cim.sql._TERM_COLUMNS but are not fields of NormalizedEvent; "
        "the Python evaluator could only ever read None for them")


# ── value resolution ──────────────────────────────────────────────────────────
def _text(value: Any) -> Optional[str]:
    """The comparison form of one event value — what ``->>`` would render, lower-cased.

    ``None`` means "no value", and a term with no value never matches: ``lower(NULL) =
    'x'`` is NULL, not true. Coercion is where the Windows fix lives — the registry
    lower-cases its YAML values to strings, so the integer ``4625`` written back by
    ``parsers.windows_security`` has to arrive here as ``'4625'``.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return value.strip().lower()
    if isinstance(value, bool):
        # BEFORE the int arm — bool is a subclass of int. jsonb renders a boolean as
        # 'true'/'false'; Python's str() gives 'True', so spell the mapping out.
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        # jsonb renders a number from its text form, and an int carries no padding, no
        # decimal point and no whitespace — so str() is byte-identical to `->>`, which
        # is exactly what makes raw {"event_id": 4625} meet the YAML's 4625. A float's
        # rendering can diverge at extreme magnitudes, but `registry._values` refuses
        # float VALUES, so a float event value can only ever fail to match.
        return str(value)
    if isinstance(value, (dict, list, tuple)):
        return None                       # a container is never a value — see PARITY
    if isinstance(value, (bytes, bytearray)):
        # No jsonb rendering exists (psycopg cannot even store this), but str() would
        # give the misleading "b'okta'" — decode to the text the author clearly meant.
        return bytes(value).decode("utf-8", "replace").strip().lower()
    try:
        return str(value).strip().lower()
    except Exception:                     # noqa: BLE001 — a bad __str__ must not
        return None                       # abort an ingest batch over one event


# Both accessors below are resolved ONCE per event and threaded through `_term_hit` —
# that is the whole reason it takes `ctext`/`raw` rather than the event. A full registry
# walk is ~40 terms per event, and at that multiplier the two things done here get
# expensive: deciding "row or event?" through the Mapping ABC (~360ns a time) and
# re-coercing the same column (six models test `log_type`, so `_text` would strip+lower
# the same string six times).
#
# Coercing UP FRONT is therefore right; coercing ALL NINE is not. The alternative worth
# measuring against is not "re-coerce per term" (strictly worse) but "coerce only the
# columns some term actually READS" (strictly better) — and the shipped 11-model /
# 36-clause registry reads four of the nine: action, log_type, product, vendor. The
# other five are two allocations each spent on a value nothing will ask for. `_compile`
# already visits every term once per registry, so it hands `tags_for` that exact set for
# free (see `_Plan.columns`); a registry whose terms are all `raw:` narrows to none.
#
# The nine names below stay as the DEFAULT, for the reference walk (`term_matches` /
# `clause_matches`), which compiles per call and so has no plan to narrow with. Sorted,
# so the per-event dict is built deterministically (and a dict dump in a failing test
# reads the same every run).
_TERM_COLUMN_NAMES: Tuple[str, ...] = tuple(sorted(cim_sql._TERM_COLUMNS))


def _column_texts(evt: EventLike,
                  columns: Tuple[str, ...] = _TERM_COLUMN_NAMES) -> dict[str, Optional[str]]:
    """The named columns, coerced once each — see :func:`_text`.

    ``columns`` MUST cover every column read by the terms this mapping will be evaluated
    against: :func:`_term_hit` reads it with ``.get``, so a column left out would resolve
    to "no value" and kill its term — silent dead membership, the very failure this
    backbone exists to remove. Only two callers narrow it, and both derive the set from
    the same compiled terms they then evaluate (:func:`_compile`), so the two cannot
    drift; everything else takes the nine-name default.

    Reads a stored row by key and a ``NormalizedEvent`` through its ``__dict__``, and
    falls back to ``getattr`` for an object that has neither (a future slotted event).
    That last branch is never taken today, but returning an empty mapping instead would
    make every column term read ``None`` — the same silent failure.
    """
    if not columns:
        return {}
    if isinstance(evt, Mapping):
        get = evt.get
    else:
        d = getattr(evt, "__dict__", None)
        get = d.get if isinstance(d, dict) else (lambda c: getattr(evt, c, None))
    return {c: _text(get(c)) for c in columns}


def _raw_of(evt: EventLike) -> Optional[Mapping[str, Any]]:
    """The event's ``raw`` record, or ``None`` when it is absent or not an object — a
    row selected without ``raw`` simply matches no ``raw:`` term rather than raising."""
    raw = evt.get("raw") if isinstance(evt, Mapping) else getattr(evt, "raw", None)
    return raw if isinstance(raw, Mapping) else None


def _raw_value(raw: Optional[Mapping[str, Any]],
               paths: Tuple[Tuple[str, ...], ...]) -> Any:
    """Resolve ordered jsonb alternatives against ``raw`` (as returned by
    :func:`_raw_of`): first non-``None`` wins, mirroring ``COALESCE``. Each alternative
    is a segment tuple walked one object level at a time, mirroring ``->>`` (one
    segment) and ``#>>`` (several).

    Keys are used BYTE-EXACT and are never split on ``.`` — see the module docstring.
    Anything unwalkable on the way down (a scalar, an array, a missing key, a JSON
    null) ends that alternative with no value, exactly as jsonb yields NULL.
    """
    if raw is None:
        return None
    for path in paths:
        cur: Any = raw.get(path[0])
        for seg in path[1:]:
            if not isinstance(cur, Mapping):
                cur = None
                break
            cur = cur.get(seg)
        if cur is not None:
            return cur
    return None


# ── compiled terms ────────────────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class _Term:
    """A membership term reduced to what evaluation actually needs.

    Exactly one of ``column`` / ``paths`` is set. ``values`` is a frozenset because the
    Windows event-id clauses carry ten of them and this runs per event on the ingest
    hot path. Every evaluation in this module — the reference walk and the compiled
    one — goes through :func:`_term_hit` on one of these, so the two cannot disagree.
    """
    column: str
    paths: Tuple[Tuple[str, ...], ...]
    values: frozenset[str]


def _compile_term(term: CimTerm) -> _Term:
    """Validate + reduce one term. Raises :class:`CimError` on a source the evaluator
    cannot read — a registry defect, which must surface rather than silently never
    match (``registry.load`` already rejects these; this covers hand-built registries)."""
    src = term.source
    if not term.values:
        raise CimError(f"membership term {term.label or src.describe()} has no values")
    if src.kind == "raw":
        if not src.paths:
            raise CimError(f"membership term {term.label or src.describe()} has no jsonb path")
        return _Term(column="", paths=src.paths, values=frozenset(term.values))
    if src.kind == "column":
        if src.name not in cim_sql._TERM_COLUMNS:
            raise CimError(f"column {src.name!r} is not allowed in a membership term "
                           f"(allowed: {sorted(cim_sql._TERM_COLUMNS)})")
        return _Term(column=src.name, paths=(), values=frozenset(term.values))
    raise CimError(f"a membership term cannot read a {src.kind!r} source "
                   f"({term.label or src.describe()})")


def _term_hit(term: _Term, ctext: Mapping[str, Optional[str]],
              raw: Optional[Mapping[str, Any]]) -> bool:
    """Evaluate one compiled term against an event resolved by :func:`_column_texts` /
    :func:`_raw_of`. This is the ONE place a term is ever decided — both the reference
    walk and the compiled plan land here, so they cannot drift apart."""
    text = (ctext.get(term.column) if term.column
            else _text(_raw_value(raw, term.paths)))
    return text is not None and text in term.values


# ── public predicates (the readable reference walk) ────────────────────────────
def term_matches(term: CimTerm, evt: EventLike) -> bool:
    """``<source> IN (values)``, case-insensitively. A missing/NULL value never matches.

    Compiles the term on every call, which is fine — this is the readable path used by
    tests and explanations; :func:`tags_for` walks a plan compiled once per registry.
    """
    return _term_hit(_compile_term(term), _column_texts(evt), _raw_of(evt))


def clause_matches(clause: CimClause, evt: EventLike) -> bool:
    """A conjunction: every term must match.

    An EMPTY clause is treated as NO match rather than Python's vacuous ``all(())``
    truth. ``registry.load`` cannot produce one (it validates through
    ``sql._clause_sql``, which raises), so this only bites a hand-built registry — and
    there, tagging every event in the store is much the worse failure.
    """
    ctext, raw = _column_texts(evt), _raw_of(evt)
    return bool(clause.terms) and all(
        _term_hit(_compile_term(t), ctext, raw) for t in clause.terms)


def model_matches(model: CimModel, evt: EventLike) -> bool:
    """Membership in one data model: any clause matches (OR of clauses, AND of terms).

    A missing key kills its term and therefore its clause, but NOT the model — the
    other clauses are still tried, which is why an Okta sign-in and a Windows 4624 can
    both be Authentication.
    """
    return any(clause_matches(c, evt) for c in model.clauses)


# ── compiled plan (the ingest hot path) ───────────────────────────────────────
_Models = Tuple[Tuple[str, Tuple[Tuple[_Term, ...], ...]], ...]


@dataclass(frozen=True, slots=True)
class _Plan:
    """One registry reduced to what an event evaluation needs.

    ``models`` is ``(tag, clauses)`` per model, a clause being a tuple of compiled terms.
    ``columns`` is every ``events`` column those terms read, and NOTHING else — it is
    what :func:`_column_texts` coerces per event, so it is derived from the very terms
    that will be evaluated against the result (see that function's contract). Both are
    built together in :func:`_compile`, which is the only way they can be kept in step.
    """
    models: _Models
    columns: Tuple[str, ...]


_PLAN_CACHE_MAX = 8
_plan_cache: dict[int, Tuple[CimRegistry, _Plan]] = {}


def _compile(reg: CimRegistry) -> _Plan:
    models: _Models = tuple(
        (m.tag, tuple(tuple(_compile_term(t) for t in c.terms) for c in m.clauses))
        for m in reg.models)
    columns = tuple(sorted({term.column
                            for _, clauses in models for terms in clauses
                            for term in terms if term.column}))
    log.debug("CIM plan compiled: registry v%s, %d models, %d of %d term column(s): %s",
              reg.version, len(models), len(columns), len(_TERM_COLUMN_NAMES),
              ", ".join(columns) or "-")
    return _Plan(models=models, columns=columns)


def _plan(reg: CimRegistry) -> _Plan:
    """The compiled plan for ``reg``, memoized.

    Keyed on ``id(reg)`` while holding a strong reference to the registry itself, so the
    id cannot be recycled behind our back while the entry lives (and the ``is`` check
    catches an id reused after eviction). A ``CimRegistry`` is hashable, but hashing one
    walks every model, clause, term and field — per event, which is precisely the work
    this cache exists to avoid. Bounded because the registry is a singleton in the app
    and only tests build many.

    Lock-free, and the eviction is written so that it stays SAFE while being lock-free.
    Every step below is one atomic operation on a builtin dict, but the size test and the
    eviction are two of them, and this runs on the ingest hot path with INGEST_WORKERS
    writers plus the threadpool entrants behind ``/upload`` and ``/api/ingest``. A
    ``clear_plan_cache()`` (or a racing evictor) landing between the two used to leave
    ``next(iter(...))`` looking at an emptied dict, and a bare ``next`` raises
    ``StopIteration`` there — out of :func:`tags_for`, out of ``cim_models_for``, into
    ``db._row`` mid-flush, over an eviction that did not even need to happen. Both calls
    therefore take a default and neither can raise. The cost of the missing lock is that
    concurrent misses can overshoot ``_PLAN_CACHE_MAX`` by a few entries before they
    settle, which is a hygiene bound on a dict of at most a handful of plans — not a
    correctness one.
    """
    key = id(reg)
    hit = _plan_cache.get(key)
    if hit is not None and hit[0] is reg:
        return hit[1]
    plan = _compile(reg)
    if len(_plan_cache) >= _PLAN_CACHE_MAX:
        oldest = next(iter(_plan_cache), None)         # FIFO, and never StopIteration
        if oldest is not None:
            _plan_cache.pop(oldest, None)              # ...and never KeyError
    _plan_cache[key] = (reg, plan)
    return plan


def clear_plan_cache() -> None:
    """Drop every compiled plan. Call after ``registry.reload()``; used by tests."""
    _plan_cache.clear()


def tags_for(evt: EventLike, registry: Optional[CimRegistry] = None) -> list[str]:
    """The model tags ``evt`` belongs to — the value of ``events.cim_models``.

    Returns a list SORTED alphabetically, and an EMPTY list for an event that belongs to
    no model. Sorted rather than registry order because ``@>`` containment is
    order-insensitive, so nothing depends on the order, and alphabetical keeps the
    stored array stable when someone reorders ``models.yaml`` — a re-run of
    ``db.backfill_cim`` after an unrelated registry edit then produces byte-identical
    arrays instead of a whole-table churn.

    Never raises on a malformed event: a missing key, a ``raw`` that is not a mapping, a
    scalar where an object was expected and a value with a hostile ``__str__`` all
    resolve to "no value" and simply fail their term. A malformed REGISTRY does raise
    :class:`CimError` — that is a deployment defect, and a data model that silently
    matches nothing is the failure mode this whole backbone was built to remove.
    """
    plan = _plan(registry if registry is not None else get_registry())
    ctext, raw = _column_texts(evt, plan.columns), _raw_of(evt)
    tags: list[str] = []
    for tag, clauses in plan.models:
        for terms in clauses:
            if not terms:
                continue        # load-bearing: `for/else` below would MATCH an empty
                                # clause, the vacuous truth `clause_matches` refuses
            for term in terms:
                if not _term_hit(term, ctext, raw):
                    break       # a failed term kills the clause (AND of terms)
            else:
                tags.append(tag)
                break           # one clause is enough (OR of clauses)
    tags.sort()
    return tags


def cim_models_for(evt: EventLike, registry: Optional[CimRegistry] = None, *,
                   tags: Optional[Iterable[str]] = None) -> Optional[list[str]]:
    """The value to bind into ``events.cim_models`` — :func:`tags_for`, or ``None``.

    NULL rather than ``'{}'`` for an event in no model, deliberately and in ONE place:
    a NULL array contributes no entries to the GIN index on ``cim_models``, so the index
    stays proportional to tagged events rather than to the whole table. Both spellings
    behave identically under the ``@>`` predicate ``sql.membership_predicate`` emits
    (``NULL @> …`` is NULL, ``'{}' @> …`` is false — neither is a match), so this is
    purely an index-size decision. ``db.backfill_cim`` must use the same spelling, or a
    re-derived row would differ from an ingested one for no visible reason.

    ``tags`` is this event's ALREADY-RESOLVED membership, and passing it skips the
    registry walk entirely. It exists because the walk used to run twice per ingested
    event: once for the detection ``datamodels:`` gate while the event streams, and
    again here when the chunk flushes. ``pipeline.write_stream`` resolves it once and
    threads it to both consumers; ``None`` means "not resolved", so every caller that
    omits it — a backfill row, a test, an ingest path that never ran detection — still
    gets the value derived here exactly as before.

    The threaded value is re-SORTED rather than trusted: the pipeline holds a
    ``frozenset`` (``detection.engine.cim_tags``), and ``events.cim_models`` has to stay
    alphabetical whichever way it was produced, or a backfill would rewrite every heap
    tuple it re-derived. Sorting three strings is nothing next to the ~40 term tests it
    replaces.
    """
    if tags is None:
        return tags_for(evt, registry) or None
    return sorted(tags) or None
