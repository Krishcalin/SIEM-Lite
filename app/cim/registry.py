# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Load + validate the CIM data-model registry from ``models.yaml``.

The YAML is DATA, never code — this loader turns it into the frozen :mod:`app.cim.spec`
objects and validates every column, tag, field name and jsonb key up front (so a typo
fails loudly at startup, not as broken SQL or a silently-empty data model later). The
parsed registry is cached; ``get_registry()`` is the one entry point the rest of the app
calls. Membership values are lower-cased on load so both evaluators — the emitted
``lower(col) IN (…)`` SQL and the Python matcher — are genuinely case-insensitive.

Three YAML hazards are handled explicitly, because every one of them fails *silently*:

* **YAML 1.1 scalars.** PyYAML reads bare ``yes``/``no``/``on``/``off``/``true``/``false``
  as booleans and ``null``/``~`` as None. A membership value of ``on`` would have been
  coerced to the string ``'true'`` and matched nothing, forever. Booleans and None are
  now rejected with a message telling the author to quote the value; integers are
  accepted on purpose (the Windows event-id lists are ints).
* **Key spaces.** Duplicate field names inside a model, and duplicate model
  names/tags across the registry, are rejected — the first would blow up at
  ``CREATE VIEW`` with SQLSTATE 42701, the second would make ``by_name`` resolve to
  whichever model happened to be listed first.
* **Duplicate mapping keys.** PyYAML keeps the last one silently; two terms written
  under the same key in one clause would lose one — see :class:`_UniqueKeyLoader`.

Source syntax (shared by ``fields:`` and membership terms) is described in the
``models.yaml`` header; :func:`_raw_source` is the normative implementation.
"""
from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Optional, Tuple

import yaml

from .spec import (CimClause, CimError, CimField, CimModel, CimRegistry, CimSource,
                   CimTerm)
from . import sql as cim_sql

_REGISTRY_PATH = Path(__file__).resolve().parent / "models.yaml"
_cache: Optional[CimRegistry] = None
# Guards `_cache` AND `_failure` for `get_registry` and `reload` together — see
# `get_registry` for why the parse is worth serializing and why the lock order cannot
# invert.
_lock = threading.Lock()

# The last failed parse, and the monotonic deadline after which it is worth retrying:
# `(exception, retry_after)`. See `get_registry` — this is the negative half of the same
# cache, and without it a broken registry is more expensive than a working one.
_failure: Optional[Tuple[BaseException, float]] = None
# How long a failed parse is remembered. Bounded rather than permanent so an operator who
# fixes models.yaml recovers on their own (within this window) instead of needing a
# restart, and long enough that the ingest path pays one parse per window rather than one
# per event. A module constant, so a test can shorten it without waiting on a clock.
_FAILURE_TTL_SECONDS = 30.0

# Ordered so error messages are deterministic (a set would reorder run to run).
_SOURCE_KEYS: Tuple[str, ...] = ("column", "raw", "const", "expr")
_TERM_KEYS: Tuple[str, ...] = ("column", "raw")


class _UniqueKeyLoader(yaml.SafeLoader):
    """A SafeLoader (same trust model as ``yaml.safe_load``) that refuses duplicate
    mapping keys.

    PyYAML keeps the LAST of a repeated key and says nothing, so a clause written with
    two ``event_id:`` terms quietly loses one. A lost membership term is invisible —
    the model just stops matching, and an empty data model looks exactly like "there
    were no such events" — so the registry refuses to load instead.
    """

    def construct_mapping(self, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                if key in seen:
                    raise CimError(f"duplicate key {key!r} in the CIM registry "
                                   f"(line {key_node.start_mark.line + 1})")
                seen.add(key)
            except TypeError:               # unhashable key — SafeLoader rejects it below
                continue
        return super().construct_mapping(node, deep=deep)


# ── value sources ─────────────────────────────────────────────────────────────
def _raw_key(seg, where: str) -> str:
    """One jsonb path segment. Must be a quoted string — see the YAML-1.1 note above."""
    if isinstance(seg, bool) or seg is None or not isinstance(seg, str):
        raise CimError(f"{where}: jsonb key {seg!r} must be a string "
                       "(quote it: YAML reads bare yes/no/on/off/null as boolean/None)")
    key = seg.strip()
    if not key:
        raise CimError(f"{where}: a jsonb key cannot be empty")
    return key


def _raw_source(value, where: str) -> CimSource:
    """Build a ``raw`` source from the YAML ``raw:`` value.

    * ``raw: user_agent``                 → one top-level key.
    * ``raw: [EventID, event_id]``        → ordered alternatives, first non-null wins.
    * ``raw: [[alert, category], category]`` → an alternative that is itself a list is an
      explicit SEGMENT LIST for a nested lookup (``raw['alert']['category']``).

    A key is NEVER split on ``.``: Zeek writes literal dotted TOP-LEVEL keys, so
    ``raw: id.orig_h`` must keep meaning the single key ``id.orig_h``. Nesting has to be
    spelled out, which is why the segment list is a list and not a dotted string.
    """
    alts = list(value) if isinstance(value, (list, tuple)) else [value]
    if not alts:
        raise CimError(f"{where}: 'raw' needs at least one jsonb key")
    paths = []
    for alt in alts:
        segs = list(alt) if isinstance(alt, (list, tuple)) else [alt]
        if not segs:
            raise CimError(f"{where}: a nested jsonb path needs at least one segment")
        paths.append(tuple(_raw_key(s, where) for s in segs))
    return CimSource(kind="raw", paths=tuple(paths))


def _source(spec: dict, allowed: Tuple[str, ...], where: str) -> Optional[CimSource]:
    """Read the one source key out of a mapping (``column``/``raw``/``const``/``expr``).
    Returns ``None`` when the mapping declares no source at all, so callers can fall back
    to their own convention (a membership term falls back to its YAML key)."""
    present = [k for k in _SOURCE_KEYS if k in spec]
    if not present:
        return None
    if len(present) > 1:
        raise CimError(f"{where} must have exactly one of {list(allowed)}, got {present}")
    kind = present[0]
    if kind not in allowed:
        raise CimError(f"{where} cannot use {kind!r} here (allowed: {list(allowed)})")
    if kind == "raw":
        return _raw_source(spec["raw"], where)
    value = spec[kind]
    if isinstance(value, bool) or value is None:
        raise CimError(f"{where}: {kind!r} needs a string value, not {value!r} "
                       "(quote it: YAML reads bare yes/no/on/off/null as boolean/None)")
    if kind == "const":
        return CimSource.const_of(str(value))
    if not isinstance(value, str):
        raise CimError(f"{where}: {kind!r} needs a string, got {type(value).__name__}")
    return CimSource(kind=kind, name=value.strip())


# ── fields ────────────────────────────────────────────────────────────────────
def _field(raw: dict) -> CimField:
    if not isinstance(raw, dict):
        raise CimError(f"a CIM field must be a mapping, got {raw!r}")
    name = str(raw.get("name") or "").strip()
    if not name:
        raise CimError("a CIM field needs a name")
    where = f"field {name!r}"
    source = _source(raw, _SOURCE_KEYS, where)
    if source is None:
        raise CimError(f"{where} must have exactly one of {list(_SOURCE_KEYS)}, got none")
    # validate now: field names can't shadow reserved view columns, and the value
    # expression must build (catches bad columns / unsafe keys / unknown exprs).
    if name in cim_sql._RESERVED_FIELDS:
        raise CimError(f"field name {name!r} is reserved")
    cim_sql._ident(name)
    field = CimField(name=name, source=source,
                     description=str(raw.get("description") or ""))
    cim_sql.field_value_sql(field)
    return field


# ── membership ────────────────────────────────────────────────────────────────
def _values(values, label: str) -> Tuple[str, ...]:
    """Normalize a term's value list. Integers are kept (event-id lists); booleans and
    None are rejected rather than stringified, because YAML 1.1 produces them from bare
    words an author almost certainly meant as text."""
    vals = list(values) if isinstance(values, (list, tuple)) else [values]
    out = []
    for v in vals:
        if isinstance(v, bool) or v is None:
            raise CimError(
                f"membership term {label!r}: {v!r} is not a usable value; YAML reads "
                "bare yes/no/on/off/true/false/null as booleans and None; quote the "
                "value if you meant the text")
        if isinstance(v, int):
            out.append(str(v))                      # event ids are ints in the YAML
            continue
        if not isinstance(v, str):
            raise CimError(f"membership term {label!r}: value {v!r} must be a string "
                           f"or an integer, got {type(v).__name__}")
        text = v.strip().lower()
        if text:
            out.append(text)
    if not out:
        raise CimError(f"membership term {label!r} needs at least one value")
    return tuple(out)


def _key_source(label: str) -> CimSource:
    """Short form: the clause KEY is the source. ``raw:<key>`` reads ONE jsonb key,
    taken literally (never dot-split — ``raw:id.orig_h`` is Zeek's real key name);
    anything else names a normalized ``events`` column."""
    if label.startswith("raw:"):
        key = label[4:].strip()
        if not key:
            raise CimError("a 'raw:' membership term needs a jsonb key after the colon")
        return CimSource.raw_of(key)
    return CimSource.column_of(label)


def _term(label: str, spec) -> CimTerm:
    """One membership term, in either form:

    * short — ``log_type: [security]`` / ``raw:event_id: [4624, 4625]``: the key is the
      source, the value is the value list.
    * long  — ``event_id: {raw: [EventID, event_id], values: [4624, 4625]}``: the value
      is a mapping carrying an explicit source (which may list alternatives or nested
      paths) plus ``values:``. The key is then just a readable label; if the mapping
      omits the source, the label is used as the source exactly as in the short form.
    """
    if isinstance(spec, dict):
        source = _source(spec, _TERM_KEYS, f"membership term {label!r}") or _key_source(label)
        if "values" not in spec:
            raise CimError(f"membership term {label!r} needs a 'values' list")
        values = spec["values"]
    else:
        source = _key_source(label)
        values = spec
    return CimTerm(source=source, values=_values(values, label), label=label)


def _clause(raw: dict) -> CimClause:
    if not isinstance(raw, dict) or not raw:
        raise CimError("a membership clause must be a non-empty mapping of source -> values")
    clause = CimClause(terms=tuple(_term(str(k).strip(), v) for k, v in raw.items()))
    cim_sql._clause_sql(clause)          # validate columns/keys eagerly
    return clause


# ── models + registry ─────────────────────────────────────────────────────────
def _dupes(items) -> list:
    seen, dupes = set(), set()
    for it in items:
        (dupes if it in seen else seen).add(it)
    return sorted(dupes)


def _model(raw: dict) -> CimModel:
    if not isinstance(raw, dict):
        raise CimError(f"a CIM model must be a mapping, got {raw!r}")
    name = str(raw.get("name") or "").strip()
    tag = str(raw.get("tag") or "").strip().lower()
    if not name or not tag:
        raise CimError(f"model {name or '?'!r} needs both a name and a tag")
    cim_sql._ident(tag)
    clauses_raw = raw.get("membership") or raw.get("clauses") or []
    if not clauses_raw:
        raise CimError(f"model {name!r} needs at least one membership clause")
    fields_raw = raw.get("fields") or []
    if not fields_raw:
        raise CimError(f"model {name!r} needs at least one field")
    fields = tuple(_field(f) for f in fields_raw)
    # Two fields with the same name load cleanly and then abort CREATE VIEW with
    # SQLSTATE 42701 ("column specified more than once") — catch it here instead.
    dupes = _dupes(f.name for f in fields)
    if dupes:
        raise CimError(f"model {name!r} has duplicate field name(s): {dupes}")
    return CimModel(
        name=name, tag=tag, version=int(raw.get("version", 1)),
        description=str(raw.get("description") or ""),
        clauses=tuple(_clause(c) for c in clauses_raw),
        fields=fields)


def load(path: Path = _REGISTRY_PATH) -> CimRegistry:
    """Parse + validate the registry at ``path`` (no caching — used by tests)."""
    # `_UniqueKeyLoader` is a SafeLoader subclass — same constructors, one extra check.
    doc = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader) or {}  # noqa: S506
    if not isinstance(doc, dict):
        raise CimError("the CIM registry must be a mapping at the top level")
    models = tuple(_model(m) for m in (doc.get("models") or []))
    if not models:
        raise CimError("the CIM registry has no models")
    tags = _dupes(m.tag for m in models)
    if tags:
        raise CimError(f"duplicate model tag(s): {tags}")
    # `by_name` resolves a display name OR a tag, so the two live in ONE key space: an
    # earlier model's tag would otherwise shadow a later model's exact name. A model
    # whose name simply lower-cases to its own tag (DNS/dns) is fine — that is one key.
    keys = [k for m in models for k in dict.fromkeys((m.name.strip().lower(), m.tag))]
    collisions = _dupes(keys)
    if collisions:
        raise CimError(f"model name/tag collision(s) across the registry: {collisions} "
                       "- a display name (case-insensitive) and a tag share one key space")
    return CimRegistry(version=int(doc.get("version", 1)), models=models)


def _replay(err: BaseException) -> BaseException:
    """A FRESH exception carrying ``err``'s type and message.

    The cached failure is never re-``raise``d as the same object. Python appends the
    raising frames to an exception's own ``__traceback__``, so replaying one instance to
    every event on the ingest path would grow that traceback without bound — an unbounded
    leak inside the handler for a defect. A clone costs one allocation and reads
    identically to the original everywhere it is reported (``db._cim_tags`` records
    ``f"{type(exc).__name__}: {exc}"``, which is what /health shows).

    Falls back to :class:`CimError` for an exception whose ``__init__`` needs more than a
    message, keeping the original type name inside the text rather than losing it.
    """
    try:
        clone = type(err)(str(err))
    except Exception:                       # noqa: BLE001 — a non-message constructor
        clone = CimError(f"{type(err).__name__}: {err}")
    clone.__cause__ = None
    clone.__suppress_context__ = True
    return clone


def get_registry() -> CimRegistry:
    """The cached registry singleton (loaded + validated once). Named ``get_registry``
    so it never shadows the ``app.cim.registry`` module when re-exported.

    Locked, so a cold start pays :func:`load` once rather than once per racing caller.
    The unlocked shape was not *wrong* — the flag and the value are the SAME global here,
    so a racing thread either sees ``None`` and redoes the work or sees a fully
    constructed registry; it can never see a half-built one (contrast
    ``detection.engine._cim``, where a separate `_resolved` flag made the same shape a
    blocker). What it cost was the parse: concurrent first callers are the normal case on
    this path — ``INGEST_WORKERS`` writers reach it through ``pipeline.write_stream``
    alongside ``/upload``, ``/api/ingest`` and the workbench — and each one that arrives
    inside the window pays the full YAML parse and validation for a result it then throws
    away. Under the lock, the first caller parses and the rest wait for it.

    FAILURE IS CACHED TOO, and that is not symmetry for its own sake. ``_cache`` alone
    memoizes only success: a registry that will not parse leaves it ``None``, so the next
    caller re-parses, re-validates and re-raises — and on the degraded write path the next
    caller is the NEXT EVENT. ``db._cim_tags`` deliberately swallows this exception so a
    broken registry costs the tags and never the event, which means the ingest loop calls
    straight back in. Un-memoized, a 27KB YAML file that fails validation therefore turns
    into a full parse-and-validate PER EVENT — the same cost ``db.registry_drift`` records
    as ~88ms and memoizes for exactly this reason — serialized behind the process-global
    lock above, so every ingest worker queues behind every other worker's doomed parse.
    That is strictly worse than the defect it is handling: the failure handler becomes the
    outage. The negative entry is time-boxed by
    ``_FAILURE_TTL_SECONDS`` so a fixed file recovers without a restart, and
    :func:`reload` drops it outright.

    LOCK ORDER. ``detection.engine._cim`` holds its own lock across a call to this
    function, so engine-before-registry is an ordering this process actually takes.
    Nothing here calls back into ``app.detection`` (this package imports only
    ``app.models`` and its own siblings), so the order cannot invert and a plain
    non-reentrant lock cannot deadlock.
    """
    global _cache, _failure
    with _lock:
        if _cache is not None:
            return _cache
        if _failure is not None:
            err, retry_after = _failure
            if time.monotonic() < retry_after:
                raise _replay(err)
            _failure = None                 # the window elapsed — try the file again
        try:
            _cache = _with_packs(load())
        except Exception as exc:            # noqa: BLE001 — remembered, then re-raised
            _failure = (exc, time.monotonic() + _FAILURE_TTL_SECONDS)
            raise
        _failure = None
        return _cache


def _with_packs(reg: CimRegistry) -> CimRegistry:
    """``reg`` plus the CIM additions of every installed content pack.

    A pack may ADD membership clauses and fields to a model models.yaml already
    defines; it may never define a model, because a model tag is what detections and
    LOQL bind to. The overlay never raises and never removes — a stale pack costs that
    pack's membership, not the registry — so a failure here degrades to the shipped
    file rather than taking CIM down with it.

    Two things make this safe to call from inside ``_lock``:
      * the import is LAZY, because ``app.contentpack`` imports this module; and
      * ``overlay_registry`` threads `known_models` down from the registry handed to
        it, so nothing under this call re-enters :func:`get_registry`. It used to,
        via ``parse`` -> ``_registry_model_names``, and since ``_lock`` is a plain
        ``threading.Lock`` that was a hard hang on the first startup after any pack
        was installed — silent, because a lock that never releases raises nothing.

    Because the registry is compiled once per process and cached, a pack's membership
    takes effect on the NEXT START, and then needs ``db.backfill_cim()`` — in that
    order (see the ordering note at the top of models.yaml).
    """
    from .. import contentpack             # lazy: contentpack imports this module
    return contentpack.overlay_registry(reg)


# Backwards/ergonomic alias — callers holding the module use ``registry.registry()``.
registry = get_registry


def reload() -> CimRegistry:
    """Drop the cache and re-load (after editing the YAML).

    Clearing and re-loading are ONE critical section: doing them as two would let a
    concurrent reader slip in between and re-populate the cache from the file, after
    which this call's own :func:`load` would overwrite it — two parses, and a window in
    which readers see a registry nobody asked for. `_lock` is not reentrant, so the load
    is called directly rather than through :func:`get_registry`.

    Both halves of the cache are cleared. This is the EXPLICIT retry an operator reaches
    for after fixing models.yaml, so it must not be answered out of the negative entry
    :func:`get_registry` keeps — and if this load fails in turn, the entry is re-armed,
    because the ingest path is about to start calling ``get_registry`` per event again.
    """
    global _cache, _failure
    with _lock:
        _cache = None
        _failure = None
        try:
            _cache = _with_packs(load())
        except Exception as exc:            # noqa: BLE001 — remembered, then re-raised
            _failure = (exc, time.monotonic() + _FAILURE_TTL_SECONDS)
            raise
        return _cache
