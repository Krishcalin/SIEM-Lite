# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""The frozen CIM (Common Information Model) contract — the in-memory shape of a
data model after the YAML registry is parsed.

A ``CimModel`` is LogOcean's equivalent of a Splunk CIM data model: a versioned,
vendor-agnostic schema (``fields``) plus a membership rule (``clauses``) that decides
which normalized events belong to it. Detections, ``datamodel:`` searches and the
per-model SQL views all bind to these objects, never to a vendor — so onboarding a new
source is a registry edit, not a code change.

Everything here is inert data: no SQL, no I/O, no event knowledge. Two consumers read
these objects and they must agree — :mod:`app.cim.sql` (the per-model views) and
:mod:`app.cim.match` (the Python evaluator that stamps ``events.cim_models`` at ingest).

The one subtlety worth knowing is :class:`CimSource`: a value may come from several
jsonb keys (vendors spell the same concept differently) and may live under a nested
object. Alternatives are ordered — first non-null wins — and nesting is spelled out
segment by segment, because a jsonb key is NEVER split on ``.``: Zeek writes literal
dotted TOP-LEVEL keys (``id.orig_h``, ``id.resp_h``), so dot-splitting would silently
break every Zeek mapping.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence, Tuple, Union

# A single alternative in a raw lookup: one top-level key, or an explicit segment list.
PathSpec = Union[str, Sequence[str]]

_SOURCE_KINDS = ("column", "raw", "const", "expr")


class CimError(Exception):
    """Raised when the CIM registry is malformed (bad column, unsafe key, dup tag…)."""


@dataclass(frozen=True)
class CimSource:
    """Where one value comes from — shared by CIM fields and membership terms.

    ``kind`` selects the source:

    * ``column`` — a normalized ``events`` column; ``name`` is the column name.
    * ``raw``    — one or more jsonb lookups, read schema-on-read. ``paths`` is an
      ORDERED tuple of alternatives (first non-null wins, i.e. ``COALESCE``), and each
      alternative is a tuple of path SEGMENTS: ``("EventID",)`` is the top-level key
      ``EventID``; ``("alert", "category")`` descends one level. Segments are never
      inferred from a dot — ``("id.orig_h",)`` is a single literal Zeek key.
    * ``const``  — a fixed string in ``name``.
    * ``expr``   — the key of a whitelisted named SQL snippet, in ``name``.
    """
    kind: str
    name: str = ""
    paths: Tuple[Tuple[str, ...], ...] = ()

    def __post_init__(self) -> None:
        # Cheap structural invariants, so a hand-built source fails here rather than
        # as odd SQL three layers away.
        if self.kind not in _SOURCE_KINDS:
            raise CimError(f"unknown CIM source kind {self.kind!r} "
                           f"(expected one of {list(_SOURCE_KINDS)})")
        if self.kind == "raw":
            if not self.paths:
                raise CimError("a 'raw' CIM source needs at least one jsonb key path")
            if any(not p for p in self.paths):
                raise CimError("a 'raw' CIM source path needs at least one segment")
        elif self.paths:
            raise CimError(f"a {self.kind!r} CIM source cannot carry jsonb paths")
        if self.kind in ("column", "expr") and not self.name:
            raise CimError(f"a {self.kind!r} CIM source needs a name")

    # ── constructors (keep callers from hand-shaping `paths`) ────────────────
    @classmethod
    def column_of(cls, name: str) -> "CimSource":
        return cls(kind="column", name=str(name))

    @classmethod
    def raw_of(cls, *alternatives: PathSpec) -> "CimSource":
        """A jsonb lookup over ordered ``alternatives``. Each alternative is either a
        string (one top-level key, taken literally — dots included) or a sequence of
        segments for a nested lookup."""
        paths = tuple((str(alt),) if isinstance(alt, str)
                      else tuple(str(seg) for seg in alt)
                      for alt in alternatives)
        return cls(kind="raw", paths=paths)

    @classmethod
    def const_of(cls, value: str) -> "CimSource":
        return cls(kind="const", name=str(value))

    @classmethod
    def expr_of(cls, name: str) -> "CimSource":
        return cls(kind="expr", name=str(name))

    # ── introspection ────────────────────────────────────────────────────────
    @property
    def keys(self) -> Tuple[str, ...]:
        """The first segment of every alternative — the top-level jsonb keys this
        source may read (``()`` for non-raw sources). Useful for coverage tooling."""
        return tuple(p[0] for p in self.paths)

    def describe(self) -> str:
        """A short, ASCII-safe rendering for error messages and reports."""
        if self.kind == "raw":
            return " | ".join("raw:" + " -> ".join(p) for p in self.paths)
        return f"{self.kind}:{self.name}"


@dataclass(frozen=True)
class CimField:
    """One field of a data model, mapped to where its value comes from.

    ``name`` is the CIM-side name (what analysts and detections see); ``source`` is the
    vendor-side lookup. A field is null for a source that does not provide it — exactly
    as in Splunk CIM.
    """
    name: str
    source: CimSource
    description: str = ""

    @property
    def kind(self) -> str:
        """Ergonomic passthrough — ``field.kind`` reads better than ``field.source.kind``."""
        return self.source.kind


@dataclass(frozen=True)
class CimTerm:
    """A single membership test: ``<source> IN (values)``, case-insensitively (values
    are lower-cased on load and the source is lower-cased at comparison time).

    ``label`` is the key the term was written under in the YAML — carried for error
    messages and reports only; it never reaches SQL.
    """
    source: CimSource
    values: Tuple[str, ...]
    label: str = ""


@dataclass(frozen=True)
class CimClause:
    """A conjunction of terms — the clause matches an event when *every* term does."""
    terms: Tuple[CimTerm, ...]


@dataclass(frozen=True)
class CimModel:
    """A versioned CIM data model. An event is a member when *any* clause matches
    (OR of clauses, AND of terms within a clause)."""
    name: str                          # display name, e.g. "Authentication"
    tag: str                           # membership token stored in events.cim_models
    version: int
    description: str
    clauses: Tuple[CimClause, ...]
    fields: Tuple[CimField, ...]

    def field(self, name: str) -> Optional[CimField]:
        return next((f for f in self.fields if f.name == name), None)


@dataclass(frozen=True)
class CimRegistry:
    """The whole loaded registry — the set of data models plus a schema version."""
    version: int
    models: Tuple[CimModel, ...]

    def by_name(self, name: str) -> Optional[CimModel]:
        """Resolve a model by display name or tag, case-insensitively.

        Names win over tags, and the two passes are deliberate: a single-pass ``name or
        tag`` predicate lets an EARLIER model's tag shadow a LATER model's exact name.
        ``registry.load`` also rejects a registry where the two key spaces collide, so
        this is belt-and-braces for hand-built registries in tests.
        """
        low = (name or "").strip().lower()
        if not low:
            return None
        return (next((m for m in self.models if m.name.lower() == low), None)
                or next((m for m in self.models if m.tag == low), None))

    @property
    def names(self) -> list[str]:
        return [m.name for m in self.models]

    @property
    def tags(self) -> list[str]:
        return [m.tag for m in self.models]
