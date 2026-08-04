# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Frozen value types for the asset & identity registry.

Pure data — no database, no settings, no clock. `app/assets/registry.py` builds these
from the tables and `app/assets/resolve.py` reads them, which is what keeps the
resolver unit-testable without a database.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

#: Ranked worst-first. The order is the contract for "which is more critical", and it
#: is what Phase 4's risk multipliers will read, so it lives here rather than being
#: re-spelled at each call site.
CRITICALITY = ("critical", "high", "medium", "low", "unknown")
_RANK = {name: i for i, name in enumerate(CRITICALITY)}

#: Identifier kinds an asset may be declared under. `cidr` is deliberately NOT a
#: `ip` with a slash — it is resolved by containment, not by equality, and mixing the
#: two in one key space would make a /24 unfindable by exact lookup and an address
#: unfindable by containment.
ASSET_ALIAS_TYPES = ("hostname", "fqdn", "ip", "cidr", "mac")

#: Identifier kinds an identity may be declared under.
IDENTITY_ALIAS_TYPES = ("email", "upn", "sam", "employee_id", "cn")


def rank(value: Optional[str]) -> int:
    """Sort key for a criticality/priority label; unknown values sort last."""
    return _RANK.get((value or "").strip().lower(), len(CRITICALITY))


def normalize_level(value: Optional[str]) -> str:
    """A criticality/priority label coerced onto the known set.

    Anything unrecognised becomes ``unknown`` rather than being stored verbatim: a
    typo like ``criticl`` that survived into the column would compare as its own
    level forever and silently never match a rule gating on ``critical``.
    """
    v = (value or "").strip().lower()
    return v if v in CRITICALITY else "unknown"


@dataclass(frozen=True)
class Asset:
    """A declared host/device. `asset_id` is the operator's stable key."""

    asset_id: str
    display_name: str = ""
    criticality: str = "medium"
    category: tuple[str, ...] = ()
    owner: str = ""
    business_unit: str = ""
    environment: str = ""
    watchlist: tuple[str, ...] = ()
    enabled: bool = True
    notes: str = ""
    source: str = "manual"

    def context_labels(self, role: str) -> list[str]:
        """Role-prefixed labels for ``events.context_tags``.

        The prefix is what lets ONE array answer questions about either side of a
        flow — ``dst:crown-jewel`` and ``src:crown-jewel`` are different facts and
        must not collapse into each other. `environment` is included because "was
        this production?" is the single most common scoping question an analyst
        asks, and it costs one label rather than a column.
        """
        out = [f"{role}:{c}" for c in self.category]
        out += [f"{role}:{w}" for w in self.watchlist]
        if self.environment:
            out.append(f"{role}:{self.environment}")
        return out


@dataclass(frozen=True)
class Identity:
    """A declared person or service account."""

    identity_id: str
    display_name: str = ""
    priority: str = "medium"
    department: str = ""
    manager: str = ""
    title: str = ""
    email: str = ""
    watchlist: tuple[str, ...] = ()
    enabled: bool = True
    notes: str = ""
    source: str = "manual"

    def context_labels(self) -> list[str]:
        """``identity:``-prefixed labels. There is only one identity per event, so
        unlike the asset side there is no src/dst role to distinguish."""
        return [f"identity:{w}" for w in self.watchlist]


@dataclass(frozen=True)
class Resolution:
    """What the registry knows about one event.

    Deliberately carries the RESOLVED VALUES rather than references, because it is
    written straight onto the event row: the pipeline hands this to `db._row` the
    same way it hands over CIM tags, and nothing downstream re-reads the registry.
    """

    asset_id: Optional[str] = None
    asset_criticality: Optional[str] = None
    identity_id: Optional[str] = None
    identity_priority: Optional[str] = None
    context_tags: tuple[str, ...] = ()
    #: Which field the subject asset was resolved from (host_name / src_ip / dst_ip),
    #: for the console's "why did this row get that asset?" answer. Never stored.
    asset_via: str = ""

    def is_empty(self) -> bool:
        return not (self.asset_id or self.identity_id or self.context_tags)


EMPTY = Resolution()
