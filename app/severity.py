"""Canonical severity ordering (pure helpers).

Used to roll a case's severity up to the highest of its member alerts.
"""
from __future__ import annotations

from typing import Iterable, Optional

SEVERITY_ORDER = ("informational", "low", "medium", "high", "critical")
_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


def severity_rank(level: Optional[str]) -> int:
    """Rank of a severity name (unknown → 'medium'-equivalent)."""
    return _RANK.get((level or "").strip().lower(), _RANK["medium"])


def max_severity(levels: Iterable[Optional[str]], default: str = "medium") -> str:
    """The highest severity among `levels` (default if none are usable)."""
    usable = [str(s).lower() for s in levels if s]
    return max(usable, key=severity_rank) if usable else default
