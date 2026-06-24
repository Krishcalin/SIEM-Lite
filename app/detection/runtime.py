"""Detection-engine runtime: load rules, sync the DB registry, hold the singleton.

The ingest pipeline calls `get_engine()` per event; the app lifespan calls
`load_and_sync()` at startup and the admin UI calls `refresh_enabled()` after a
rule is toggled.
"""
from __future__ import annotations

from typing import Optional

from .. import db
from .correlation import CorrelationRule, load_correlation_rules
from .engine import DetectionEngine, load_rules

_engine: Optional[DetectionEngine] = None
_correlation_rules: list[CorrelationRule] = []


def get_engine() -> Optional[DetectionEngine]:
    return _engine


def set_engine(engine: Optional[DetectionEngine]) -> None:
    global _engine
    _engine = engine


def get_correlation_rules() -> list[CorrelationRule]:
    return _correlation_rules


def load_and_sync(rules_dir) -> DetectionEngine:
    """Load per-event + correlation rules, upsert their metadata into one registry,
    and apply the stored enabled flags."""
    global _correlation_rules
    rules = load_rules(rules_dir)
    corr = load_correlation_rules(rules_dir)
    db.sync_rules(rules + corr)
    enabled = db.enabled_rule_ids()
    for r in rules:
        r.enabled = r.id in enabled
    for r in corr:
        r.enabled = r.id in enabled
    set_engine(DetectionEngine(rules))
    _correlation_rules = corr
    return _engine


def refresh_enabled() -> None:
    """Re-apply the stored enabled flags to the in-memory rules (after a toggle)."""
    enabled = db.enabled_rule_ids()
    if _engine is not None:
        for r in _engine.rules:
            r.enabled = r.id in enabled
    for r in _correlation_rules:
        r.enabled = r.id in enabled
