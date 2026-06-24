"""Detection-engine runtime: load rules, sync the DB registry, hold the singleton.

The ingest pipeline calls `get_engine()` per event; the app lifespan calls
`load_and_sync()` at startup and the admin UI calls `refresh_enabled()` after a
rule is toggled.
"""
from __future__ import annotations

from typing import Optional

from .. import db
from .engine import DetectionEngine, load_rules

_engine: Optional[DetectionEngine] = None


def get_engine() -> Optional[DetectionEngine]:
    return _engine


def set_engine(engine: Optional[DetectionEngine]) -> None:
    global _engine
    _engine = engine


def load_and_sync(rules_dir) -> DetectionEngine:
    """Load YAML rules, upsert their metadata, apply the stored enabled flags."""
    rules = load_rules(rules_dir)
    db.sync_rules(rules)
    enabled = db.enabled_rule_ids()
    for r in rules:
        r.enabled = r.id in enabled
    engine = DetectionEngine(rules)
    set_engine(engine)
    return engine


def refresh_enabled() -> None:
    """Re-apply the stored enabled flags to the in-memory rules (after a toggle)."""
    if _engine is None:
        return
    enabled = db.enabled_rule_ids()
    for r in _engine.rules:
        r.enabled = r.id in enabled
