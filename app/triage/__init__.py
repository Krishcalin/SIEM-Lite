"""Alert triage & tuning: suppression/allowlist matching + assignment/notes.

Suppression rules are matched against newly-raised alerts inline in the ingest
pipeline; a match stores the alert as ``status='suppressed'`` (kept for audit,
hidden from the default queue, not notified). Assignment and notes are plain
per-alert metadata managed from the alert detail page.
"""
from .suppression import Suppression, SuppressionIndex, matches
from .runtime import get_index, reload_index, set_index

__all__ = ["Suppression", "SuppressionIndex", "matches",
           "get_index", "reload_index", "set_index"]
