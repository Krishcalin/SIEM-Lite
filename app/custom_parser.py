"""Console-authored field-mapper parsers.

Definitions live in the `custom_parsers` table as data (never code): a signature
(match_key / match_value) that identifies a source, plus a field map of
raw-key -> normalized-column. `apply()` runs AFTER the built-in parser and only
fills columns the built-in parser left empty, so it can never clobber a value a
real parser already resolved.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from . import db

log = logging.getLogger(__name__)

# Columns a custom parser is allowed to fill. Deliberately excludes raw/event_time
# so a definition cannot corrupt provenance or partitioning.
_ALLOWED = {"vendor", "product", "log_type", "severity", "action", "src_ip",
            "dst_ip", "protocol", "app", "user_name", "host_name", "rule_name",
            "message"}

_defs: list[dict] = []


def reload() -> None:
    """Re-read enabled definitions from the DB (call after any edit)."""
    global _defs
    try:
        _defs = list(db.enabled_custom_parsers())
        log.info("loaded %d custom parser definition(s)", len(_defs))
    except Exception:  # noqa: BLE001 — never let a bad definition break ingest
        log.exception("failed to load custom parsers")
        _defs = []


def get_defs() -> list[dict]:
    return _defs


def _lower(rec: dict) -> dict:
    return {str(k).lower(): v for k, v in rec.items()}


def matches(defn: dict, rec: dict) -> bool:
    val = _lower(rec).get(str(defn["match_key"]).lower())
    if val is None:
        return False
    return str(defn["match_value"]).lower() in str(val).lower()


def extract_kv(defn: dict, rec: dict) -> dict:
    """Pull `key=value` pairs out of a text field into a flat dict.

    Used for sources that carry their fields inside the message body rather than
    as structured keys (e.g. Nutanix audit: `userName=admin||httpMethod=GET`).
    Returns the record unchanged when the definition has no kv_source.
    """
    src = defn.get("kv_source")
    if not src:
        return rec
    text = _lower(rec).get(str(src).lower())
    if not text:
        return rec
    sep = defn.get("kv_sep") or "||"
    merged = dict(rec)
    for part in str(text).split(sep):
        if "=" not in part:
            continue
        k, _, v = part.partition("=")
        k, v = k.strip(), v.strip()
        if k and v and k not in merged:
            merged[k] = v
    return merged


def map_fields(defn: dict, rec: dict) -> dict:
    """Return {normalized_column: value} for one record under one definition."""
    low = _lower(rec)
    out: dict[str, Any] = {}
    for raw_key, column in (defn.get("field_map") or {}).items():
        if column not in _ALLOWED:
            continue
        v = low.get(str(raw_key).lower())
        if v not in (None, ""):
            out[column] = str(v)
    for col in ("vendor", "product"):
        if defn.get(col):
            out.setdefault(col, defn[col])
    return out


def apply(evt) -> None:
    """Fill empty normalized fields on a NormalizedEvent from its raw record."""
    if not _defs or not isinstance(getattr(evt, "raw", None), dict):
        return
    for defn in _defs:
        try:
            if not matches(defn, evt.raw):
                continue
            rec = extract_kv(defn, evt.raw)
            declared = {c: defn[c] for c in ("vendor", "product") if defn.get(c)}
            for column, value in map_fields(defn, rec).items():
                # An explicitly declared vendor/product is authoritative: the
                # built-in generic parsers stamp a placeholder ("json"), which is
                # not real knowledge. Mapped fields stay fill-only-empty so a
                # definition can never clobber what a real parser resolved.
                if column in declared:
                    setattr(evt, column, value)
                elif getattr(evt, column, None) in (None, ""):
                    setattr(evt, column, value)
            return  # first matching definition wins
        except Exception:  # noqa: BLE001 — one bad definition must not kill ingest
            log.exception("custom parser %s failed", defn.get("parser_id"))
            continue
