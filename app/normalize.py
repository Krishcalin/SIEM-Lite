"""Derive the dedup hash and full-text blob from a NormalizedEvent."""
from __future__ import annotations

import hashlib
import json

from .models import NormalizedEvent

_MAX_TSV_CHARS = 900_000  # keep tsvector input well under Postgres' 1MB limit


def dedup_hash(evt: NormalizedEvent) -> str:
    """Stable identity for an event so re-uploading the same file is idempotent."""
    raw_json = json.dumps(evt.raw, sort_keys=True, default=str, ensure_ascii=False)
    h = hashlib.sha256()
    h.update(evt.vendor.encode("utf-8"))
    h.update((evt.event_time.isoformat() if evt.event_time else "none").encode("utf-8"))
    h.update(raw_json.encode("utf-8"))
    return h.hexdigest()


def tsv_text(evt: NormalizedEvent) -> str:
    """Text fed to to_tsvector — normalized fields plus the full raw record."""
    fields = [evt.vendor, evt.product, evt.log_type, evt.severity, evt.action,
              evt.src_ip, evt.dst_ip, evt.protocol, evt.app, evt.user_name,
              evt.host_name, evt.rule_name, evt.message]
    blob = " ".join(str(f) for f in fields if f)
    raw_json = json.dumps(evt.raw, default=str, ensure_ascii=False)
    return (blob + " " + raw_json)[:_MAX_TSV_CHARS]
