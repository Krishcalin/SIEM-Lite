"""Ingest orchestration: per-batch sha + lifecycle around the shared pipeline.

The detect → parse → normalize → insert core lives in `pipeline`; this module
adds the per-batch concerns (content hash, one batch per upload or API POST,
informational duplicate detection, source tagging) and the result summary the
UI / API returns. The same `ingest()` serves uploads (`source_type="upload"`)
and the HTTP ingest API (`source_type="api"`).
"""
from __future__ import annotations

import hashlib
from typing import Optional

from . import alert_actions, db, pipeline

_VENDOR_OF = {
    "paloalto_csv": "paloalto", "paloalto_syslog": "paloalto",
    "crowdstrike_csv": "crowdstrike", "crowdstrike_json": "crowdstrike",
}


def ingest(content: str, fmt: str, *, filename: Optional[str] = None,
           source_type: str = "upload", source_addr: Optional[str] = None) -> dict:
    """Parse and store one batch of content. Returns a result summary."""
    events = pipeline.parse_events(content, fmt)  # validates fmt before any DB work

    sha = hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()
    prior = db.find_batch_by_sha(sha)  # informational: same bytes seen before
    batch_id = db.create_batch(filename, sha, _VENDOR_OF.get(fmt), fmt,
                               source_type=source_type, source_addr=source_addr)

    with db.pool().connection() as conn:
        try:
            result = pipeline.write_stream(conn, events, batch_id)
            conn.commit()
        except Exception as exc:  # noqa: BLE001 — record failure on the batch, then re-raise
            conn.rollback()
            db.update_batch(batch_id, status="error", notes=str(exc)[:500])
            raise
    alert_actions.dispatch(result.alerts)  # after commit: notify + run response playbooks

    inserted = db.count_batch_rows(batch_id)
    duplicates = max(result.total - inserted, 0)
    db.update_batch(batch_id, status="done", total_rows=result.total, inserted_rows=inserted,
                    duplicate_rows=duplicates, error_rows=0)

    return {
        "batch_id": batch_id, "filename": filename, "format": fmt,
        "vendor": _VENDOR_OF.get(fmt), "sha256": sha, "source_type": source_type,
        "total": result.total, "inserted": inserted, "duplicates": duplicates, "errors": 0,
        "already_ingested": bool(prior),
    }
