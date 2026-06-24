"""Upload ingest orchestration: per-file batch + sha around the shared pipeline.

The detect → parse → normalize → insert core lives in `pipeline`; this module
adds the file-specific concerns (content hash, one batch per uploaded file,
informational duplicate-file detection) and the result summary the UI shows.
Live sources (syslog / HTTP API, Phase 1) reuse `pipeline` directly with their
own batch lifecycle.
"""
from __future__ import annotations

import hashlib

from . import db, pipeline

_VENDOR_OF = {
    "paloalto_csv": "paloalto", "paloalto_syslog": "paloalto",
    "crowdstrike_csv": "crowdstrike", "crowdstrike_json": "crowdstrike",
}


def ingest(filename: str, content: str, fmt: str) -> dict:
    """Parse and store one uploaded file. Returns a result summary."""
    events = pipeline.parse_events(content, fmt)  # validates fmt before any DB work

    sha = hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()
    prior = db.find_batch_by_sha(sha)  # informational: same bytes seen before
    batch_id = db.create_batch(filename, sha, _VENDOR_OF.get(fmt), fmt)

    with db.pool().connection() as conn:
        try:
            total = pipeline.write_stream(conn, events, batch_id)
            conn.commit()
        except Exception as exc:  # noqa: BLE001 — record failure on the batch, then re-raise
            conn.rollback()
            db.update_batch(batch_id, status="error", notes=str(exc)[:500])
            raise

    inserted = db.count_batch_rows(batch_id)
    duplicates = max(total - inserted, 0)
    db.update_batch(batch_id, status="done", total_rows=total, inserted_rows=inserted,
                    duplicate_rows=duplicates, error_rows=0)

    return {
        "batch_id": batch_id, "filename": filename, "format": fmt,
        "vendor": _VENDOR_OF.get(fmt), "sha256": sha,
        "total": total, "inserted": inserted, "duplicates": duplicates, "errors": 0,
        "already_ingested": bool(prior),
    }
