"""Ingest orchestration: detect → parse → normalize → bulk insert → batch stats."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from . import db
from .parsers import PARSERS

_CHUNK = 5000

_VENDOR_OF = {
    "paloalto_csv": "paloalto", "paloalto_syslog": "paloalto",
    "crowdstrike_csv": "crowdstrike", "crowdstrike_json": "crowdstrike",
}


def ingest(filename: str, content: str, fmt: str) -> dict:
    """Parse and store one uploaded file. Returns a result summary."""
    if fmt not in PARSERS:
        raise ValueError(f"unknown format: {fmt}")

    sha = hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()
    prior = db.find_batch_by_sha(sha)  # informational: same bytes seen before
    batch_id = db.create_batch(filename, sha, _VENDOR_OF.get(fmt), fmt)

    parser = PARSERS[fmt]
    total = errors = 0
    chunk = []

    with db.pool().connection() as conn:
        try:
            for evt in parser.parse(content):
                total += 1
                if evt.event_time is None:
                    evt.event_time = datetime.now(timezone.utc)
                    evt.raw.setdefault("_parse_note", "missing_or_unparsed_timestamp")
                chunk.append(evt)
                if len(chunk) >= _CHUNK:
                    db.insert_events(conn, chunk, batch_id)
                    chunk = []
            if chunk:
                db.insert_events(conn, chunk, batch_id)
            conn.commit()
        except Exception as exc:  # noqa: BLE001 — record failure on the batch, then re-raise
            conn.rollback()
            db.update_batch(batch_id, status="error", total_rows=total, notes=str(exc)[:500])
            raise

    inserted = db.count_batch_rows(batch_id)
    duplicates = max(total - inserted - errors, 0)
    db.update_batch(batch_id, status="done", total_rows=total, inserted_rows=inserted,
                    duplicate_rows=duplicates, error_rows=errors)

    return {
        "batch_id": batch_id, "filename": filename, "format": fmt,
        "vendor": _VENDOR_OF.get(fmt), "sha256": sha,
        "total": total, "inserted": inserted, "duplicates": duplicates, "errors": errors,
        "already_ingested": bool(prior),
    }
