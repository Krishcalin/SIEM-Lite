"""AWS CloudTrail parser (management & data events).

CloudTrail delivers JSON as ``{"Records": [ ... ]}``, a single event, or NDJSON.
Each record carries ``eventSource`` / ``eventName`` plus the caller's
``userIdentity`` and ``sourceIPAddress``. We normalize those and derive a
success/failure action from ``errorCode`` / ``responseElements``; the full
record is kept in ``raw``.
"""
from __future__ import annotations

from typing import Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, iter_json_records, parse_ts


def _service(event_source: Optional[str]) -> Optional[str]:
    """'signin.amazonaws.com' -> 'signin'."""
    if not event_source:
        return None
    return str(event_source).split(".")[0] or None


def parse(content: str) -> Iterator[NormalizedEvent]:
    for rec in iter_json_records(content, "Records"):
        ui = rec.get("userIdentity") if isinstance(rec.get("userIdentity"), dict) else {}
        resp = rec.get("responseElements") if isinstance(rec.get("responseElements"), dict) else {}
        event_name = rec.get("eventName")
        service = _service(rec.get("eventSource"))
        console = resp.get("ConsoleLogin") if resp else None
        err = rec.get("errorCode")

        if console:
            action = str(console).lower()       # success / failure
        elif err:
            action = "failed"
        else:
            action = "success"                  # API call recorded with no error

        if rec.get("errorMessage"):
            message = str(rec["errorMessage"])
        else:
            message = f"{event_name}" + (f" — {console}" if console else "")

        yield NormalizedEvent(
            event_time=parse_ts(rec.get("eventTime")),
            vendor="aws",
            product="cloudtrail",
            log_type=service,
            action=action,
            src_ip=clean_ip(rec.get("sourceIPAddress")),
            user_name=first(ui.get("userName"), ui.get("arn"), ui.get("principalId"), ui.get("type")),
            host_name=first(rec.get("recipientAccountId"), ui.get("accountId")),
            app=service,
            rule_name=event_name,
            message=message or None,
            raw=rec,
        )
