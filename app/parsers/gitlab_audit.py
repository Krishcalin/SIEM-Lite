"""GitLab audit event parser.

GitLab's audit events (API ``/audit_events`` or exports) are JSON objects (array
or NDJSON). The actor and the action detail live under ``details``
(``author_name``, ``ip_address``, ``custom_message`` or an add/remove/change
verb); the affected object is ``entity_type`` / ``details.target_details``. The
full record is kept in ``raw``.
"""
from __future__ import annotations

from typing import Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, iter_json_records, parse_ts


def _action(details: dict, rec: dict) -> Optional[str]:
    msg = details.get("custom_message")
    if msg:
        return msg
    name = first(rec.get("event_name"), details.get("event_name"))
    if name:
        return name
    for verb in ("add", "remove", "change"):
        if verb in details and details[verb] not in (None, ""):
            return f"{verb} {details[verb]}"
    return None


def parse(content: str) -> Iterator[NormalizedEvent]:
    for rec in iter_json_records(content):
        details = rec.get("details") if isinstance(rec.get("details"), dict) else {}
        entity = rec.get("entity_type")
        target = first(details.get("target_details"), details.get("entity_path"))
        action = _action(details, rec)

        message = action
        if action and target and target not in str(action):
            message = f"{action} — {target}"

        yield NormalizedEvent(
            event_time=parse_ts(first(rec.get("created_at"), details.get("created_at"))),
            vendor="gitlab",
            product="audit",
            log_type=(str(entity).lower() if entity else None),
            action=action,
            src_ip=clean_ip(details.get("ip_address")),
            user_name=first(details.get("author_name"), rec.get("author_id")),
            host_name=None,
            rule_name=target,
            message=message,
            raw=rec,
        )
