"""Okta System Log parser (identity / SSO events).

The Okta System Log API returns JSON events (array or NDJSON) describing
authentication and admin activity. Each event has an ``eventType``, an
``actor``, a ``client`` (with ``ipAddress``) and an ``outcome``. The full event
is kept in ``raw``.
"""
from __future__ import annotations

from typing import Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, iter_json_records, parse_ts

_SEV = {"info": "informational", "warn": "warning", "error": "error", "debug": "debug"}


def _app_target(rec: dict) -> Optional[str]:
    targets = rec.get("target")
    if isinstance(targets, list):
        for t in targets:
            if isinstance(t, dict) and t.get("type") in ("AppInstance", "app"):
                return t.get("displayName") or t.get("alternateId")
    return None


def parse(content: str) -> Iterator[NormalizedEvent]:
    for rec in iter_json_records(content, "value"):
        actor = rec.get("actor") if isinstance(rec.get("actor"), dict) else {}
        client = rec.get("client") if isinstance(rec.get("client"), dict) else {}
        outcome = rec.get("outcome") if isinstance(rec.get("outcome"), dict) else {}

        src_ip = client.get("ipAddress")
        if not src_ip:
            req = rec.get("request") if isinstance(rec.get("request"), dict) else {}
            chain = req.get("ipChain") if isinstance(req.get("ipChain"), list) else []
            if chain and isinstance(chain[0], dict):
                src_ip = chain[0].get("ip")

        sev = str(rec.get("severity") or "").lower()
        result = outcome.get("result")
        reason = outcome.get("reason")
        display = rec.get("displayMessage") or rec.get("eventType")
        message = f"{display} — {reason}" if (display and reason) else display

        yield NormalizedEvent(
            event_time=parse_ts(rec.get("published")),
            vendor="okta",
            product="system-log",
            log_type=rec.get("eventType"),
            severity=_SEV.get(sev, sev or None),
            action=str(result).lower() if result else None,
            src_ip=clean_ip(src_ip),
            user_name=first(actor.get("alternateId"), actor.get("displayName")),
            app=_app_target(rec),
            host_name=None,
            rule_name=first(rec.get("legacyEventType"), rec.get("eventType")),
            message=message,
            raw=rec,
        )
