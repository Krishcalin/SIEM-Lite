"""Microsoft 365 Unified Audit Log parser.

Handles the Office 365 Management Activity API record shape (and the
``Search-UnifiedAuditLog`` rows that embed an ``AuditData`` JSON string). Each
record has an ``Operation`` on a ``Workload`` with a ``ResultStatus`` and the
actor's ``UserId`` / ``ClientIP``. The full record is kept in ``raw``.
"""
from __future__ import annotations

import json
from typing import Any, Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, iter_json_records, parse_ts, split_ip_port


def _g(rec: dict, *names: str) -> Optional[Any]:
    low = {str(k).strip().lower(): v for k, v in rec.items()}
    for n in names:
        v = low.get(n.lower())
        if v not in (None, ""):
            return v
    return None


def parse(content: str) -> Iterator[NormalizedEvent]:
    for rec in iter_json_records(content):
        if isinstance(rec.get("AuditData"), str):   # Search-UnifiedAuditLog row
            try:
                rec = {**rec, **json.loads(rec["AuditData"])}
            except (json.JSONDecodeError, TypeError):
                pass

        operation = _g(rec, "operation")
        workload = _g(rec, "workload")
        result = _g(rec, "resultstatus", "result")
        ip, port = split_ip_port(_g(rec, "clientip", "clientipaddress", "actoripaddress"))

        message = f"{operation} ({result})" if (operation and result) else operation

        yield NormalizedEvent(
            event_time=parse_ts(_g(rec, "creationtime", "creationdate")),
            vendor="microsoft",
            product="o365",
            log_type=(str(workload).lower() if workload else None),
            action=operation,
            src_ip=clean_ip(ip),
            src_port=port,
            user_name=_g(rec, "userid", "userprincipalname", "userkey"),
            host_name=None,
            rule_name=_g(rec, "objectid"),
            message=message,
            raw=rec,
        )
