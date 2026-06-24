"""Google Cloud Platform — Cloud Audit Logs parser.

Cloud Logging exports each entry as a JSON ``LogEntry`` whose ``protoPayload`` is
an ``AuditLog`` (array, single object, NDJSON, or ``{"entries":[…]}``). The
operation is ``protoPayload.methodName`` on ``serviceName``, the caller is
``authenticationInfo.principalEmail`` from ``requestMetadata.callerIp``. The full
entry is kept in ``raw``.
"""
from __future__ import annotations

from typing import Iterator

from ..models import NormalizedEvent
from ..util import clean_ip, first, iter_json_records, parse_ts


def parse(content: str) -> Iterator[NormalizedEvent]:
    for rec in iter_json_records(content, "entries"):
        pp = rec.get("protoPayload") if isinstance(rec.get("protoPayload"), dict) else {}
        auth = pp.get("authenticationInfo") if isinstance(pp.get("authenticationInfo"), dict) else {}
        meta = pp.get("requestMetadata") if isinstance(pp.get("requestMetadata"), dict) else {}
        status = pp.get("status") if isinstance(pp.get("status"), dict) else {}
        method = pp.get("methodName")
        service = pp.get("serviceName")
        sev = rec.get("severity")

        status_msg = status.get("message")
        message = f"{method} — {status_msg}" if (method and status_msg) else first(method, status_msg)

        yield NormalizedEvent(
            event_time=parse_ts(rec.get("timestamp")),
            vendor="gcp",
            product="cloud-audit",
            log_type=service,
            severity=str(sev).lower() if sev else None,
            action=method,
            src_ip=clean_ip(meta.get("callerIp")),
            user_name=first(auth.get("principalEmail")),
            host_name=None,
            rule_name=first(pp.get("resourceName")),
            message=message,
            raw=rec,
        )
