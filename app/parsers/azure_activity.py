"""Microsoft Azure — Activity Log parser.

Azure Monitor exports the subscription Activity Log as JSON, usually wrapped in
``{"records":[…]}`` (also handles a bare array / NDJSON and the REST
``az monitor activity-log list`` shape). Each record has an ``operationName``,
a ``resultType`` outcome, ``callerIpAddress`` and an ``identity`` with the
caller's name. The full record is kept in ``raw``.
"""
from __future__ import annotations

from typing import Any, Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, iter_json_records, parse_ts

_LEVEL = {"information": "informational", "informational": "informational",
          "warning": "warning", "error": "error", "critical": "critical",
          "verbose": "debug"}


def _g(rec: dict, *names: str) -> Optional[Any]:
    low = {str(k).strip().lower(): v for k, v in rec.items()}
    for n in names:
        v = low.get(n.lower())
        if v not in (None, ""):
            return v
    return None


def _localized(value: Any) -> Optional[str]:
    """operationName / resultType can be a string or {"value","localizedValue"}."""
    if isinstance(value, dict):
        return value.get("value") or value.get("localizedValue")
    return value


def _caller(rec: dict) -> Optional[str]:
    ident = _g(rec, "identity")
    if isinstance(ident, dict):
        claims = ident.get("claims") if isinstance(ident.get("claims"), dict) else {}
        name = (claims.get("name")
                or claims.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn")
                or claims.get("upn"))
        if name:
            return name
    return _g(rec, "caller")


def parse(content: str) -> Iterator[NormalizedEvent]:
    for rec in iter_json_records(content, "records", "value"):
        operation = _localized(_g(rec, "operationname"))
        result = _localized(_g(rec, "resulttype", "status"))
        level = str(_g(rec, "level") or "").lower()
        ip = _g(rec, "calleripaddress", "clientipaddress")
        category = _g(rec, "category")

        message = f"{operation} ({result})" if (operation and result) else first(operation, result)

        yield NormalizedEvent(
            event_time=parse_ts(_g(rec, "time", "eventtimestamp")),
            vendor="microsoft",
            product="azure",
            log_type=(str(category).lower() if category else "activity"),
            severity=_LEVEL.get(level, level or None),
            action=operation,
            src_ip=clean_ip(ip),
            user_name=_caller(rec),
            host_name=None,
            rule_name=first(_g(rec, "resourceid")),
            message=message,
            raw=rec,
        )
