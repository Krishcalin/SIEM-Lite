"""Generic JSON / NDJSON catch-all parser.

The JSON analog of ``generic_syslog``: a best-effort mapper for JSON logs that
aren't a more specific supported source. Records (single object, array, NDJSON,
or a ``{"records"|"data"|"events":[…]}`` wrapper) are flattened one level
(so Elastic Common Schema keys like ``source.ip`` / ``event.action`` resolve)
and matched against candidate field names. Whatever can't be mapped stays in
``raw`` and remains searchable.
"""
from __future__ import annotations

from typing import Any, Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, iter_json_records, parse_ts, to_int

_TIME = ("@timestamp", "timestamp", "time", "eventtime", "event_time", "_time",
         "datetime", "created_at", "ts", "observedtimestamp", "date")
_SRC_IP = ("source.ip", "src_ip", "srcip", "source_ip", "sourceip", "client.ip",
           "client_ip", "clientip", "src", "ipaddress", "ip")
_DST_IP = ("destination.ip", "dst_ip", "dstip", "dest_ip", "destip", "destination_ip",
           "server.ip", "dst")
_SRC_PORT = ("source.port", "src_port", "srcport", "sport", "sourceport")
_DST_PORT = ("destination.port", "dst_port", "dstport", "dport", "destinationport")
_PROTO = ("network.protocol", "network.transport", "protocol", "proto", "transport", "ip_proto")
_USER = ("user.name", "username", "user_name", "user", "account", "principal",
         "actor", "src_user", "subject")
_HOST = ("host.name", "hostname", "host", "computer", "device", "dvc", "observer.hostname")
_ACTION = ("event.action", "action", "act", "event_action", "disposition", "outcome", "activity")
_SEVERITY = ("event.severity", "severity", "level", "sev", "priority", "log.level")
_MESSAGE = ("message", "msg", "description", "summary", "text", "event.original", "raw_message")
_RULE = ("rule.name", "rule", "rule_name", "signature", "alert.signature", "policy", "rulename")
_BYTES = ("network.bytes", "bytes", "bytes_total", "total_bytes")
_LOGTYPE = ("event.category", "event.type", "event_type", "event.dataset", "log_type",
            "logtype", "category", "type", "eventtype")
_VENDOR = ("observer.vendor", "vendor")
_PRODUCT = ("observer.product", "product")


def _flatten(obj: Any, prefix: str, out: dict) -> dict:
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}{k}"
            if isinstance(v, dict):
                _flatten(v, key + ".", out)
            elif not isinstance(v, list):
                out[key.lower()] = v
    return out


def parse(content: str) -> Iterator[NormalizedEvent]:
    for rec in iter_json_records(content, "records", "data", "events", "logs"):
        flat = _flatten(rec, "", {})

        def g(names) -> Optional[Any]:
            for n in names:
                v = flat.get(n)
                if v not in (None, ""):
                    return v
            return None

        proto = g(_PROTO)
        sev = g(_SEVERITY)
        vendor = g(_VENDOR)
        log_type = g(_LOGTYPE)

        yield NormalizedEvent(
            event_time=parse_ts(g(_TIME)),
            vendor=str(vendor).lower() if vendor else "json",
            product=(str(g(_PRODUCT)) if g(_PRODUCT) else None),
            log_type=str(log_type) if log_type else None,
            severity=str(sev).lower() if sev not in (None, "") else None,
            action=(str(g(_ACTION)) if g(_ACTION) is not None else None),
            src_ip=clean_ip(g(_SRC_IP)),
            dst_ip=clean_ip(g(_DST_IP)),
            src_port=to_int(g(_SRC_PORT)),
            dst_port=to_int(g(_DST_PORT)),
            protocol=str(proto).lower() if proto else None,
            user_name=(str(g(_USER)) if g(_USER) is not None else None),
            host_name=(str(g(_HOST)) if g(_HOST) is not None else None),
            rule_name=(str(g(_RULE)) if g(_RULE) is not None else None),
            bytes_total=to_int(g(_BYTES)),
            message=(str(g(_MESSAGE)) if g(_MESSAGE) is not None else None),
            raw=rec,
        )
