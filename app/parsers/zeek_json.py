"""Zeek (Bro) JSON log parser — conn / dns / http and other logs.

When Zeek is configured with ``LogAscii::use_json=T`` it writes one JSON object
per line (NDJSON; manual exports may be a JSON array). Keys mirror the TSV
columns — ``ts``, ``uid``, ``id.orig_h`` … — and records often carry ``_path``
identifying the log. We map the same fields as ``zeek_tsv`` and keep the whole
record in ``raw``.
"""
from __future__ import annotations

from typing import Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, iter_json_records, parse_ts, to_int


def _path(rec: dict) -> str:
    p = rec.get("_path")
    if p:
        return str(p).lower()
    if rec.get("query") is not None:
        return "dns"
    if any(k in rec for k in ("method", "uri", "host", "status_code")):
        return "http"
    return "conn"


def _message(path: str, rec: dict) -> Optional[str]:
    if path == "dns":
        return (f"DNS {rec.get('qtype_name', '') or ''} {rec.get('query', '') or ''}".strip()) or None
    if path == "http":
        return (f"HTTP {rec.get('method', '') or ''} {rec.get('host', '') or ''}"
                f"{rec.get('uri', '') or ''}".strip()) or None
    return first(rec.get("service"), rec.get("conn_state"), path)


def parse(content: str) -> Iterator[NormalizedEvent]:
    for rec in iter_json_records(content):
        path = _path(rec)
        sizes = [x for x in (to_int(rec.get("orig_bytes")), to_int(rec.get("resp_bytes")),
                             to_int(rec.get("request_body_len")), to_int(rec.get("response_body_len")))
                 if x is not None]
        proto = rec.get("proto")
        if path == "dns":
            action = rec.get("rcode_name")
        elif path == "http":
            action = rec.get("status_code")
        else:
            action = rec.get("conn_state")

        yield NormalizedEvent(
            event_time=parse_ts(rec.get("ts")),
            vendor="zeek",
            product=path,
            log_type=path,
            action=str(action) if action not in (None, "") else None,
            src_ip=clean_ip(rec.get("id.orig_h")),
            dst_ip=clean_ip(rec.get("id.resp_h")),
            src_port=to_int(rec.get("id.orig_p")),
            dst_port=to_int(rec.get("id.resp_p")),
            protocol=str(proto).lower() if proto else None,
            app=first(rec.get("service")),
            user_name=first(rec.get("user"), rec.get("username")),
            host_name=first(rec.get("server_name")),
            rule_name=first(rec.get("uid")),
            bytes_total=sum(sizes) if sizes else None,
            message=_message(path, rec),
            raw=rec,
        )
