"""Zeek (Bro) TSV log parser — conn / dns / http and other ``#fields`` logs.

Classic Zeek logs are tab-separated with a metadata header::

    #separator \\x09
    #fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	...
    1781517600.123	CXY	10.20.30.40	51514	93.184.216.34	443	tcp	ssl	...

We read the ``#separator`` / ``#fields`` / ``#path`` / ``#unset_field`` directives,
then map each data row to the common schema. A single file may concatenate
several logs (each with its own header); the header is re-read when it changes.
The full row is kept in ``raw``.
"""
from __future__ import annotations

import re
from typing import Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, parse_ts, to_int

_NUM = re.compile(r"^\d+(?:\.\d+)?$")


def _decode_sep(v: str) -> str:
    v = v.strip()
    if v.lower().startswith("\\x"):
        try:
            return chr(int(v[2:], 16))
        except ValueError:
            return "\t"
    return {"\\t": "\t"}.get(v, v) or "\t"


def _ts(value: Optional[str]):
    if value and _NUM.match(value):
        return parse_ts(float(value))   # Zeek ts is epoch seconds with a fraction
    return parse_ts(value)


def _message(path: str, g) -> Optional[str]:
    if path == "dns":
        return (f"DNS {g('qtype_name') or ''} {g('query') or ''}".strip()) or None
    if path == "http":
        return (f"HTTP {g('method') or ''} {g('host') or ''}{g('uri') or ''}".strip()) or None
    return first(g("service"), g("conn_state"), path)


def parse(content: str) -> Iterator[NormalizedEvent]:
    sep, unset, empty = "\t", "-", "(empty)"
    fields: list[str] = []
    path: Optional[str] = None

    for line in content.splitlines():
        if not line:
            continue
        if line.startswith("#separator"):
            parts = line.split(" ", 1)
            sep = _decode_sep(parts[1]) if len(parts) > 1 else "\t"
            continue
        if line.startswith("#"):
            key, _, rest = line[1:].partition(sep)
            key = key.strip()
            if key == "fields":
                fields = rest.split(sep)
            elif key == "path":
                path = rest.strip()
            elif key == "unset_field":
                unset = rest.strip()
            elif key == "empty_field":
                empty = rest.strip()
            continue
        if not fields:
            continue

        values = line.split(sep)
        row = {k: (None if v in (unset, empty) else v) for k, v in zip(fields, values)}

        def g(*names: str) -> Optional[str]:
            for n in names:
                v = row.get(n)
                if v not in (None, ""):
                    return v
            return None

        sizes = [x for x in (to_int(g("orig_bytes")), to_int(g("resp_bytes")),
                             to_int(g("request_body_len")), to_int(g("response_body_len")))
                 if x is not None]
        proto = g("proto")
        p = path or "conn"
        if p == "dns":
            action = g("rcode_name")
        elif p == "http":
            action = g("status_code")
        else:
            action = g("conn_state")

        yield NormalizedEvent(
            event_time=_ts(g("ts")),
            vendor="zeek",
            product=p,
            log_type=p,
            action=action,
            src_ip=clean_ip(g("id.orig_h")),
            dst_ip=clean_ip(g("id.resp_h")),
            src_port=to_int(g("id.orig_p")),
            dst_port=to_int(g("id.resp_p")),
            protocol=proto.lower() if proto else None,
            app=first(g("service"), g("app")),
            user_name=first(g("user"), g("username")),
            host_name=first(g("server_name")),
            rule_name=g("uid"),
            bytes_total=sum(sizes) if sizes else None,
            message=_message(p, g),
            raw=row,
        )
