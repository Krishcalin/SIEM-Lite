"""Apache / Nginx access-log parser (Common & Combined Log Format).

Both Apache's CLF/combined and Nginx's default ``combined`` log share one layout:

    HOST IDENT AUTH [DD/Mon/YYYY:HH:MM:SS +ZZZZ] "METHOD PATH PROTO" STATUS BYTES \
        "REFERER" "USER-AGENT"

    45.83.122.7 - - [24/Jun/2026:10:00:00 +0000] "GET /admin/../../etc/passwd HTTP/1.1" \
        404 512 "-" "curl/8.4.0"

The referer + user-agent pair (combined) is optional (plain CLF omits it). The
client IP, auth user, request line, status, size, referer and user-agent are
normalized; the whole request line goes into ``message`` so path-traversal /
tool-signature detections can match. The full parse is kept in ``raw``.
"""
from __future__ import annotations

import re
from typing import Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, to_int, parse_ts

_LINE = re.compile(
    r'^(?P<host>\S+)\s+\S+\s+(?P<auth>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<req>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?\s*$')
_METHODS = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE")


def _severity(status: int) -> Optional[str]:
    if 500 <= status <= 599:
        return "error"
    if 400 <= status <= 499:
        return "warning"
    return None


def parse(content: str) -> Iterator[NormalizedEvent]:
    for line in content.splitlines():
        m = _LINE.match(line.strip())
        if not m:
            continue
        status = int(m.group("status"))
        # Apache stamp "10/Oct/2000:13:55:36 -0700" -> swap the first ':' for a space.
        ts = parse_ts(m.group("ts").replace(":", " ", 1))
        req = m.group("req")
        parts = req.split()
        method = parts[0] if parts else None
        path = parts[1] if len(parts) > 1 else None
        proto = parts[2] if len(parts) > 2 else None
        auth = m.group("auth")

        yield NormalizedEvent(
            event_time=ts,
            vendor="web",
            product="access",
            log_type="access",
            severity=_severity(status),
            action=method,
            src_ip=clean_ip(m.group("host")),
            app="http",
            user_name=auth if auth not in ("-", "") else None,
            rule_name=f"HTTP {status}",
            bytes_total=to_int(m.group("size")),
            message=first(req, path),
            raw={"host": m.group("host"), "auth": auth, "request": req,
                 "method": method, "path": path, "protocol": proto,
                 "status": status, "bytes": m.group("size"),
                 "referer": m.group("ref"), "user_agent": m.group("ua")},
        )
