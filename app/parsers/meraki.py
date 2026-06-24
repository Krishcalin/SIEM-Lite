"""Cisco Meraki syslog parser.

Meraki MX/MR/MS devices emit RFC 5424-style syslog where the message body starts
with an event type followed by ``key=value`` pairs and a trailing free-text note::

    <134>1 2026-06-24T10:00:00.000000Z MX84-CORP flows src=45.83.122.7 dst=10.20.30.40 protocol=tcp sport=4444 dport=51515 pattern: deny all
    <134>1 ... MX84-CORP urls src=10.20.30.40:51000 dst=93.184.216.34:443 request: GET https://example.com/
    <134>1 ... MX84-CORP ids-alerts signature=1:2010935:3 ... src=45.83.122.7:4444 dst=10.20.30.40:51515 message: ET MALWARE ...

We lift the 5-tuple from the key=value pairs (``src``/``dst`` may carry ``:port``)
and the human note (``pattern:`` / ``request:`` / ``message:``) into the message.
The full pair set is kept in ``raw``.
"""
from __future__ import annotations

import re
from typing import Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, parse_ts, split_ip_port, to_int

_HEADER = re.compile(
    r"^(?:<\d{1,3}>)?(?:\d+\s+)?(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<etype>\S+)\s+(?P<rest>.*)$")
_KV = re.compile(r"(\w[\w.\-]*)=(\S+)")
_NOTE = re.compile(r"(?:message|request|pattern|reason|url):\s*(.*)$", re.IGNORECASE)
_PATTERN = re.compile(r"(?:pattern|disposition|action):\s*(\w+)", re.IGNORECASE)


def parse(content: str) -> Iterator[NormalizedEvent]:
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        h = _HEADER.match(line)
        if not h:
            continue
        etype = h.group("etype")
        rest = h.group("rest")
        # Only scan key=value pairs in the portion *before* the free-text note, so
        # a `?a=b` query string or `key=value` inside the note isn't mined as a field.
        note = _NOTE.search(rest)
        kv_part = rest[:note.start()] if note else rest
        kv = {k.lower(): v for k, v in _KV.findall(kv_part)}
        if not kv and "=" not in rest:
            continue   # not a Meraki key=value body

        src_ip, src_port = split_ip_port(kv.get("src"))
        dst_ip, dst_port = split_ip_port(kv.get("dst"))
        proto = kv.get("protocol") or kv.get("proto")
        if proto:
            proto = proto.split("/")[0].lower()    # "tcp/ip" -> "tcp"
        pat = kv.get("disposition") or kv.get("action")
        if not pat and (pm := _PATTERN.search(rest)):
            pat = pm.group(1)

        yield NormalizedEvent(
            event_time=parse_ts(h.group("ts")),
            vendor="cisco",
            product="meraki",
            log_type=etype.lower(),
            action=pat.lower() if pat else None,
            src_ip=clean_ip(src_ip),
            dst_ip=clean_ip(dst_ip),
            src_port=first(src_port, to_int(kv.get("sport"))),
            dst_port=first(dst_port, to_int(kv.get("dport"))),
            protocol=proto,
            user_name=first(kv.get("user"), kv.get("identity")),
            host_name=h.group("host"),
            rule_name=first(kv.get("signature"), kv.get("rule")),
            bytes_total=to_int(kv.get("bytes")),
            message=first(note.group(1).strip() if note else None, etype),
            raw={"event_type": etype, **kv},
        )
