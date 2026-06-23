"""Cisco ASA / Firepower Threat Defense (FTD) syslog parser.

ASA/FTD emit one event per line keyed by a message ID::

    <166>Jun 15 2026 10:00:31 ASA-FW : %ASA-6-302013: Built outbound TCP connection ...
    %ASA-2-106023: Deny tcp src outside:45.83.122.7/4444 dst inside:10.20.30.40/51515 ...

The ``%FAC-LEVEL-ID:`` token gives the facility (ASA/FTD/PIX/FWSM/ASASM), the
syslog severity level, and the message number. The 5-tuple, byte count and user
are mined from the free-text message with best-effort regexes (``src``/``dst``,
``from``/``to`` and the Built-connection ``for``/``to`` phrasing); the full
message is always kept in ``raw``.
"""
from __future__ import annotations

import re
from typing import Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, parse_ts, to_int

_SEVERITY = {0: "emergency", 1: "alert", 2: "critical", 3: "error",
             4: "warning", 5: "notice", 6: "informational", 7: "debug"}

_PRI = re.compile(r"^<\d{1,3}>")
_MSGID = re.compile(
    r"%(?P<fac>ASA|FTD|ASASM|FWSM|PIX)-(?P<lvl>\d)-(?P<id>\d+):\s*(?P<msg>.*)$",
    re.IGNORECASE)
_TS = re.compile(
    r"([A-Z][a-z]{2}\s+\d{1,2}\s+(?:\d{4}\s+)?\d{2}:\d{2}:\d{2}(?:\.\d+)?)")

_ADDR = r"(?:[\w\-]+:)?(\d{1,3}(?:\.\d{1,3}){3})/(\d+)"
_SRC = re.compile(r"\bsrc\s+" + _ADDR, re.IGNORECASE)
_DST = re.compile(r"\bdst\s+" + _ADDR, re.IGNORECASE)
_FROM = re.compile(r"\bfrom\s+" + _ADDR, re.IGNORECASE)
_TO = re.compile(r"\bto\s+" + _ADDR, re.IGNORECASE)
_FOR = re.compile(r"\bfor\s+" + _ADDR, re.IGNORECASE)
_BYTES = re.compile(r"\bbytes\s+(\d+)", re.IGNORECASE)
_USER = re.compile(r"\buser\s+'?([\w.\-\\@]+)'?", re.IGNORECASE)
_PROTO = re.compile(r"\b(TCP|UDP|ICMP|GRE|ESP|SCTP)\b", re.IGNORECASE)


def _action(msg: str) -> Optional[str]:
    low = msg.lower()
    if low.startswith("deny") or " deny " in low or "denied" in low:
        return "deny"
    if "built" in low or "permitted" in low or "allowed" in low or "allow " in low:
        return "allow"
    if "teardown" in low:
        return "teardown"
    return None


def parse(content: str) -> Iterator[NormalizedEvent]:
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        m = _MSGID.search(line)
        if not m:
            continue
        fac = m.group("fac").upper()
        lvl = int(m.group("lvl"))
        mid = m.group("id")
        msg = m.group("msg").strip()

        head = _PRI.sub("", line[:m.start()]).strip()
        tsm = _TS.search(head)
        event_time = parse_ts(tsm.group(1)) if tsm else None
        if tsm:
            head = head[:tsm.start()] + head[tsm.end():]
        head = head.strip().strip(":").strip()
        host = head.split()[-1].strip(": ") if head else None

        s, d = _SRC.search(msg), _DST.search(msg)
        fr, to, fo = _FROM.search(msg), _TO.search(msg), _FOR.search(msg)
        src_ip = src_port = dst_ip = dst_port = None
        if s and d:
            src_ip, src_port = s.group(1), to_int(s.group(2))
            dst_ip, dst_port = d.group(1), to_int(d.group(2))
        elif fr and to:
            src_ip, src_port = fr.group(1), to_int(fr.group(2))
            dst_ip, dst_port = to.group(1), to_int(to.group(2))
        elif fo and to:                       # "Built ... for <foreign> to <local>"
            dst_ip, dst_port = fo.group(1), to_int(fo.group(2))
            src_ip, src_port = to.group(1), to_int(to.group(2))

        proto_m, bytes_m, user_m = _PROTO.search(msg), _BYTES.search(msg), _USER.search(msg)

        yield NormalizedEvent(
            event_time=event_time,
            vendor="cisco",
            product="firepower" if fac == "FTD" else "asa",
            log_type=mid,
            severity=_SEVERITY.get(lvl),
            action=_action(msg),
            src_ip=clean_ip(src_ip),
            dst_ip=clean_ip(dst_ip),
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto_m.group(1).lower() if proto_m else None,
            user_name=user_m.group(1) if user_m else None,
            host_name=host,
            rule_name=f"%{fac}-{lvl}-{mid}",
            bytes_total=to_int(bytes_m.group(1)) if bytes_m else None,
            message=msg or None,
            raw={"facility": fac, "level": lvl, "message_id": mid, "message": msg,
                 "host": host, "line": line},
        )
