"""Cisco IOS / IOS-XE / NX-OS syslog parser.

IOS-family devices log one event per line with a mnemonic tag::

    <189>1001: RTR-CORE: Jun 24 2026 10:00:00.123 UTC: %SEC-6-IPACCESSLOGP: list 101 denied tcp 45.83.122.7(4444) -> 10.20.30.40(51515), 1 packet

The ``%FACILITY-SEVERITY-MNEMONIC:`` token gives the facility (LINK, SYS, SEC …),
the syslog severity level and the mnemonic. Distinct from ASA/FTD (whose
"mnemonic" is a numeric message id — handled by ``cisco_asa``). The 5-tuple /
user are mined from the free-text message; the full message is kept in ``raw``.
"""
from __future__ import annotations

import re
from typing import Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, parse_ts, to_int

_SEVERITY = {0: "emergency", 1: "alert", 2: "critical", 3: "error",
             4: "warning", 5: "notice", 6: "informational", 7: "debug"}

_PRI = re.compile(r"^<\d{1,3}>")
_SEQ = re.compile(r"^\d+:\s*")        # leading sequence number "1001: "
_MSG = re.compile(
    r"%(?P<fac>[A-Z][A-Z0-9_]*)-(?P<sev>\d)-(?P<mnem>[A-Z_][A-Z0-9_]*):\s*(?P<msg>.*)$")
_TS = re.compile(
    r"([A-Z][a-z]{2}\s+\d{1,2}\s+(?:\d{4}\s+)?\d{2}:\d{2}:\d{2}(?:\.\d+)?)")

# ACL logging: "... tcp 45.83.122.7(4444) -> 10.20.30.40(51515) ..."
_ACL = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\((\d+)\)\s*->\s*(\d{1,3}(?:\.\d{1,3}){3})\((\d+)\)")
_SOURCE = re.compile(r"\[Source:\s*([0-9.]+)", re.IGNORECASE)
_USER_BRK = re.compile(r"\[user:\s*([^\]]+)\]", re.IGNORECASE)
_USER_BY = re.compile(r"\bby\s+([A-Za-z0-9._\\-]+)", re.IGNORECASE)
_PROTO = re.compile(r"\b(TCP|UDP|ICMP|GRE|ESP|SCTP)\b", re.IGNORECASE)


def _action(msg: str) -> Optional[str]:
    low = msg.lower()
    if "denied" in low or "deny" in low:
        return "deny"
    if "permitted" in low or "permit" in low:
        return "permit"
    if "failed" in low or "failure" in low:
        return "failure"
    return None


def parse(content: str) -> Iterator[NormalizedEvent]:
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        m = _MSG.search(line)
        if not m:
            continue
        fac = m.group("fac")
        sev = int(m.group("sev"))
        mnem = m.group("mnem")
        msg = m.group("msg").strip()

        head = _SEQ.sub("", _PRI.sub("", line[:m.start()]).strip())
        tsm = _TS.search(head)
        event_time = parse_ts(tsm.group(1)) if tsm else None
        before_ts = head[:tsm.start()] if tsm else head
        host = before_ts.replace("*", " ").strip().rstrip(":").strip() or None
        if host:
            host = host.split()[-1]

        src_ip = src_port = dst_ip = dst_port = None
        acl = _ACL.search(msg)
        if acl:
            src_ip, src_port = acl.group(1), to_int(acl.group(2))
            dst_ip, dst_port = acl.group(3), to_int(acl.group(4))
        elif (sm := _SOURCE.search(msg)):
            src_ip = sm.group(1)

        ub, uby = _USER_BRK.search(msg), _USER_BY.search(msg)
        user = (ub.group(1).strip() if ub else (uby.group(1) if uby else None))
        proto_m = _PROTO.search(msg)

        yield NormalizedEvent(
            event_time=event_time,
            vendor="cisco",
            product="ios",
            log_type=fac.lower(),
            severity=_SEVERITY.get(sev),
            action=_action(msg),
            src_ip=clean_ip(src_ip),
            dst_ip=clean_ip(dst_ip),
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto_m.group(1).lower() if proto_m else None,
            user_name=user,
            host_name=host,
            rule_name=f"%{fac}-{sev}-{mnem}",
            message=msg or None,
            raw={"facility": fac, "severity": sev, "mnemonic": mnem,
                 "message": msg, "host": host, "line": line},
        )
