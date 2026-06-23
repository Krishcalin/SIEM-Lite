"""Fortinet FortiGate parser (key=value syslog).

FortiGate emits one event per line as space-separated ``key=value`` pairs (values
may be double-quoted), optionally behind a syslog header:

    date=2026-06-15 time=10:00:31 devname="FGT" devid="FG.." logid="…" type="traffic"
    subtype="forward" level="notice" srcip=10.20.30.40 srcport=51514 dstip=… action="accept" …

Field names are stable across log types (traffic / utm / event / vpn), so we map
by key and keep the full pair set in ``raw``.
"""
from __future__ import annotations

import re
from typing import Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, parse_ts, to_int

_KV = re.compile(r'([A-Za-z0-9_.\-]+)=("([^"]*)"|\S*)')
_PROTO = {"1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp",
          "58": "ipv6-icmp", "89": "ospf", "132": "sctp"}


def _kv(line: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in _KV.finditer(line):
        key = m.group(1).lower()
        out[key] = m.group(3) if m.group(3) is not None else m.group(2)
    return out


def parse(content: str) -> Iterator[NormalizedEvent]:
    for line in content.splitlines():
        if "devname=" not in line and "date=" not in line:
            continue
        f = _kv(line)
        if not f.get("type") and not f.get("logid"):
            continue

        def g(*names: str) -> Optional[str]:
            for n in names:
                v = f.get(n)
                if v not in (None, ""):
                    return v
            return None

        proto = g("proto")
        sent, rcvd = to_int(g("sentbyte")), to_int(g("rcvdbyte"))
        bytes_total = (sent or 0) + (rcvd or 0) if (sent is not None or rcvd is not None) else None
        policy = first(g("policyname"), ("policy " + g("policyid")) if g("policyid") else None)

        yield NormalizedEvent(
            event_time=parse_ts(first(
                (f"{g('date')} {g('time')}" if g("date") and g("time") else None),
                g("eventtime"),
            )),
            vendor="fortinet",
            product="fortigate",
            log_type=str(first(g("subtype"), g("type")) or "traffic").lower(),
            severity=(g("level", "severity") or "").lower() or None,
            action=g("action"),
            src_ip=clean_ip(g("srcip")),
            dst_ip=clean_ip(g("dstip")),
            src_port=to_int(g("srcport")),
            dst_port=to_int(g("dstport")),
            protocol=_PROTO.get(str(proto), proto.lower() if proto else None) if proto else None,
            app=first(g("app", "appid"), g("service")),
            user_name=first(g("srcuser", "user"), g("unauthuser")),
            host_name=g("devname"),
            rule_name=policy,
            bytes_total=bytes_total,
            message=first(g("msg"), g("attack"), g("logdesc"), g("url"), g("subtype")),
            raw=f,
        )
