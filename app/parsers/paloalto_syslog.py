"""Palo Alto NGFW — syslog parser (comma-separated payload, no header row).

PAN forwards logs as syslog whose payload is positional CSV. After splitting a
line on commas (quote-aware), field[0] is the syslog header + a FUTURE_USE token,
field[1] is Receive Time, field[3] is the log Type, and so on. The field order is
documented by Palo Alto and is largely stable across PAN-OS 9/10/11 for the
leading "common" fields; type-specific tails (TRAFFIC vs THREAT vs SYSTEM vs
CONFIG) diverge after the action field.

These maps cover the fields we normalize for the most common log types. The FULL
positional field list is always preserved in raw["fields"], so nothing is lost
and any field can still be searched via the jsonb index or re-mapped later.
"""
from __future__ import annotations

import csv
import io
from typing import Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, parse_ts, to_int

KNOWN_TYPES = {"TRAFFIC", "THREAT", "URL", "WILDFIRE", "DATA", "SYSTEM",
               "CONFIG", "HIPMATCH", "GLOBALPROTECT", "AUTHENTICATION", "DECRYPTION"}

# Index -> normalized field, for the common leading fields (shared by flow logs).
_COMMON = {
    1: "receive_time", 3: "type", 4: "subtype", 6: "time_generated",
    7: "src", 8: "dst", 11: "rule", 12: "srcuser", 14: "app",
    16: "from_zone", 17: "to_zone", 24: "sport", 25: "dport",
    29: "protocol", 30: "action",
}
# Type-specific tail fields (best-effort; PAN-OS 10/11 common layout).
_TRAFFIC_TAIL = {31: "bytes", 32: "bytes_sent", 33: "bytes_received", 37: "category"}
_THREAT_TAIL = {31: "misc", 32: "threatid", 33: "category", 34: "severity", 35: "direction"}


def _get(fields: list[str], idx: int) -> Optional[str]:
    if 0 <= idx < len(fields):
        v = fields[idx].strip()
        return v or None
    return None


def _split(line: str) -> Optional[list[str]]:
    line = line.rstrip("\r\n")
    if not line.strip():
        return None
    try:
        return next(csv.reader(io.StringIO(line)))
    except (csv.Error, StopIteration):
        return line.split(",")


def _detect_type(fields: list[str]) -> Optional[str]:
    # Type is normally field 3; scan the first few fields to be resilient.
    for i in (3, 2, 4):
        v = _get(fields, i)
        if v and v.upper() in KNOWN_TYPES:
            return v.upper()
    return None


def parse(content: str) -> Iterator[NormalizedEvent]:
    for line in content.splitlines():
        fields = _split(line)
        if not fields or len(fields) < 5:
            continue
        ltype = _detect_type(fields)
        if ltype is None:
            continue  # not a recognizable PAN syslog line

        raw = {"fields": fields, "log_type": ltype}
        # pull common fields into a friendly dict for raw + normalization
        for idx, name in _COMMON.items():
            raw[name] = _get(fields, idx)

        ev = NormalizedEvent(
            event_time=parse_ts(first(raw.get("receive_time"), raw.get("time_generated"))),
            vendor="paloalto", product="ngfw",
            log_type=(raw.get("subtype") or ltype).lower(),
            action=raw.get("action"),
            src_ip=clean_ip(raw.get("src")),
            dst_ip=clean_ip(raw.get("dst")),
            src_port=to_int(raw.get("sport")),
            dst_port=to_int(raw.get("dport")),
            protocol=raw.get("protocol"),
            app=raw.get("app"),
            user_name=raw.get("srcuser"),
            host_name=_get(fields, 2),  # device serial — stable device identifier
            rule_name=raw.get("rule"),
            raw=raw,
        )

        if ltype == "TRAFFIC":
            for idx, name in _TRAFFIC_TAIL.items():
                raw[name] = _get(fields, idx)
            ev.bytes_total = to_int(raw.get("bytes"))
            ev.message = raw.get("category")
        elif ltype in ("THREAT", "URL", "WILDFIRE", "DATA"):
            for idx, name in _THREAT_TAIL.items():
                raw[name] = _get(fields, idx)
            ev.severity = raw.get("severity")
            ev.message = first(raw.get("threatid"), raw.get("misc"), raw.get("category"))
        elif ltype == "SYSTEM":
            # FUTURE_USE,RecvTime,Serial,Type,Subtype,FUTURE,GenTime,VSys,EventID,Object,FUTURE,FUTURE,Module,Severity,Description
            raw.update(eventid=_get(fields, 8), module=_get(fields, 12),
                       sys_severity=_get(fields, 13), description=_get(fields, 14))
            ev.log_type = "system"
            ev.severity = raw.get("sys_severity")
            ev.message = first(raw.get("description"), raw.get("eventid"))
        elif ltype == "CONFIG":
            # ...,GenTime,Host,VSys,Command,Admin,Client,Result,Path
            raw.update(cfg_host=_get(fields, 7), command=_get(fields, 9),
                       admin=_get(fields, 10), client=_get(fields, 11),
                       result=_get(fields, 12), path=_get(fields, 13))
            ev.log_type = "config"
            ev.action = raw.get("command")
            ev.user_name = raw.get("admin")
            ev.message = first(raw.get("path"), raw.get("command"))

        yield ev
