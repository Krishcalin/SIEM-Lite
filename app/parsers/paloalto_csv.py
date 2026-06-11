"""Palo Alto NGFW — CSV export parser (Monitor > Logs > Export to CSV).

The GUI export includes a header row of human-readable column names, so we map
by header rather than position. Column names differ slightly across PAN-OS
versions and log types (Traffic / Threat / URL / WildFire / Data / System /
Config), so each normalized field is resolved from a list of candidate headers.
"""
from __future__ import annotations

import csv
import io
from typing import Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, parse_ts, to_int


def _g(row: dict, *names: str) -> Optional[str]:
    """Case-insensitive header lookup over candidate column names."""
    low = {(k or "").strip().lower(): v for k, v in row.items()}
    for n in names:
        v = low.get(n)
        if v not in (None, ""):
            return v
    return None


def parse(content: str) -> Iterator[NormalizedEvent]:
    reader = csv.DictReader(io.StringIO(content))
    for row in reader:
        if not any((v or "").strip() for v in row.values()):
            continue  # blank line

        log_type = _g(row, "type") or "traffic"
        subtype = _g(row, "threat/content type", "subtype", "content type")

        yield NormalizedEvent(
            event_time=parse_ts(
                first(_g(row, "receive time", "time received", "receive_time"),
                      _g(row, "generate time", "time generated", "generated time"))
            ),
            vendor="paloalto",
            product="ngfw",
            log_type=(subtype or log_type or "").strip().lower() or "traffic",
            severity=_g(row, "severity"),
            action=_g(row, "action"),
            src_ip=clean_ip(_g(row, "source address", "src", "source ip", "source")),
            dst_ip=clean_ip(_g(row, "destination address", "dst", "destination ip", "destination")),
            src_port=to_int(_g(row, "source port", "src port", "sport")),
            dst_port=to_int(_g(row, "destination port", "dst port", "dport")),
            protocol=_g(row, "ip protocol", "protocol", "proto"),
            app=_g(row, "application", "app"),
            user_name=first(_g(row, "source user", "src user"), _g(row, "user")),
            host_name=_g(row, "device name", "device_name", "serial number", "host"),
            rule_name=_g(row, "rule", "rule name", "rule_name"),
            bytes_total=to_int(_g(row, "bytes", "bytes total")),
            message=first(
                _g(row, "threat/content name", "threat name", "threatid"),
                _g(row, "url", "url/filename", "misc", "filename"),
                _g(row, "category"),
                subtype,
            ),
            raw={k: v for k, v in row.items() if k},
        )
