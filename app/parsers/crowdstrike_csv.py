"""CrowdStrike Falcon — CSV export parser (detections / incidents / events).

Falcon console CSV exports include a header row whose columns vary by export
type and tenant configuration, so each normalized field is resolved from a list
of candidate header names (case-insensitive).
"""
from __future__ import annotations

import csv
import io
from typing import Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, parse_ts, to_int


def _g(row: dict, *names: str) -> Optional[str]:
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
            continue

        detect_name = _g(row, "detectname", "detect name", "detectdescription", "name")
        is_detection = bool(detect_name or _g(row, "tactic", "technique", "severityname"))

        yield NormalizedEvent(
            event_time=parse_ts(first(
                _g(row, "timestamp", "detectdate", "detect time", "detecttime"),
                _g(row, "createdtimestamp", "processstarttime", "eventtime", "date", "time"),
            )),
            vendor="crowdstrike",
            product="falcon",
            log_type="detection" if is_detection else "event",
            severity=_g(row, "severityname", "severity", "maxseverity_displayname", "maxseverity"),
            action=first(_g(row, "pattern_disposition_description", "patterndispositiondescription"),
                         _g(row, "action", "status")),
            src_ip=clean_ip(_g(row, "localip", "local ip", "src_ip", "sourceip")),
            dst_ip=clean_ip(_g(row, "externalip", "external ip", "remoteip", "dst_ip", "destinationip")),
            user_name=_g(row, "username", "user name", "userid", "user"),
            host_name=first(_g(row, "hostname", "computername", "host", "endpoint", "device"),
                            _g(row, "aid", "sensorid")),
            rule_name=_g(row, "tactic", "technique", "rulename"),
            message=first(detect_name, _g(row, "commandline", "command line", "filename", "filepath"),
                          _g(row, "description")),
            raw={k: v for k, v in row.items() if k},
        )
