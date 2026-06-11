"""CrowdStrike Falcon — JSON parser.

Handles the shapes you get from manual exports and the streaming/FDR feeds:
  * a top-level JSON array of objects,
  * a single object,
  * an API response wrapper: {"resources": [...]},
  * NDJSON (one JSON object per line — common for event streams / Falcon Data Replicator).

Detection-stream and FDR records nest the useful fields under "event" and
"metadata"; we flatten those so a single field lookup works across shapes.
"""
from __future__ import annotations

import json
from typing import Any, Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, parse_ts, to_int


def _iter_records(content: str) -> Iterator[dict]:
    text = content.strip()
    if not text:
        return
    # Try a single well-formed JSON document first.
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        obj = None
    if obj is not None:
        if isinstance(obj, list):
            yield from (r for r in obj if isinstance(r, dict))
        elif isinstance(obj, dict):
            if isinstance(obj.get("resources"), list):
                yield from (r for r in obj["resources"] if isinstance(r, dict))
            elif isinstance(obj.get("events"), list):
                yield from (r for r in obj["events"] if isinstance(r, dict))
            else:
                yield obj
        return
    # Fall back to NDJSON.
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict):
            yield rec


def _flatten(rec: dict) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in ("metadata", "event"):
        sub = rec.get(key)
        if isinstance(sub, dict):
            for k, v in sub.items():
                out.setdefault(k, v)
    for k, v in rec.items():
        if k not in ("metadata", "event"):
            out.setdefault(k, v)
    return out


def _g(f: dict, *names: str) -> Optional[Any]:
    low = {str(k).lower(): v for k, v in f.items()}
    for n in names:
        v = low.get(n.lower())
        if v not in (None, ""):
            return v
    return None


def parse(content: str) -> Iterator[NormalizedEvent]:
    for rec in _iter_records(content):
        f = _flatten(rec)

        evt_type = _g(f, "eventType", "event_simpleName", "metadata.eventType")
        detect_name = _g(f, "DetectName", "detect_name", "name")
        is_detection = bool(detect_name) or (evt_type and "detection" in str(evt_type).lower())

        sev = _g(f, "SeverityName", "severity_name", "Severity", "severity", "max_severity_displayname")

        yield NormalizedEvent(
            event_time=parse_ts(first(
                _g(f, "timestamp", "eventCreationTime", "ProcessStartTime", "ContextTimeStamp"),
                _g(f, "DetectTime", "@timestamp", "createdTimestamp", "ProcessEndTime"),
            )),
            vendor="crowdstrike",
            product="falcon",
            log_type="detection" if is_detection else (str(evt_type).lower() if evt_type else "event"),
            severity=str(sev) if sev is not None else None,
            action=first(_g(f, "PatternDispositionDescription", "pattern_disposition_description"),
                         _g(f, "action", "Status")),
            src_ip=clean_ip(_g(f, "LocalIP", "local_ip", "src_ip")),
            dst_ip=clean_ip(_g(f, "ExternalIP", "external_ip", "RemoteAddress", "aip")),
            src_port=to_int(_g(f, "LocalPort", "local_port")),
            dst_port=to_int(_g(f, "RemotePort", "remote_port")),
            protocol=_g(f, "Protocol", "ConnectionProtocol"),
            user_name=_g(f, "UserName", "user_name", "UserId"),
            host_name=first(_g(f, "ComputerName", "Hostname", "hostname", "host"),
                            _g(f, "aid", "SensorId", "device_id")),
            rule_name=first(_g(f, "Tactic", "tactic"), _g(f, "Technique", "technique")),
            message=first(detect_name,
                          _g(f, "CommandLine", "command_line", "FileName", "FilePath", "ImageFileName"),
                          _g(f, "Description", "description"),
                          str(evt_type) if evt_type else None),
            raw=rec,
        )
