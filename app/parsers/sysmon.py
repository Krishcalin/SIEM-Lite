"""Microsoft Sysmon (System Monitor) parser — the key Windows endpoint telemetry.

Sysmon logs process, network, file, registry, image-load, WMI and DNS activity to
the ``Microsoft-Windows-Sysmon/Operational`` channel — the data most community
detections assume. Accepts the two shapes analysts export without extra tooling:

  * **JSON** — ``Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' |
    ConvertTo-Json`` (array / single object / NDJSON). The named EventData
    (``Image`` / ``CommandLine`` / ``DestinationIp`` …) lives in the rendered
    ``Message`` there, so we parse its ``Key: Value`` lines. A shipper that emits a
    named ``EventData`` object (Winlogbeat / NXLog) is also honored.
  * **CSV** — ``Get-WinEvent … | Export-Csv``.

The EventID sets the event kind; process kinds use the same labels as the Windows
Security parser (EID 1 -> ``process-create`` like 4688) so cross-vendor rules match
both. The parsed fields are surfaced onto ``raw`` (so ``Image`` / ``CommandLine`` /
``TargetObject`` are searchable and rule-matchable) and ``CommandLine`` flows into
``message`` so command-line detections fire on endpoint telemetry.
"""
from __future__ import annotations

import csv
import io
import re
from typing import Any, Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, json_or_none, parse_ts, to_int

# Sysmon EventID -> event-kind label. Process kinds mirror windows_security
# (4688 process-create / 4689 process-exit) so a rule on action matches both.
_KIND = {
    1: "process-create", 2: "file-time-change", 3: "network-connect",
    5: "process-exit", 6: "driver-load", 7: "image-load",
    8: "create-remote-thread", 9: "raw-access-read", 10: "process-access",
    11: "file-create", 12: "registry-add-delete", 13: "registry-set",
    14: "registry-rename", 15: "file-stream-hash", 17: "pipe-create",
    18: "pipe-connect", 19: "wmi-filter", 20: "wmi-consumer", 21: "wmi-binding",
    22: "dns-query", 23: "file-delete", 24: "clipboard", 25: "process-tamper",
    26: "file-delete-detected", 27: "file-block-executable",
    28: "file-block-shredding", 29: "file-executable-detected",
}
_KV_LINE = re.compile(r"^\s*([A-Za-z0-9_]+):\s?(.*)$")
# Fields lifted onto raw's top level so Sysmon/Sigma field names resolve directly.
_LIFT = ("Image", "CommandLine", "ParentImage", "ParentCommandLine", "OriginalFileName",
         "TargetFilename", "TargetObject", "Details", "QueryName", "QueryResults",
         "User", "Hashes", "ProcessId", "ParentProcessId", "IntegrityLevel",
         "CurrentDirectory", "PipeName", "DestinationHostname")


def _g(rec: dict, *names: str) -> Optional[Any]:
    low = {str(k).strip().lower(): v for k, v in rec.items()}
    for n in names:
        v = low.get(n.lower())
        if v not in (None, ""):
            return v
    return None


def _event_fields(rec: dict, msg: str) -> dict:
    """Named Sysmon fields, from the rendered Message lines and/or an EventData obj."""
    out: dict[str, Any] = {}
    for line in re.split(r"[\r\n]+", msg):
        m = _KV_LINE.match(line)
        if m and m.group(2) != "":                 # 'Key: value' (skip the header line)
            out.setdefault(m.group(1), m.group(2).strip())
    ed = _g(rec, "event_data", "eventdata", "data")
    if isinstance(ed, dict):
        for k, v in ed.items():
            out[str(k)] = v
    return out


def _iter_records(content: str) -> Iterator[dict]:
    text = content.strip()
    if text[:1] in ("{", "["):
        obj = json_or_none(text)
        if obj is not None:
            if isinstance(obj, list):
                yield from (r for r in obj if isinstance(r, dict))
            elif isinstance(obj, dict):
                yield obj
            return
        for line in text.splitlines():          # NDJSON fallback
            line = line.strip().rstrip(",")
            if not line:
                continue
            r = json_or_none(line)
            if isinstance(r, dict):
                yield r
        return
    for row in csv.DictReader(io.StringIO(content)):
        if any((v or "").strip() for v in row.values()):
            yield {k: v for k, v in row.items() if k}


def parse(content: str) -> Iterator[NormalizedEvent]:
    for rec in _iter_records(content):
        msg = str(_g(rec, "message", "description") or "")
        eid = to_int(_g(rec, "id", "eventid", "event id"))
        fields = _event_fields(rec, msg)
        low = {str(k).lower(): v for k, v in fields.items()}

        def f(*names: str) -> Optional[Any]:
            for n in names:
                v = low.get(n.lower())
                if v not in (None, ""):
                    return v
            return None

        kind = _KIND.get(eid or -1, "sysmon")
        if eid == 1:
            summary = f("CommandLine")
        elif eid == 3:
            summary = f"{f('Image') or '?'} -> {f('DestinationIp') or '?'}:{f('DestinationPort') or '?'}"
        elif eid == 22:
            summary = f"DNS query {f('QueryName') or '?'}"
        elif eid in (11, 23, 26):
            summary = f("TargetFilename")
        elif eid in (12, 13, 14):
            summary = f("TargetObject")
        else:
            summary = first(f("Image"),
                            next((ln.strip() for ln in re.split(r"[\r\n]", msg) if ln.strip()), None))

        proto = f("Protocol")
        rn = f("RuleName")
        rn = rn if (rn and rn != "-") else None

        raw = {**rec}
        for k in _LIFT:                             # surface named fields for search / rules
            v = f(k)
            if v is not None:
                raw.setdefault(k, v)

        yield NormalizedEvent(
            event_time=parse_ts(first(f("UtcTime"),
                                      _g(rec, "timecreated", "time created", "date"))),
            vendor="microsoft",
            product="sysmon",
            log_type=kind,
            action=kind,
            severity=(str(_g(rec, "leveldisplayname", "level") or "").lower() or None),
            src_ip=clean_ip(f("SourceIp")),
            dst_ip=clean_ip(f("DestinationIp")),
            src_port=to_int(f("SourcePort")),
            dst_port=to_int(f("DestinationPort")),
            protocol=(proto.lower() if proto else None),
            user_name=f("User"),
            host_name=_g(rec, "machinename", "computername", "computer") or f("Computer"),
            rule_name=first(rn, f"Sysmon EID {eid}" if eid else "sysmon"),
            message=first(summary, _g(rec, "providername")),
            raw=raw,
        )
