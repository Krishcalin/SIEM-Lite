"""Best-effort detection of a file's vendor+format from its name and content.

Order matters: specific signatures (CEF, vendor JSON, PAN syslog, Fortinet KV)
are tested before broader ones so a stray field value can't trip another
vendor's detector. Anything unrecognized returns None and the UI asks the user
to pick a format explicitly.
"""
from __future__ import annotations

import csv
import io
import json
import re
from typing import Optional

# Header tokens that strongly identify a CSV's vendor.
_PAN_CSV_MARKERS = {"receive time", "source address", "threat/content type",
                    "destination address", "rule"}
_CS_CSV_MARKERS = {"detectname", "computername", "tactic", "sha256", "hostname",
                   "severityname", "patterndispositiondescription", "aid"}
_WIN_CSV_MARKERS = {"providername", "machinename", "leveldisplayname",
                    "timecreated", "task category", "event id"}

# PAN syslog payload signature: ",<date> <time>,<serial 6+ digits>,<TYPE>,".
_PAN_SYSLOG_RE = re.compile(
    r",\s*\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2},\d{6,},"
    r"(TRAFFIC|THREAT|SYSTEM|CONFIG|URL|WILDFIRE|DATA|HIPMATCH|GLOBALPROTECT)\b",
    re.IGNORECASE)
# CEF header (optionally behind a syslog header).
_CEF_RE = re.compile(r"CEF:\s*\d+\s*\|")
# Fortinet key=value syslog: needs devname= plus a Forti-specific key.
_FORTINET_RE = re.compile(r"\bdevname=", re.IGNORECASE)
_FORTINET_MARK = re.compile(r"\b(logid|devid|vd|eventtime)=", re.IGNORECASE)


def detect_format(filename: str, content: str) -> Optional[str]:
    name = (filename or "").lower()
    sample = content[:16384]
    stripped = sample.lstrip()

    # JSON family — disambiguate by content (Suricata / Windows / CrowdStrike).
    if name.endswith((".json", ".ndjson")) or stripped[:1] in ("{", "["):
        return _detect_json(stripped)

    # CEF — generic, but a strong, specific prefix; check before syslog/CSV.
    if _CEF_RE.search(sample):
        return "cef"

    # Palo Alto syslog — positional payload signature.
    if _PAN_SYSLOG_RE.search(sample):
        return "paloalto_syslog"

    # Fortinet FortiGate — key=value syslog.
    if _FORTINET_RE.search(sample) and _FORTINET_MARK.search(sample):
        return "fortinet_fortigate"

    # CSV by header.
    try:
        header = next(csv.reader(io.StringIO(sample)))
    except (csv.Error, StopIteration):
        header = []
    hset = {(h or "").strip().lower() for h in header}
    if hset & _PAN_CSV_MARKERS:
        return "paloalto_csv"
    if hset & _CS_CSV_MARKERS:
        return "crowdstrike_csv"
    if hset & _WIN_CSV_MARKERS:
        return "windows_security"

    return None  # unknown — the UI asks the user to pick a format explicitly


def _detect_json(text: str) -> Optional[str]:
    """Route a JSON/NDJSON document to the right parser by inspecting its keys."""
    rec = _first_json_record(text)
    if not isinstance(rec, dict):
        return "crowdstrike_json"  # looked like JSON but no object — legacy default
    keys = {str(k).lower() for k in rec}

    if "event_type" in keys and ({"flow_id", "src_ip", "alert", "dest_ip"} & keys):
        return "suricata_eve"
    if "providername" in keys and "id" in keys and ({"leveldisplayname", "machinename"} & keys):
        return "windows_security"
    if ({"aid", "cid", "sensorid", "detectname"} & keys) or ({"metadata", "event", "resources"} & keys):
        return "crowdstrike_json"
    return "crowdstrike_json"  # default JSON source in scope


def _first_json_record(text: str) -> Optional[dict]:
    t = text.strip()
    try:
        obj = json.loads(t)
    except json.JSONDecodeError:
        obj = None
    if obj is not None:
        if isinstance(obj, list):
            return next((r for r in obj if isinstance(r, dict)), None)
        if isinstance(obj, dict):
            for key in ("resources", "events"):
                if isinstance(obj.get(key), list):
                    return next((r for r in obj[key] if isinstance(r, dict)), None)
            return obj
        return None
    for line in t.splitlines():
        line = line.strip().rstrip(",")
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(r, dict):
            return r
    return None
