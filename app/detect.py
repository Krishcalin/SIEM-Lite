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

from .util import _exceeds_json_depth, _MAX_JSON_DEPTH

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
# Cisco ASA / Firepower message ID: %ASA-6-302013: ...
_CISCO_RE = re.compile(r"%(?:ASA|FTD|ASASM|FWSM|PIX)-\d-\d+", re.IGNORECASE)
# Cisco IOS/IOS-XE/NX-OS mnemonic: %SEC-6-IPACCESSLOGP: ... (alpha mnemonic; not ASA's numeric id).
_CISCO_IOS_RE = re.compile(r"%[A-Z][A-Z0-9_]*-\d-[A-Z_][A-Z0-9_]*:")
# Cisco Meraki: RFC 5424 syslog whose body starts with a Meraki event type.
_MERAKI_RE = re.compile(
    r"^<\d{1,3}>1\s+\S+\s+\S+\s+"
    r"(?:flows|urls|ids-alerts|security_event|ip_flow_start|ip_flow_end|firewall|"
    r"vpn_firewall|dhcp_lease|dhcp_no_offers|events|airmarshal_events)\b",
    re.MULTILINE)
# Zeek TSV metadata header.
_ZEEK_RE = re.compile(r"^#(?:separator|fields)\b", re.MULTILINE)
# Fortinet key=value syslog: needs devname= plus a Forti-specific key.
_FORTINET_RE = re.compile(r"\bdevname=", re.IGNORECASE)
_FORTINET_MARK = re.compile(r"\b(logid|devid|vd|eventtime)=", re.IGNORECASE)
# Generic syslog (catch-all, checked LAST): a <PRI> prefix or an RFC 3164 header.
_SYSLOG_RE = re.compile(r"^<\d{1,3}>", re.MULTILINE)
_RFC3164_HDR = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s", re.MULTILINE)


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

    # Cisco ASA / Firepower — distinctive %ASA-L-NNNNNN message id (numeric).
    if _CISCO_RE.search(sample):
        return "cisco_asa"

    # Cisco IOS / IOS-XE / NX-OS — %FACILITY-SEVERITY-MNEMONIC (alpha mnemonic).
    if _CISCO_IOS_RE.search(sample):
        return "cisco_ios"

    # Zeek TSV — #separator / #fields metadata header (check before CSV).
    if _ZEEK_RE.search(sample):
        return "zeek_tsv"

    # Palo Alto syslog — positional payload signature.
    if _PAN_SYSLOG_RE.search(sample):
        return "paloalto_syslog"

    # Fortinet FortiGate — key=value syslog.
    if _FORTINET_RE.search(sample) and _FORTINET_MARK.search(sample):
        return "fortinet_fortigate"

    # Cisco Meraki — RFC 5424 syslog with a Meraki event type (before generic syslog).
    if _MERAKI_RE.search(sample):
        return "meraki"

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

    # Generic syslog — catch-all, only after every specific signature missed.
    if _SYSLOG_RE.search(sample) or _RFC3164_HDR.search(sample):
        return "generic_syslog"

    return None  # unknown — the UI asks the user to pick a format explicitly


def _detect_json(text: str) -> Optional[str]:
    """Route a JSON/NDJSON document to the right parser by inspecting its keys."""
    rec = _first_json_record(text)
    if not isinstance(rec, dict):
        return "generic_json"  # looked like JSON but no object to inspect
    keys = {str(k).lower() for k in rec}

    # Suricata EVE — event_type plus network fields.
    if "event_type" in keys and ({"flow_id", "src_ip", "alert", "dest_ip"} & keys):
        return "suricata_eve"
    # Windows Security Event Log (JSON export).
    if "providername" in keys and "id" in keys and ({"leveldisplayname", "machinename"} & keys):
        return "windows_security"
    # AWS CloudTrail.
    if "eventsource" in keys and ({"eventname", "awsregion", "eventid"} & keys):
        return "aws_cloudtrail"
    # Microsoft 365 Unified Audit Log.
    if ("workload" in keys and "operation" in keys) or ("auditdata" in keys and "creationtime" in keys):
        return "m365_audit"
    # Okta System Log (eventType — distinct from Suricata's event_type).
    if "eventtype" in keys and ({"actor", "legacyeventtype", "outcome", "published"} & keys):
        return "okta_system_log"
    # Microsoft Entra ID sign-in logs.
    if ({"userprincipalname", "appdisplayname"} & keys) and \
            ({"createddatetime", "clientappused", "risklevelduringsignin"} & keys):
        return "entra_signin"
    # Zeek JSON — dotted connection keys.
    if ("id.orig_h" in keys) or ("id.resp_h" in keys) or \
            ({"uid", "ts", "id.orig_p"} <= keys):
        return "zeek_json"
    # GCP Cloud Audit Logs.
    if "protopayload" in keys:
        return "gcp_audit"
    # Azure Activity Log.
    if "operationname" in keys and \
            ({"resultsignature", "calleripaddress", "correlationid", "resourceid"} & keys):
        return "azure_activity"
    # GitHub audit log.
    if "action" in keys and "actor" in keys and \
            ({"@timestamp", "actor_id", "actor_ip", "org", "repo"} & keys):
        return "github_audit"
    # GitLab audit events.
    if "entity_type" in keys and "details" in keys:
        return "gitlab_audit"
    # CrowdStrike Falcon JSON (detection-summary or flat/FDR shapes).
    if ({"aid", "cid", "sensorid", "detectname"} & keys) or ({"metadata", "event"} <= keys):
        return "crowdstrike_json"
    # Unrecognized JSON — fall back to the generic JSON mapper (not CrowdStrike).
    return "generic_json"


def _first_json_record(text: str) -> Optional[dict]:
    t = text.strip()
    if _exceeds_json_depth(t, _MAX_JSON_DEPTH):   # drop a deeply-nested bomb pre-parse
        return None
    try:
        obj = json.loads(t)
    except (json.JSONDecodeError, RecursionError):
        obj = None
    if obj is not None:
        if isinstance(obj, list):
            return next((r for r in obj if isinstance(r, dict)), None)
        if isinstance(obj, dict):
            for key in ("resources", "events", "Records", "records", "value", "entries", "data"):
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
        except (json.JSONDecodeError, RecursionError):
            continue
        if isinstance(r, dict):
            return r
    return None
