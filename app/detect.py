"""Best-effort detection of a file's vendor+format from its name and content."""
from __future__ import annotations

import csv
import io
import re
from typing import Optional

# Header tokens that strongly identify a CSV's vendor.
_PAN_CSV_MARKERS = {"receive time", "source address", "threat/content type",
                    "destination address", "rule"}
_CS_CSV_MARKERS = {"detectname", "computername", "tactic", "sha256", "hostname",
                   "severityname", "patterndispositiondescription", "aid"}
# PAN syslog payload signature: ",<date> <time>,<serial 6+ digits>,<TYPE>,".
# Strict enough that a stray "SYSTEM" username in another vendor's CSV won't match.
_PAN_SYSLOG_RE = re.compile(
    r",\s*\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2},\d{6,},"
    r"(TRAFFIC|THREAT|SYSTEM|CONFIG|URL|WILDFIRE|DATA|HIPMATCH|GLOBALPROTECT)\b",
    re.IGNORECASE)


def detect_format(filename: str, content: str) -> Optional[str]:
    name = (filename or "").lower()
    sample = content[:16384]
    stripped = sample.lstrip()

    # JSON (CrowdStrike is the only JSON source in scope)
    if name.endswith((".json", ".ndjson")) or stripped[:1] in ("{", "["):
        return "crowdstrike_json"

    # PAN syslog: positional payload matching the date+serial+type signature
    if _PAN_SYSLOG_RE.search(sample):
        return "paloalto_syslog"

    # CSV by header
    try:
        header = next(csv.reader(io.StringIO(sample)))
    except (csv.Error, StopIteration):
        header = []
    hset = {(h or "").strip().lower() for h in header}
    if hset & _PAN_CSV_MARKERS:
        return "paloalto_csv"
    if hset & _CS_CSV_MARKERS:
        return "crowdstrike_csv"

    return None  # unknown — the UI asks the user to pick a format explicitly
