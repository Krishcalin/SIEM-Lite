"""Log parsers. Each module exposes `parse(content: str) -> Iterator[NormalizedEvent]`."""
from __future__ import annotations

from . import (cef, crowdstrike_csv, crowdstrike_json, fortinet_fortigate,
               paloalto_csv, paloalto_syslog, suricata_eve, windows_security)

# Format key -> parser module. Keys are also the values of the UI "format" dropdown.
PARSERS = {
    "paloalto_csv": paloalto_csv,
    "paloalto_syslog": paloalto_syslog,
    "crowdstrike_csv": crowdstrike_csv,
    "crowdstrike_json": crowdstrike_json,
    "fortinet_fortigate": fortinet_fortigate,
    "windows_security": windows_security,
    "suricata_eve": suricata_eve,
    "cef": cef,
}

FORMAT_LABELS = {
    "paloalto_csv": "Palo Alto NGFW — CSV export",
    "paloalto_syslog": "Palo Alto NGFW — syslog",
    "crowdstrike_csv": "CrowdStrike Falcon — CSV export",
    "crowdstrike_json": "CrowdStrike Falcon — JSON",
    "fortinet_fortigate": "Fortinet FortiGate — syslog (key=value)",
    "windows_security": "Windows Security Event Log — CSV / JSON",
    "suricata_eve": "Suricata — EVE JSON",
    "cef": "CEF — Common Event Format (generic)",
}
