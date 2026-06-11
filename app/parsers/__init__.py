"""Log parsers. Each module exposes `parse(content: str) -> Iterator[NormalizedEvent]`."""
from __future__ import annotations

from . import crowdstrike_csv, crowdstrike_json, paloalto_csv, paloalto_syslog

# Format key -> parser module. Keys are also the values of the UI "format" dropdown.
PARSERS = {
    "paloalto_csv": paloalto_csv,
    "paloalto_syslog": paloalto_syslog,
    "crowdstrike_csv": crowdstrike_csv,
    "crowdstrike_json": crowdstrike_json,
}

FORMAT_LABELS = {
    "paloalto_csv": "Palo Alto NGFW — CSV export",
    "paloalto_syslog": "Palo Alto NGFW — syslog",
    "crowdstrike_csv": "CrowdStrike Falcon — CSV export",
    "crowdstrike_json": "CrowdStrike Falcon — JSON",
}
