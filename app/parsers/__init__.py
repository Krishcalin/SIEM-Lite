"""Log parsers. Each module exposes `parse(content: str) -> Iterator[NormalizedEvent]`."""
from __future__ import annotations

from . import (aws_cloudtrail, cef, cisco_asa, crowdstrike_csv, crowdstrike_json,
               entra_signin, fortinet_fortigate, generic_syslog, m365_audit,
               okta_system_log, paloalto_csv, paloalto_syslog, suricata_eve,
               windows_security, zeek_tsv)

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
    "cisco_asa": cisco_asa,
    "zeek_tsv": zeek_tsv,
    "generic_syslog": generic_syslog,
    "aws_cloudtrail": aws_cloudtrail,
    "m365_audit": m365_audit,
    "okta_system_log": okta_system_log,
    "entra_signin": entra_signin,
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
    "cisco_asa": "Cisco ASA / Firepower (FTD) — syslog",
    "zeek_tsv": "Zeek (Bro) — TSV (conn / dns / http …)",
    "generic_syslog": "Generic syslog — RFC 3164 / 5424",
    "aws_cloudtrail": "AWS CloudTrail — JSON",
    "m365_audit": "Microsoft 365 — Unified Audit Log",
    "okta_system_log": "Okta — System Log",
    "entra_signin": "Microsoft Entra ID — sign-in logs",
}
