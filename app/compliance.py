"""Compliance mapping (Phase 5.5).

Maps the MITRE ATT&CK techniques already carried on detection rules and alerts to
controls across common frameworks, so the `/compliance` page can show, per
framework: which controls have a detection rule covering them and how much recent
alert activity each control has seen.

This is a curated, illustrative mapping (not an authoritative crosswalk) — extend
`MAP` with more techniques/controls as rules are added. `build_report` is pure and
unit-tested.
"""
from __future__ import annotations

# Render frameworks in this order on the page.
FRAMEWORKS = ["NIST 800-53", "CIS v8", "PCI DSS v4", "HIPAA"]

# technique -> framework -> list of (control_id, control_name)
MAP: dict[str, dict[str, list[tuple[str, str]]]] = {
    "T1110": {  # Brute Force
        "NIST 800-53": [("AC-7", "Unsuccessful Logon Attempts"), ("IA-5", "Authenticator Management")],
        "CIS v8": [("6.2", "Establish an Access Revoking Process"), ("4.10", "Enforce Automatic Lockout")],
        "PCI DSS v4": [("8.3.4", "Limit Repeated Access Attempts"), ("8.6.1", "Manage Account Lockout")],
        "HIPAA": [("164.308(a)(5)(ii)(C)", "Log-in Monitoring")],
    },
    "T1021.001": {  # Remote Services: RDP
        "NIST 800-53": [("AC-17", "Remote Access"), ("SC-7", "Boundary Protection")],
        "CIS v8": [("12.7", "Manage Remote Devices"), ("4.6", "Securely Manage Enterprise Assets")],
        "PCI DSS v4": [("1.3.1", "Restrict Inbound Traffic"), ("8.4.2", "MFA for Access")],
        "HIPAA": [("164.312(a)(1)", "Access Control")],
    },
    "T1105": {  # Ingress Tool Transfer
        "NIST 800-53": [("SC-7", "Boundary Protection"), ("SI-3", "Malicious Code Protection")],
        "CIS v8": [("10.1", "Deploy Anti-Malware"), ("13.3", "Network Intrusion Detection")],
        "PCI DSS v4": [("5.2.1", "Anti-Malware Deployed"), ("1.4.1", "Control Network Connections")],
        "HIPAA": [("164.308(a)(5)(ii)(B)", "Protection from Malicious Software")],
    },
    "T1070.001": {  # Clear Windows Event Logs
        "NIST 800-53": [("AU-9", "Protection of Audit Information"), ("AU-6", "Audit Record Review")],
        "CIS v8": [("8.2", "Collect Audit Logs"), ("8.5", "Collect Detailed Audit Logs")],
        "PCI DSS v4": [("10.3.1", "Protect Audit Logs"), ("10.5.1", "Retain Audit Logs")],
        "HIPAA": [("164.312(b)", "Audit Controls")],
    },
    "T1562.001": {  # Disable Security Tools
        "NIST 800-53": [("SI-3", "Malicious Code Protection"), ("CM-7", "Least Functionality")],
        "CIS v8": [("10.1", "Deploy Anti-Malware"), ("8.2", "Collect Audit Logs")],
        "PCI DSS v4": [("5.2.2", "Anti-Malware Kept Active"), ("10.7.1", "Detect Logging Failures")],
        "HIPAA": [("164.308(a)(1)(ii)(D)", "Information System Activity Review")],
    },
    "T1046": {  # Network Service Discovery
        "NIST 800-53": [("SC-7", "Boundary Protection"), ("SI-4", "System Monitoring")],
        "CIS v8": [("13.3", "Network Intrusion Detection"), ("13.6", "Network Traffic Flow Logging")],
        "PCI DSS v4": [("11.4.1", "Intrusion Detection"), ("1.4.1", "Control Network Connections")],
        "HIPAA": [("164.312(b)", "Audit Controls")],
    },
    "T1003": {  # OS Credential Dumping
        "NIST 800-53": [("IA-5", "Authenticator Management"), ("AC-6", "Least Privilege")],
        "CIS v8": [("5.4", "Restrict Administrator Privileges"), ("6.8", "Define Role-Based Access")],
        "PCI DSS v4": [("8.3.1", "Strong Authentication"), ("7.2.1", "Least Privilege Access")],
        "HIPAA": [("164.312(d)", "Person or Entity Authentication")],
    },
    "T1059": {  # Command and Scripting Interpreter
        "NIST 800-53": [("CM-7", "Least Functionality"), ("SI-4", "System Monitoring")],
        "CIS v8": [("2.7", "Allowlist Authorized Scripts"), ("8.2", "Collect Audit Logs")],
        "PCI DSS v4": [("2.2.4", "Disable Unnecessary Services"), ("11.5.1", "Detect Changes")],
        "HIPAA": [("164.308(a)(1)(ii)(D)", "Information System Activity Review")],
    },
    "T1078": {  # Valid Accounts
        "NIST 800-53": [("AC-2", "Account Management"), ("IA-2", "Identification and Authentication")],
        "CIS v8": [("5.1", "Establish an Inventory of Accounts"), ("6.7", "Centralize Access Control")],
        "PCI DSS v4": [("8.2.1", "Unique User IDs"), ("8.4.1", "MFA for Admin Access")],
        "HIPAA": [("164.312(d)", "Person or Entity Authentication")],
    },
    "T1486": {  # Data Encrypted for Impact (ransomware)
        "NIST 800-53": [("CP-9", "System Backup"), ("SI-3", "Malicious Code Protection")],
        "CIS v8": [("11.2", "Perform Automated Backups"), ("10.1", "Deploy Anti-Malware")],
        "PCI DSS v4": [("12.10.1", "Incident Response Plan"), ("5.2.1", "Anti-Malware Deployed")],
        "HIPAA": [("164.308(a)(7)(ii)(A)", "Data Backup Plan")],
    },
}


def _index() -> dict[str, dict[str, dict]]:
    """framework -> control_id -> {name, techniques(set)}."""
    out: dict[str, dict[str, dict]] = {}
    for tech, frameworks in MAP.items():
        for fw, controls in frameworks.items():
            fw_map = out.setdefault(fw, {})
            for cid, cname in controls:
                entry = fw_map.setdefault(cid, {"name": cname, "techniques": set()})
                entry["techniques"].add(tech)
    return out


_FW_CONTROLS = _index()


def controls_for_technique(technique: str) -> dict[str, list[tuple[str, str]]]:
    return MAP.get(technique.upper(), {})


def build_report(enabled_techniques: set[str], alert_counts: dict[str, int]) -> dict:
    """Per-framework coverage: each control flagged covered if an enabled rule maps
    to one of its techniques, plus the recent alert count attributable to it."""
    report: dict[str, dict] = {}
    for fw in FRAMEWORKS:
        controls = _FW_CONTROLS.get(fw, {})
        rows = []
        for cid in sorted(controls):
            techs = controls[cid]["techniques"]
            rows.append({
                "id": cid, "name": controls[cid]["name"],
                "techniques": sorted(techs),
                "covered": bool(techs & enabled_techniques),
                "alerts": sum(alert_counts.get(t, 0) for t in techs),
            })
        report[fw] = {"controls": rows,
                      "covered": sum(1 for r in rows if r["covered"]),
                      "total": len(rows)}
    return report
