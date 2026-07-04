# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
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

# Render frameworks in this order on the page. ISO 27001 (2022 Annex A) and SOC 2
# (Trust Services Criteria) are general-purpose and cover the enterprise techniques.
# The last two are OT/ICS-specific (IEC 62443-3-3 System Requirements; NERC CIP for
# the bulk electric system) and are populated by the ATT&CK-for-ICS techniques on
# the OT rule pack.
FRAMEWORKS = ["NIST 800-53", "CIS v8", "ISO 27001", "SOC 2", "PCI DSS v4", "HIPAA",
              "IEC 62443-3-3", "NERC CIP"]

# technique -> framework -> list of (control_id, control_name)
MAP: dict[str, dict[str, list[tuple[str, str]]]] = {
    "T1110": {  # Brute Force
        "NIST 800-53": [("AC-7", "Unsuccessful Logon Attempts"), ("IA-5", "Authenticator Management")],
        "CIS v8": [("6.2", "Establish an Access Revoking Process"), ("4.10", "Enforce Automatic Lockout")],
        "PCI DSS v4": [("8.3.4", "Limit Repeated Access Attempts"), ("8.6.1", "Manage Account Lockout")],
        "HIPAA": [("164.308(a)(5)(ii)(C)", "Log-in Monitoring")],
        "ISO 27001": [("A.8.5", "Secure Authentication"), ("A.5.15", "Access Control")],
        "SOC 2": [("CC6.1", "Logical Access Security"), ("CC7.2", "Security Event Monitoring")],
    },
    "T1021.001": {  # Remote Services: RDP
        "NIST 800-53": [("AC-17", "Remote Access"), ("SC-7", "Boundary Protection")],
        "CIS v8": [("12.7", "Manage Remote Devices"), ("4.6", "Securely Manage Enterprise Assets")],
        "PCI DSS v4": [("1.3.1", "Restrict Inbound Traffic"), ("8.4.2", "MFA for Access")],
        "HIPAA": [("164.312(a)(1)", "Access Control")],
        "ISO 27001": [("A.8.20", "Networks Security"), ("A.5.15", "Access Control")],
        "SOC 2": [("CC6.1", "Logical Access Security"), ("CC6.6", "Boundary Protection")],
    },
    "T1105": {  # Ingress Tool Transfer
        "NIST 800-53": [("SC-7", "Boundary Protection"), ("SI-3", "Malicious Code Protection")],
        "CIS v8": [("10.1", "Deploy Anti-Malware"), ("13.3", "Network Intrusion Detection")],
        "PCI DSS v4": [("5.2.1", "Anti-Malware Deployed"), ("1.4.1", "Control Network Connections")],
        "HIPAA": [("164.308(a)(5)(ii)(B)", "Protection from Malicious Software")],
        "ISO 27001": [("A.8.7", "Protection Against Malware"), ("A.8.23", "Web Filtering")],
        "SOC 2": [("CC6.8", "Malicious Software Prevention"), ("CC6.6", "Boundary Protection")],
    },
    "T1070.001": {  # Clear Windows Event Logs
        "NIST 800-53": [("AU-9", "Protection of Audit Information"), ("AU-6", "Audit Record Review")],
        "CIS v8": [("8.2", "Collect Audit Logs"), ("8.5", "Collect Detailed Audit Logs")],
        "PCI DSS v4": [("10.3.1", "Protect Audit Logs"), ("10.5.1", "Retain Audit Logs")],
        "HIPAA": [("164.312(b)", "Audit Controls")],
        "ISO 27001": [("A.8.15", "Logging"), ("A.8.16", "Monitoring Activities")],
        "SOC 2": [("CC7.2", "Security Event Monitoring"), ("CC7.3", "Security Event Evaluation")],
    },
    "T1562.001": {  # Disable Security Tools
        "NIST 800-53": [("SI-3", "Malicious Code Protection"), ("CM-7", "Least Functionality")],
        "CIS v8": [("10.1", "Deploy Anti-Malware"), ("8.2", "Collect Audit Logs")],
        "PCI DSS v4": [("5.2.2", "Anti-Malware Kept Active"), ("10.7.1", "Detect Logging Failures")],
        "HIPAA": [("164.308(a)(1)(ii)(D)", "Information System Activity Review")],
        "ISO 27001": [("A.8.7", "Protection Against Malware"), ("A.8.16", "Monitoring Activities")],
        "SOC 2": [("CC6.8", "Malicious Software Prevention"), ("CC7.2", "Security Event Monitoring")],
    },
    "T1046": {  # Network Service Discovery
        "NIST 800-53": [("SC-7", "Boundary Protection"), ("SI-4", "System Monitoring")],
        "CIS v8": [("13.3", "Network Intrusion Detection"), ("13.6", "Network Traffic Flow Logging")],
        "PCI DSS v4": [("11.4.1", "Intrusion Detection"), ("1.4.1", "Control Network Connections")],
        "HIPAA": [("164.312(b)", "Audit Controls")],
        "ISO 27001": [("A.8.20", "Networks Security"), ("A.8.16", "Monitoring Activities")],
        "SOC 2": [("CC6.6", "Boundary Protection"), ("CC7.2", "Security Event Monitoring")],
    },
    "T1003": {  # OS Credential Dumping
        "NIST 800-53": [("IA-5", "Authenticator Management"), ("AC-6", "Least Privilege")],
        "CIS v8": [("5.4", "Restrict Administrator Privileges"), ("6.8", "Define Role-Based Access")],
        "PCI DSS v4": [("8.3.1", "Strong Authentication"), ("7.2.1", "Least Privilege Access")],
        "HIPAA": [("164.312(d)", "Person or Entity Authentication")],
        "ISO 27001": [("A.8.2", "Privileged Access Rights"), ("A.5.17", "Authentication Information")],
        "SOC 2": [("CC6.1", "Logical Access Security"), ("CC6.3", "Role-Based Access")],
    },
    "T1059": {  # Command and Scripting Interpreter
        "NIST 800-53": [("CM-7", "Least Functionality"), ("SI-4", "System Monitoring")],
        "CIS v8": [("2.7", "Allowlist Authorized Scripts"), ("8.2", "Collect Audit Logs")],
        "PCI DSS v4": [("2.2.4", "Disable Unnecessary Services"), ("11.5.1", "Detect Changes")],
        "HIPAA": [("164.308(a)(1)(ii)(D)", "Information System Activity Review")],
        "ISO 27001": [("A.8.19", "Installation of Software on Operational Systems"), ("A.8.16", "Monitoring Activities")],
        "SOC 2": [("CC7.1", "Configuration and Vulnerability Detection"), ("CC7.2", "Security Event Monitoring")],
    },
    "T1078": {  # Valid Accounts
        "NIST 800-53": [("AC-2", "Account Management"), ("IA-2", "Identification and Authentication")],
        "CIS v8": [("5.1", "Establish an Inventory of Accounts"), ("6.7", "Centralize Access Control")],
        "PCI DSS v4": [("8.2.1", "Unique User IDs"), ("8.4.1", "MFA for Admin Access")],
        "HIPAA": [("164.312(d)", "Person or Entity Authentication")],
        "ISO 27001": [("A.5.16", "Identity Management"), ("A.8.2", "Privileged Access Rights")],
        "SOC 2": [("CC6.2", "User Registration and Authorization"), ("CC6.3", "Role-Based Access")],
    },
    "T1486": {  # Data Encrypted for Impact (ransomware)
        "NIST 800-53": [("CP-9", "System Backup"), ("SI-3", "Malicious Code Protection")],
        "CIS v8": [("11.2", "Perform Automated Backups"), ("10.1", "Deploy Anti-Malware")],
        "PCI DSS v4": [("12.10.1", "Incident Response Plan"), ("5.2.1", "Anti-Malware Deployed")],
        "HIPAA": [("164.308(a)(7)(ii)(A)", "Data Backup Plan")],
        "ISO 27001": [("A.8.13", "Information Backup"), ("A.8.7", "Protection Against Malware")],
        "SOC 2": [("A1.2", "Availability - Backup and Recovery"), ("CC7.4", "Security Incident Response")],
    },
    # ── ATT&CK for ICS (T0NNN) — OT rule pack -> IEC 62443-3-3 / NERC CIP ──────
    "T0855": {  # Unauthorized Command Message
        "NIST 800-53": [("AC-3", "Access Enforcement"), ("SC-7", "Boundary Protection")],
        "IEC 62443-3-3": [("SR 2.1", "Authorization Enforcement"), ("SR 3.1", "Communication Integrity")],
        "NERC CIP": [("CIP-005", "Electronic Security Perimeter(s)"), ("CIP-007", "System Security Management")],
    },
    "T0836": {  # Modify Parameter
        "NIST 800-53": [("CM-5", "Access Restrictions for Change"), ("SI-10", "Information Input Validation")],
        "IEC 62443-3-3": [("SR 2.1", "Authorization Enforcement"), ("SR 3.1", "Communication Integrity")],
        "NERC CIP": [("CIP-010", "Configuration Change Management")],
    },
    "T0843": {  # Program Download
        "NIST 800-53": [("CM-5", "Access Restrictions for Change"), ("CM-7", "Least Functionality")],
        "IEC 62443-3-3": [("SR 2.1", "Authorization Enforcement"), ("SR 3.4", "Software and Information Integrity")],
        "NERC CIP": [("CIP-010", "Configuration Change Management")],
    },
    "T0889": {  # Modify Program
        "NIST 800-53": [("CM-5", "Access Restrictions for Change"), ("SI-7", "Software, Firmware, and Information Integrity")],
        "IEC 62443-3-3": [("SR 3.4", "Software and Information Integrity"), ("SR 2.1", "Authorization Enforcement")],
        "NERC CIP": [("CIP-010", "Configuration Change Management")],
    },
    "T0858": {  # Change Operating Mode
        "NIST 800-53": [("AC-3", "Access Enforcement"), ("CM-7", "Least Functionality")],
        "IEC 62443-3-3": [("SR 2.1", "Authorization Enforcement"), ("SR 1.1", "Human User Identification and Authentication")],
        "NERC CIP": [("CIP-007", "System Security Management")],
    },
    "T0813": {  # Denial of Control
        "NIST 800-53": [("SC-5", "Denial-of-Service Protection")],
        "IEC 62443-3-3": [("SR 7.1", "Denial of Service Protection"), ("SR 7.2", "Resource Management")],
        "NERC CIP": [("CIP-007", "System Security Management")],
    },
    "T0816": {  # Device Restart/Shutdown
        "NIST 800-53": [("SC-5", "Denial-of-Service Protection"), ("CM-7", "Least Functionality")],
        "IEC 62443-3-3": [("SR 7.1", "Denial of Service Protection"), ("SR 2.1", "Authorization Enforcement")],
        "NERC CIP": [("CIP-007", "System Security Management")],
    },
    "T0814": {  # Denial of Service
        "NIST 800-53": [("SC-5", "Denial-of-Service Protection")],
        "IEC 62443-3-3": [("SR 7.1", "Denial of Service Protection"), ("SR 7.2", "Resource Management")],
        "NERC CIP": [("CIP-007", "System Security Management")],
    },
    "T0878": {  # Alarm Suppression
        "NIST 800-53": [("AU-6", "Audit Record Review, Analysis, and Reporting"), ("SI-4", "System Monitoring")],
        "IEC 62443-3-3": [("SR 6.1", "Audit Log Accessibility"), ("SR 6.2", "Continuous Monitoring")],
        "NERC CIP": [("CIP-007", "System Security Management")],
    },
    "T0846": {  # Remote System Discovery
        "NIST 800-53": [("SC-7", "Boundary Protection"), ("SI-4", "System Monitoring")],
        "IEC 62443-3-3": [("SR 5.1", "Network Segmentation"), ("SR 6.2", "Continuous Monitoring")],
        "NERC CIP": [("CIP-005", "Electronic Security Perimeter(s)")],
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
