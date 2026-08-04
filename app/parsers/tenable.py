# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Tenable Vulnerability Management (Tenable.io) — vulnerability findings parser.

Input is a chunk of the asynchronous ``/vulns/export`` workflow: a JSON array of
finding objects, each joining the scanned ``asset``, the ``plugin`` that fired,
the ``port`` it was seen on, and the finding's own state and timestamps.

The record is flattened onto the Vulnerability CIM contract
(``app/cim/models.yaml``):

  * ``vendor=tenable`` + ``log_type=vulnerability`` is the membership handle —
    the model's single clause ANDs a scanner vendor with a scanner log_type.
  * ``rule_name`` is the plugin name (the model projects it as ``signature``),
    ``host_name`` is the affected asset (``dest`` / ``dvc``) and ``severity`` is
    the repo's own vocabulary, never Tenable's.
  * ``cve`` / ``cve_id`` / ``category`` / ``plugin_family`` are written back into
    ``raw`` as TOP-LEVEL SCALARS. jsonb lookups in CIM are byte-exact and cannot
    descend into an array, so the model could never read ``plugin.cve[0]``; this
    follows the ``windows_security.py`` precedent of writing one agreed spelling
    beside the vendor's own.

Severity ordering is CVSS FIRST, vendor rating second. The CVSS base score is the
only rating that means the same thing across Qualys, Tenable and Rapid7, so it is
what makes a cross-vendor ``severity=critical`` search honest; Tenable's own
``severity`` string is the fallback for findings that carry no score (compliance
and informational plugins).
"""
from __future__ import annotations

import re
from typing import Any, Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, iter_json_records, parse_ts, to_port

# ── CVSS -> the repo's severity vocabulary ───────────────────────────────────
# app/severity.py:SEVERITY_ORDER is ("informational", "low", "medium", "high",
# "critical"); these are the NVD qualitative bands for a CVSS v3.x base score.
# Deliberately NOT a new scale, and deliberately duplicated verbatim in the other
# two scanner parsers (the repo already duplicates `_SEVERITY` across the four
# syslog parsers) — tests/test_vuln.py pins all three to one table so they cannot
# drift apart silently.
_CVSS_BANDS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"))
_CVSS_NUM = re.compile(r"^\s*(-?\d+(?:\.\d+)?)")


def cvss_severity(score: Any) -> Optional[str]:
    """Map a CVSS base score onto the repo's severity vocabulary.

    Accepts a float, an int or a string that STARTS with the number (Qualys ships
    ``"7.5 (AV:N/AC:L/...)"``). Returns None — so the caller falls back to the
    vendor's own rating — for anything unparseable or outside the 0..10 CVSS
    range, which also rejects ``nan`` and ``inf``.
    """
    if score is None:
        return None
    m = _CVSS_NUM.match(str(score))
    if not m:
        return None
    value = float(m.group(1))
    if value < 0.0 or value > 10.0:
        return None
    for floor, name in _CVSS_BANDS:
        if value >= floor:
            return name
    return "informational"


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def cve_scalars(*sources: Any) -> tuple[Optional[str], Optional[str]]:
    """Flatten CVE identifiers out of any mix of lists/strings into two scalars.

    Returns ``(all_joined, first)`` — the value written to ``raw["cve"]`` and
    ``raw["cve_id"]`` respectively. The CIM field reads ``[cve, cve_id]``, so the
    complete comma-joined list wins the projection while ``cve_id`` stays a clean
    single value for equality filters. ``(None, None)`` when nothing matched.
    """
    seen: list[str] = []
    for source in sources:
        items = source if isinstance(source, (list, tuple, set)) else [source]
        for item in items:
            if item is None or isinstance(item, (dict, list, tuple, set)):
                continue
            for match in _CVE_RE.finditer(str(item)):
                value = match.group(0).upper()
                if value not in seen:
                    seen.append(value)
    if not seen:
        return None, None
    return ",".join(seen), seen[0]


# Tenable's own rating, used only when a finding carries no CVSS score.
_VENDOR_SEV = {
    "info": "informational", "informational": "informational", "none": "informational",
    "low": "low", "medium": "medium", "high": "high", "critical": "critical",
}
# `state` -> the cross-vendor action vocabulary the three scanner parsers share.
_STATE = {"open": "open", "reopened": "reopened", "fixed": "fixed",
          "resurfaced": "reopened"}


def _sub(rec: dict, key: str) -> dict:
    value = rec.get(key)
    return value if isinstance(value, dict) else {}


def parse(content: str) -> Iterator[NormalizedEvent]:
    for rec in iter_json_records(content, "vulnerabilities", "findings", "data"):
        asset = _sub(rec, "asset")
        plugin = _sub(rec, "plugin")
        port = _sub(rec, "port")
        scan = _sub(rec, "scan")

        score = first(plugin.get("cvss3_base_score"), plugin.get("cvss_base_score"))
        state = str(rec.get("state") or "").strip().lower()
        cve_all, cve_one = cve_scalars(plugin.get("cve"), plugin.get("cves"))
        family = plugin.get("family")

        raw = dict(rec)
        if cve_all:
            raw["cve"], raw["cve_id"] = cve_all, cve_one
        if family:
            raw["category"] = raw["plugin_family"] = family
        if score is not None:
            raw["cvss"] = score
            raw["cvss_version"] = "3.0" if plugin.get("cvss3_base_score") is not None else "2.0"
        if plugin.get("id") is not None:
            raw["plugin_id"] = plugin["id"]

        ipv4 = clean_ip(asset.get("ipv4"))
        yield NormalizedEvent(
            event_time=parse_ts(first(rec.get("last_found"), rec.get("indexed"),
                                      scan.get("started_at"), rec.get("first_found"))),
            vendor="tenable",
            product="tenable_io",
            log_type="vulnerability",
            severity=first(cvss_severity(score),
                           _VENDOR_SEV.get(str(rec.get("severity") or "").strip().lower())),
            action=_STATE.get(state, state or None),
            dst_ip=first(ipv4, clean_ip(asset.get("ipv6"))),
            # Tenable reports port 0 for a finding that is not port-specific (a
            # local/agent plugin); that is "no port", not port zero.
            dst_port=to_port(port.get("port")) or None,
            protocol=str(port["protocol"]).lower() if port.get("protocol") else None,
            host_name=first(asset.get("fqdn"), asset.get("hostname"),
                            asset.get("netbios_name"), asset.get("ipv4"),
                            asset.get("uuid")),
            rule_name=first(plugin.get("name"), plugin.get("synopsis")),
            message=first(plugin.get("name"), plugin.get("synopsis"),
                          plugin.get("description")),
            raw=raw,
        )
