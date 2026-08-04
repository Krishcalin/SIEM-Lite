# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Rapid7 InsightVM — vulnerability findings parser (Console API v3).

InsightVM splits one finding across three resources: the ASSET
(``/api/3/assets``), the per-asset FINDING (``/api/3/assets/{id}/vulnerabilities``,
which carries only the vulnerability id, its status and the proof results) and the
VULNERABILITY catalog entry (``/api/3/vulnerabilities/{id}``, which carries the
title, severity, CVSS and CVEs). None of the three is a finding on its own, so
``app/collectors/vuln.py`` joins them and emits one envelope per finding::

    {"asset": {...}, "finding": {...}, "vulnerability": {...}}

The parser also accepts a FLAT record — a bare catalog resource, or an envelope
whose keys sit at the top level — so a hand-exported ``/api/3/...`` response can
be uploaded through the console without the collector.

Flattened onto the Vulnerability CIM contract (``app/cim/models.yaml``):
``vendor=rapid7`` + ``log_type=vulnerability`` is the membership handle,
``rule_name`` is the vulnerability title (projected as ``signature``),
``host_name`` is the affected asset (``dest`` / ``dvc``), and ``cve`` / ``cve_id``
/ ``category`` are written back into ``raw`` as TOP-LEVEL SCALARS because jsonb
lookups in CIM are byte-exact and cannot descend into the ``cves`` array.

Severity ordering is CVSS FIRST, vendor rating second — see the same note in
``tenable.py``. InsightVM's ``severity`` is a three-value scale
(Critical / Severe / Moderate) that does not line up with the repo's five, so
mapping it directly would quietly compress two bands into one.

When the catalog entry is missing (the collector's lookup budget was spent, or the
id 404s) the CVE is still recovered from the vulnerability id itself: InsightVM
names a large share of its checks ``<product>-cve-2021-41773``.
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


# InsightVM's own rating, used only when the catalog entry carries no CVSS score.
_VENDOR_SEV = {"critical": "critical", "severe": "high", "moderate": "medium",
               "low": "low", "informational": "informational", "info": "informational"}
# `status` -> the cross-vendor action vocabulary the three scanner parsers share.
# "vulnerable-version" is a version-only match; "potential" is unconfirmed.
_STATUS = {"vulnerable": "open", "vulnerable-version": "open", "potential": "potential",
           "fixed": "fixed", "remediated": "fixed"}


def _sub(rec: dict, key: str) -> dict:
    value = rec.get(key)
    return value if isinstance(value, dict) else {}


def _cvss_score(vuln: dict) -> Optional[Any]:
    """The catalog entry's CVSS base score — v3 preferred, then v2, then the
    ``severityScore`` (InsightVM's own 0-10 restatement of the CVSS base)."""
    cvss = _sub(vuln, "cvss")
    for block in ("v3", "v2"):
        score = _sub(cvss, block).get("score")
        if score is not None:
            return score
    return first(cvss.get("score"), vuln.get("severityScore"))


def _first_result(finding: dict) -> dict:
    results = finding.get("results")
    if isinstance(results, list):
        for item in results:
            if isinstance(item, dict):
                return item
    return {}


def _host(asset: dict) -> Optional[str]:
    names = asset.get("hostNames")
    if isinstance(names, list):
        for item in names:
            if isinstance(item, dict) and item.get("name"):
                return item["name"]
            if isinstance(item, str) and item:
                return item
    return first(asset.get("hostName"), asset.get("host_name"), asset.get("ip"))


def parse(content: str) -> Iterator[NormalizedEvent]:
    for rec in iter_json_records(content, "resources", "data", "vulnerabilities"):
        asset = _sub(rec, "asset")
        finding = _sub(rec, "finding") or rec
        vuln = _sub(rec, "vulnerability") or rec
        result = _first_result(finding)

        vuln_id = first(vuln.get("id"), finding.get("id"))
        score = _cvss_score(vuln)
        status = str(first(finding.get("status"), result.get("status")) or "").strip().lower()
        categories = vuln.get("categories")
        category = (", ".join(str(c) for c in categories)
                    if isinstance(categories, list) and categories else categories)
        cve_all, cve_one = cve_scalars(vuln.get("cves"), vuln.get("cve"), vuln_id)

        raw = dict(rec)
        if cve_all:
            raw["cve"], raw["cve_id"] = cve_all, cve_one
        if category:
            raw["category"] = category
        if score is not None:
            raw["cvss"] = score
        if vuln_id:
            raw["vuln_id"] = vuln_id

        yield NormalizedEvent(
            event_time=parse_ts(first(finding.get("since"), rec.get("since"),
                                      asset.get("lastScanEnd"), asset.get("last_scan_end"),
                                      vuln.get("modified"), vuln.get("published"))),
            vendor="rapid7",
            product="insightvm",
            log_type="vulnerability",
            severity=first(cvss_severity(score),
                           _VENDOR_SEV.get(str(vuln.get("severity") or "").strip().lower())),
            action=_STATUS.get(status, status or None),
            dst_ip=clean_ip(asset.get("ip")),
            dst_port=to_port(result.get("port")) or None,
            protocol=str(result["protocol"]).lower() if result.get("protocol") else None,
            host_name=_host(asset) if asset else None,
            rule_name=first(vuln.get("title"), vuln_id),
            message=first(vuln.get("title"), vuln_id),
            raw=raw,
        )
