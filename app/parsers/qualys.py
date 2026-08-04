# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Qualys VMDR — Host List Detection parser (XML).

Input is the ``HOST_LIST_VM_DETECTION_OUTPUT`` document the VM detection API
(``/api/2.0/fo/asset/host/vm/detection/``) returns: a ``HOST_LIST`` of hosts,
each with a ``DETECTION_LIST`` of per-QID findings. One event is emitted per
HOST x DETECTION pair, with the host's identity flattened onto the detection so
every finding is independently searchable.

Two documents are accepted in one payload. A truncated Qualys response carries a
``<WARNING><URL>`` continuation link, so ``app/collectors/vuln.py`` concatenates
the pages it walked; ``_iter_documents`` splits them back apart on the XML
declaration.

CVE COVERAGE, HONESTLY: the bare Host List Detection response identifies a
finding by QID and carries no CVE and no title — those live in the Qualys
KnowledgeBase. This parser therefore lifts ``CVE_LIST`` / ``CVE_ID_LIST``,
``VULN_TITLE`` / ``TITLE``, ``CVSS3_BASE`` / ``CVSS_BASE`` and ``CATEGORY``
whenever the export IS KB-enriched (a Qualys scan-report XML, or a detection list
post-processed against the KnowledgeBase), and falls back to ``QID <n>`` as the
signature and Qualys' own 1-5 severity otherwise. A plain detection export is a
member of the Vulnerability CIM model — membership needs only vendor + log_type —
whose ``cve`` field reads null. That is a property of the API, not of the parser.

XML SAFETY: ``xml.etree.ElementTree`` is documented as vulnerable to entity
expansion ("billion laughs") and quadratic blowup. Both attacks require an
internal DTD subset, so ``_has_declaration`` walks only the prolog — past the XML
declaration and comments, stopping at the root element's start tag — and rejects
the whole document if a ``<!DOCTYPE`` / ``<!ENTITY`` declaration appears there.
It deliberately does NOT scan the body: Qualys ``RESULTS`` sections are CDATA and
legitimately contain captured HTML.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any, Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, parse_ts, to_int, to_port

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


# Qualys grades a detection 1 (minimal) .. 5 (urgent). Used only when the export
# carries no CVSS score, which is the normal case for a detection-API pull.
_QUALYS_SEV = {1: "informational", 2: "low", 3: "medium", 4: "high", 5: "critical"}
# `STATUS` -> the cross-vendor action vocabulary the three scanner parsers share.
_STATUS = {"new": "open", "active": "open", "re-opened": "reopened",
           "reopened": "reopened", "fixed": "fixed"}

# Host-level tags renamed on the way into `raw` so they cannot be shadowed by a
# same-named detection tag. Everything else keeps its own lower-cased tag name.
_HOST_RENAME = {"id": "host_id", "type": "host_type", "status": "host_status",
                "severity": "host_severity"}


def _end_of_doctype(text: str, start: int) -> int:
    """Index just past the ``>`` closing the DOCTYPE at `start`, or -1 if unterminated.

    Quote-aware, because the SYSTEM/PUBLIC literal legitimately contains a URL and a
    naive ``find(">")`` would stop inside it on any DTD served over a query string.
    Stops at an internal subset ``[`` — the caller rejects that case, so there is no
    need to balance brackets here.
    """
    i, n, quote = start, len(text), ""
    while i < n:
        ch = text[i]
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == "[":
            return -1                    # internal subset — caller rejects
        elif ch == ">":
            return i + 1
        i += 1
    return -1


def _has_declaration(text: str) -> bool:
    """True if a DANGEROUS markup declaration precedes the root element.

    Walks the prolog only: an XML declaration or a comment is skipped, the first real
    element start tag ends the walk (accept), and an unterminated construct also ends
    it, since there is then no root element to parse anyway.

    WHAT COUNTS AS DANGEROUS, and why this is narrower than "any ``<!``". The attack
    this guards against — billion laughs, quadratic blowup — needs an INTERNAL subset,
    ``<!DOCTYPE x [ <!ENTITY ...> ]>``, because that is the only place a document may
    define its own entities. ElementTree never resolves an external SYSTEM/PUBLIC DTD,
    so a DOCTYPE that merely *names* one is inert.

    Rejecting the external form too was a real bug, not a conservative margin: every
    Qualys FO API 2.0 response opens with

        <!DOCTYPE HOST_LIST_VM_DETECTION_OUTPUT SYSTEM "https://.../output.dtd">

    and each continuation page of a truncated walk carries its own copy. The wide
    guard therefore made `_root` return None for every real API response while the
    shipped sample (which has no DOCTYPE) parsed fine — so a production VMDR pull
    ingested zero events while the collector reported ``ok`` with a non-zero count.
    """
    i, n = 0, len(text)
    while i < n:
        j = text.find("<", i)
        if j < 0:
            return False
        if text.startswith("<?", j):
            end = text.find("?>", j)
            if end < 0:
                return False
            i = end + 2
        elif text.startswith("<!--", j):
            end = text.find("-->", j)
            if end < 0:
                return False
            i = end + 3
        elif text.startswith("<!DOCTYPE", j):
            end = _end_of_doctype(text, j + len("<!DOCTYPE"))
            if end < 0:
                return True              # internal subset, or unterminated
            i = end
        elif text.startswith("<!", j):
            return True                  # a bare <!ENTITY et al — never legitimate here
        else:
            return False
    return False


def _iter_documents(text: str) -> Iterator[str]:
    """Yield each complete XML document in `text` (pages are concatenated)."""
    for part in re.split(r"(?=<\?xml\b)", text):
        part = part.strip()
        if part:
            yield part


def _root(document: str) -> Optional[ET.Element]:
    if _has_declaration(document):
        return None
    try:
        return ET.fromstring(document)          # nosec B314 — prolog guarded above
    except (ET.ParseError, ValueError, RecursionError):
        return None


def _scalars(elem: ET.Element) -> dict[str, str]:
    """Direct leaf children as ``{lower_tag: text}``; containers are skipped."""
    out: dict[str, str] = {}
    for child in elem:
        if len(child):
            continue
        text = (child.text or "").strip()
        if text:
            out[str(child.tag).strip().lower()] = text
    return out


def _cves(elem: ET.Element) -> list[str]:
    """CVE ids from any descendant whose TAG names CVE (``CVE_LIST``/``CVE_ID_LIST``).

    Qualys nests the identifier one level down (``<CVE><ID>CVE-…</ID></CVE>``), so
    the whole subtree text of a CVE-named node is scanned. Restricting the search
    to CVE-named tags keeps a CVE mentioned in a ``RESULTS`` proof blob from being
    reported as the finding's own identifier.
    """
    out: list[str] = []
    for node in elem.iter():
        if "CVE" not in str(node.tag).upper():
            continue
        for match in _CVE_RE.finditer("".join(node.itertext())):
            value = match.group(0).upper()
            if value not in out:
                out.append(value)
    return out


def parse(content: str) -> Iterator[NormalizedEvent]:
    for document in _iter_documents(content):
        root = _root(document)
        if root is None:
            continue
        for host in root.iter("HOST"):
            host_fields = _scalars(host)
            base = {_HOST_RENAME.get(k, k): v for k, v in host_fields.items()}
            ip = clean_ip(host_fields.get("ip"))
            host_name = first(host_fields.get("dns"), host_fields.get("netbios"),
                              host_fields.get("ip"), host_fields.get("id"))

            for detection in host.iter("DETECTION"):
                fields = _scalars(detection)
                raw = dict(base)
                raw.update(fields)

                cve_all, cve_one = cve_scalars(_cves(detection))
                if cve_all:
                    raw["cve"], raw["cve_id"] = cve_all, cve_one
                score = first(fields.get("cvss3_base"), fields.get("cvss_base"),
                              fields.get("cvss3_score"), fields.get("cvss_score"))
                # Qualys ships the score glued to its vector — "8.8 (AV:N/AC:L/…)".
                # `raw["cvss"]` is the cross-vendor key, so it holds the NUMBER; the
                # vendor's own spelling stays under its own tag name.
                number = _CVSS_NUM.match(str(score)) if score is not None else None
                if number:
                    raw["cvss"] = float(number.group(1))
                qid = fields.get("qid")
                title = first(fields.get("vuln_title"), fields.get("title"))
                status = str(fields.get("status") or "").strip().lower()

                yield NormalizedEvent(
                    event_time=parse_ts(first(fields.get("last_found_datetime"),
                                              fields.get("last_processed_datetime"),
                                              host_fields.get("last_scan_datetime"),
                                              fields.get("first_found_datetime"))),
                    vendor="qualys",
                    product="vmdr",
                    log_type="vulnerability",
                    severity=first(cvss_severity(score),
                                   _QUALYS_SEV.get(to_int(fields.get("severity")))),
                    action=_STATUS.get(status, status or None),
                    dst_ip=ip,
                    # A host-level detection carries no PORT; Qualys writes 0 there,
                    # which means "not port-specific", not port zero.
                    dst_port=to_port(fields.get("port")) or None,
                    protocol=str(fields["protocol"]).lower() if fields.get("protocol") else None,
                    host_name=host_name,
                    rule_name=first(title, f"QID {qid}" if qid else None),
                    message=first(f"QID {qid}: {title}" if qid and title else None,
                                  title, f"QID {qid}" if qid else None),
                    raw=raw,
                )
