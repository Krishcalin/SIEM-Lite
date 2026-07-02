"""IOC classification + the in-memory match index (pure, unit-testable).

An ``IocIndex`` holds indicators bucketed by type for O(1) lookups (plus a list
of CIDRs for containment). ``match`` pulls the observables out of a
``NormalizedEvent`` — its src/dst IPs, the normalized string fields, and every
scalar in ``raw`` — and also extracts IPs/domains/URLs/hashes embedded in free
text, so an indicator hidden inside a ``message`` is still caught.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Optional

from ..models import NormalizedEvent

VALID_TYPES = ("ip", "cidr", "domain", "hash", "url")
_SEV_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Whole-string classifiers.
_HEX_HASH = re.compile(r"\A[a-fA-F0-9]{32}\Z|\A[a-fA-F0-9]{40}\Z|\A[a-fA-F0-9]{64}\Z")
_DOMAIN = re.compile(
    r"\A(?=.{1,253}\Z)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,}\Z", re.I)
# Token extractors over free text.
_IP_TOK = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_TOK = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)
_URL_TOK = re.compile(r"https?://[^\s\"'<>\\]+", re.I)
_HASH_TOK = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")


@dataclass(frozen=True)
class Ioc:
    indicator: str
    ioc_type: str
    source: str = "manual"
    severity: str = "high"
    description: str = ""


@dataclass
class IocHit:
    indicator: str
    ioc_type: str
    source: str
    severity: str
    observed: str          # the value in the event that matched


def classify(indicator: str) -> Optional[str]:
    """Infer an indicator's type from its shape (None if it's not a usable IOC)."""
    s = (indicator or "").strip()
    if not s:
        return None
    if s.lower().startswith(("http://", "https://")):
        return "url"
    if "/" in s:
        try:
            ipaddress.ip_network(s, strict=False)
            return "cidr"
        except ValueError:
            return None
    try:
        ipaddress.ip_address(s)
        return "ip"
    except ValueError:
        pass
    if _HEX_HASH.match(s):
        return "hash"
    if _DOMAIN.match(s):
        return "domain"
    return None


def normalize(indicator: str, ioc_type: str) -> str:
    """Canonical stored form: domains/hashes/URLs lowercased; IP/CIDR as-is."""
    s = indicator.strip()
    return s.lower() if ioc_type in ("domain", "hash", "url") else s


def make_ioc(indicator: str, source: str, severity: str = "high",
             description: str = "", ioc_type: Optional[str] = None) -> Optional[Ioc]:
    """Build a validated, normalized Ioc (None if the indicator can't be typed)."""
    t = ioc_type if ioc_type in VALID_TYPES else classify(indicator)
    if not t:
        return None
    return Ioc(normalize(indicator, t), t, source or "manual",
               (severity or "high").lower(), description or "")


# --------------------------------------------------------------------------- #
#  Index                                                                       #
# --------------------------------------------------------------------------- #
class IocIndex:
    def __init__(self) -> None:
        self.ips: dict[str, Ioc] = {}
        self.cidrs: list[tuple[Any, Ioc]] = []
        self.domains: dict[str, Ioc] = {}
        self.hashes: dict[str, Ioc] = {}
        self.urls: dict[str, Ioc] = {}

    def add(self, ioc: Ioc) -> None:
        if ioc.ioc_type == "ip":
            self.ips[ioc.indicator] = ioc
        elif ioc.ioc_type == "cidr":
            try:
                self.cidrs.append((ipaddress.ip_network(ioc.indicator, strict=False), ioc))
            except ValueError:
                pass
        elif ioc.ioc_type == "domain":
            self.domains[ioc.indicator.lower()] = ioc
        elif ioc.ioc_type == "hash":
            self.hashes[ioc.indicator.lower()] = ioc
        elif ioc.ioc_type == "url":
            self.urls[ioc.indicator.lower()] = ioc

    def __len__(self) -> int:
        return len(self.ips) + len(self.cidrs) + len(self.domains) + \
            len(self.hashes) + len(self.urls)

    def counts(self) -> dict[str, int]:
        return {"ip": len(self.ips), "cidr": len(self.cidrs),
                "domain": len(self.domains), "hash": len(self.hashes),
                "url": len(self.urls)}

    def _ip_hit(self, ip: str, observed: str) -> Optional[IocHit]:
        ioc = self.ips.get(ip)
        if ioc:
            return IocHit(ioc.indicator, "ip", ioc.source, ioc.severity, observed)
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, ioc in self.cidrs:
            if addr in net:
                return IocHit(ioc.indicator, "cidr", ioc.source, ioc.severity, observed)
        return None

    def match(self, evt: NormalizedEvent) -> list[IocHit]:
        """Every distinct indicator the event touches (deduped by indicator)."""
        values = _observables(evt)
        blob = " ".join(values)
        hits: dict[str, IocHit] = {}

        def add(hit: Optional[IocHit]) -> None:
            if hit:
                hits.setdefault(hit.indicator, hit)

        # IPs: the explicit src/dst plus any dotted-quad found in text.
        ip_cands = {str(evt.src_ip), str(evt.dst_ip)} if (evt.src_ip or evt.dst_ip) else set()
        ip_cands = {v for v in ip_cands if v and v != "None"} | set(_IP_TOK.findall(blob))
        for ip in ip_cands:
            add(self._ip_hit(ip, ip))

        if self.hashes:
            for h in set(_HASH_TOK.findall(blob)):
                ioc = self.hashes.get(h.lower())
                if ioc:
                    add(IocHit(ioc.indicator, "hash", ioc.source, ioc.severity, h))
        if self.urls:
            for u in set(_URL_TOK.findall(blob)):
                ioc = self.urls.get(u.lower().rstrip(".,);"))
                if ioc:
                    add(IocHit(ioc.indicator, "url", ioc.source, ioc.severity, u))
        if self.domains:
            for d in set(_DOMAIN_TOK.findall(blob)):
                ioc = self.domains.get(d.lower())
                if ioc:
                    add(IocHit(ioc.indicator, "domain", ioc.source, ioc.severity, d))
        return list(hits.values())


def _observables(evt: NormalizedEvent) -> list[str]:
    vals: list[str] = []
    for f in (evt.src_ip, evt.dst_ip, evt.host_name, evt.app, evt.user_name,
              evt.rule_name, evt.message):
        if f:
            vals.append(str(f))
    _collect_scalars(evt.raw, vals)
    return vals


def _collect_scalars(obj: Any, out: list[str], depth: int = 0) -> None:
    if depth > 16:
        return
    if isinstance(obj, dict):
        for v in obj.values():
            _collect_scalars(v, out, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            _collect_scalars(v, out, depth + 1)
    elif obj is not None:
        out.append(str(obj))


# --------------------------------------------------------------------------- #
#  Alert builder                                                               #
# --------------------------------------------------------------------------- #
TI_RULE_ID = "ti-ioc-match"
TI_RULE_TITLE = "Threat Intelligence Match"


def _max_severity(hits: list[IocHit]) -> str:
    return max((h.severity for h in hits), key=lambda s: _SEV_RANK.get(s, 2), default="high")


def _short(source: str) -> str:
    """A compact feed label (host of a URL, or the bare name)."""
    s = re.sub(r"^https?://", "", source)
    return s.split("/")[0][:40] or source[:40]


def ti_alert(hits: list[IocHit], evt: NormalizedEvent, dedup_hash: str,
             batch_id: Optional[int] = None) -> dict:
    """Build one alert row summarizing all IOC hits on an event (DB-free, pure).
    Deduped per (rule, event) like detection alerts."""
    shown = ", ".join(f"{h.indicator} ({h.ioc_type})" for h in hits[:5])
    extra = f" [+{len(hits) - 5} more]" if len(hits) > 5 else ""
    feeds = ", ".join(sorted({_short(h.source) for h in hits}))
    message = f"Threat-intel match: {shown}{extra} — source: {feeds}"
    return {
        "event_time": evt.event_time,
        "rule_id": TI_RULE_ID, "rule_title": TI_RULE_TITLE,
        "level": _max_severity(hits), "tactics": [], "techniques": [],
        "vendor": evt.vendor, "src_ip": evt.src_ip, "dst_ip": evt.dst_ip,
        "user_name": evt.user_name, "host_name": evt.host_name,
        "message": message[:1000], "dedup_hash": dedup_hash, "batch_id": batch_id,
        "status": "open",
    }
