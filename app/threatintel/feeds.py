"""Threat-intel feed loading + parsing.

A feed is a local file path or an ``http(s)`` URL. The parser accepts the common
shapes — a plain one-indicator-per-line list (``#`` comments allowed), a CSV with
``indicator[,type[,severity[,description]]]``, or JSON (an array of strings, or of
objects with an ``indicator``/``value``/``ioc`` key). Indicator type is inferred
when absent. Parsing is pure; only ``load_feed_source`` touches the network/disk.
"""
from __future__ import annotations

import json
import logging
import re
import urllib.request
from pathlib import Path
from typing import Optional

from .matcher import Ioc, make_ioc

log = logging.getLogger("logocean")

_IND_KEYS = ("indicator", "value", "ioc", "ip", "domain", "url", "hash")
_TYPE_KEYS = ("type", "ioc_type", "indicator_type")
_SEV_KEYS = ("severity", "level", "confidence")
_DESC_KEYS = ("description", "desc", "comment", "threat", "tags")


def _pick(d: dict, keys) -> Optional[str]:
    low = {str(k).strip().lower(): v for k, v in d.items()}
    for k in keys:
        v = low.get(k)
        if v not in (None, ""):
            return str(v)
    return None


def _parse_json_feed(text: str, source: str, default_severity: str) -> list[Ioc]:
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    rows = obj if isinstance(obj, list) else obj.get("data") if isinstance(obj, dict) else None
    iocs: list[Ioc] = []
    for r in rows or []:
        if isinstance(r, str):
            ioc = make_ioc(r, source, default_severity)
        elif isinstance(r, dict):
            ind = _pick(r, _IND_KEYS)
            if not ind:
                continue
            ioc = make_ioc(ind, source, _pick(r, _SEV_KEYS) or default_severity,
                           _pick(r, _DESC_KEYS) or "", _pick(r, _TYPE_KEYS))
        else:
            ioc = None
        if ioc:
            iocs.append(ioc)
    return iocs


def parse_feed(text: str, source: str, default_severity: str = "high") -> list[Ioc]:
    """Parse feed `text` into validated, de-duplicated IOCs."""
    t = (text or "").strip()
    if not t:
        return []
    if t[:1] in "[{":
        parsed = _parse_json_feed(t, source, default_severity)
    else:
        parsed = []
        for line in t.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")] if "," in line else [line]
            ind = parts[0]
            typ = parts[1].lower() if len(parts) > 1 and parts[1] else None
            sev = parts[2].lower() if len(parts) > 2 and parts[2] else default_severity
            desc = parts[3] if len(parts) > 3 else ""
            ioc = make_ioc(ind, source, sev, desc, typ)
            if ioc:
                parsed.append(ioc)
    # de-dup within a feed, keeping the first occurrence
    seen: set[tuple[str, str]] = set()
    out: list[Ioc] = []
    for ioc in parsed:
        key = (ioc.indicator, ioc.ioc_type)
        if key not in seen:
            seen.add(key)
            out.append(ioc)
    return out


def load_feed_source(src: str) -> str:
    """Read a feed's raw text from a URL or local file (the only network/disk I/O)."""
    if src.startswith(("http://", "https://")):
        req = urllib.request.Request(src, headers={"User-Agent": "LogOcean"})
        with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310 — configured feed
            return resp.read().decode("utf-8", "replace")
    return Path(src).read_text(encoding="utf-8", errors="replace")


def split_feeds(spec: str) -> list[str]:
    """Split the THREATINTEL_FEEDS setting (comma- or whitespace-separated)."""
    return [s for s in re.split(r"[,\s]+", spec.strip()) if s] if spec else []
