"""Collector base + shared helpers.

A collector pulls new records from a vendor API since a stored cursor and returns
the raw response text (the input its parser already expects) plus the advanced
cursor. The network call is isolated in `_http_get` so concrete collectors stay
unit-testable (URL building + cursor extraction are pure functions)."""
from __future__ import annotations

import json
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from ..util import parse_ts


@dataclass
class FetchResult:
    content: str               # raw text to feed the parser
    cursor: Optional[str]      # advanced checkpoint to persist
    count: int                 # records fetched (for status/stats)


def iso_lookback(hours: int) -> str:
    """An ISO-8601 UTC timestamp `hours` in the past — the initial cursor."""
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime(
        "%Y-%m-%dT%H:%M:%S.000Z")


def json_records(body: str, key: Optional[str] = None) -> list:
    """Parse a response into a list of records ([] on anything else).

    A bare JSON array is returned as-is. When `key` is given and the body is a
    JSON object (e.g. Microsoft Graph's ``{"value": [...]}``), that key's list is
    returned. Anything else yields []."""
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return []
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict) and key and isinstance(obj.get(key), list):
        return obj[key]
    return []


def max_time_iso(records: list, field: str, current: Optional[str]) -> Optional[str]:
    """The latest `field` timestamp across records, as ISO — the next cursor.
    Falls back to `current` when nothing parseable is present."""
    best: Optional[datetime] = None
    for r in records:
        if not isinstance(r, dict):
            continue
        dt = parse_ts(r.get(field))
        if dt and (best is None or dt > best):
            best = dt
    return best.isoformat() if best else current


class Collector(ABC):
    name: str = ""
    fmt: str = ""              # parser format key the response is fed to
    label: str = ""

    def configured(self) -> bool:
        return True

    @abstractmethod
    def fetch(self, cursor: Optional[str]) -> FetchResult:
        ...

    def _http_get(self, url: str, headers: dict) -> str:
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310 — configured URL
            return resp.read().decode("utf-8", "replace")

    def _http_post(self, url: str, headers: dict, data: bytes) -> str:
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310 — configured URL
            return resp.read().decode("utf-8", "replace")
