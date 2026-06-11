"""Shared parsing helpers — tolerant timestamp / IP / int coercion."""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any, Optional

from dateutil import parser as _dtparser


def parse_ts(value: Any) -> Optional[datetime]:
    """Parse epoch (s or ms), ISO-8601, or vendor date strings to aware UTC.
    Returns None if unparseable."""
    if value is None or value == "":
        return None
    # Numeric epoch (seconds or milliseconds)
    if isinstance(value, (int, float)):
        return _from_epoch(float(value))
    s = str(value).strip().strip('"')
    if not s:
        return None
    if s.isdigit() and len(s) >= 9:  # looks like an epoch, not a year
        return _from_epoch(float(s))
    try:
        dt = _dtparser.parse(s)
    except (ValueError, OverflowError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _from_epoch(v: float) -> Optional[datetime]:
    if v > 1e14:        # microseconds
        v /= 1_000_000.0
    elif v > 1e11:      # milliseconds
        v /= 1_000.0
    try:
        return datetime.fromtimestamp(v, tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        return None


def clean_ip(value: Any) -> Optional[str]:
    """Return a canonical IP string, or None if not a valid IP."""
    if value is None or value == "":
        return None
    s = str(value).strip().strip('"')
    if not s or s in ("0.0.0.0", "::"):
        return None
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def to_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(str(value).strip().strip('"'))
    except (ValueError, TypeError):
        return None


def first(*values: Any) -> Optional[Any]:
    """First value that is not None/empty."""
    for v in values:
        if v is not None and v != "":
            return v
    return None
