"""Shared parsing helpers — tolerant timestamp / IP / int coercion."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any, Iterator, Optional

from dateutil import parser as _dtparser


def hash_api_key(key: str) -> str:
    """sha256 hex of an API key. Only this hash is stored; the plaintext key is
    shown once at creation and never persisted."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def extract_api_key(x_api_key: Optional[str], authorization: Optional[str]) -> Optional[str]:
    """Pull an API key from the X-API-Key header or an `Authorization: Bearer` header."""
    if x_api_key and x_api_key.strip():
        return x_api_key.strip()
    if authorization and authorization[:7].lower() == "bearer ":
        return authorization[7:].strip() or None
    return None


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


_IPV4_PORT = re.compile(r"^\[(.+?)\](?::(\d+))?$")


def split_ip_port(value: Any) -> tuple[Optional[str], Optional[int]]:
    """Split ``ip:port`` or ``[ipv6]:port`` into (ip, port).

    Returns ``(ip, None)`` when there is no port, and ``(None, None)`` for an
    empty value. Cloud audit logs (M365, Entra) often glue the port onto the
    client IP; the caller still runs the ip through ``clean_ip``.
    """
    if value is None or value == "":
        return None, None
    s = str(value).strip().strip('"')
    m = _IPV4_PORT.match(s)          # bracketed IPv6, optional port
    if m:
        return m.group(1), to_int(m.group(2))
    if s.count(":") == 1 and "." in s:   # ipv4:port
        ip, _, port = s.partition(":")
        return ip, to_int(port)
    return s, None


def _unwrap_json(obj: Any, wrapper_keys: tuple[str, ...]) -> Iterator[dict]:
    if isinstance(obj, list):
        yield from (r for r in obj if isinstance(r, dict))
    elif isinstance(obj, dict):
        low = {str(k).lower(): k for k in obj}
        for wk in wrapper_keys:
            actual = low.get(wk.lower())
            if actual is not None and isinstance(obj[actual], list):
                yield from (r for r in obj[actual] if isinstance(r, dict))
                return
        yield obj


# Reject documents nested past this many levels. Real logs (ECS is ~5-6 deep)
# never approach it; a pathological bomb does. This is an explicit, version-stable
# guard — newer CPython no longer raises RecursionError at moderate depths, so the
# decoder alone can no longer be relied on to reject a deeply nested payload.
_MAX_JSON_DEPTH = 100


def _exceeds_json_depth(text: str, limit: int) -> bool:
    """True if `text`'s structural nesting exceeds `limit`. O(n), string-aware
    (braces inside JSON string literals don't count) — so it can drop a deeply
    nested bomb before json.loads ever sees it."""
    depth = 0
    in_str = escaped = False
    for ch in text:
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "{[":
            depth += 1
            if depth > limit:
                return True
        elif ch in "}]" and depth > 0:
            depth -= 1
    return False


def iter_json_records(content: str, *wrapper_keys: str) -> Iterator[dict]:
    """Yield dict records from a JSON document of any common shape.

    Handles a single object, a top-level array, an NDJSON stream, or an object
    that wraps the records under one of ``wrapper_keys`` (e.g. CloudTrail's
    ``Records``, Microsoft Graph's ``value``). Non-dict members are skipped.
    """
    text = content.strip()
    if not text:
        return
    # Drop a deeply-nested (attacker-crafted) payload before parsing it, so json's
    # recursive decoder can't exhaust the stack and abort the whole ingest. NDJSON
    # streams are unaffected: depth resets between records, so the max stays small.
    if _exceeds_json_depth(text, _MAX_JSON_DEPTH):
        return
    # Belt-and-suspenders: also treat a RecursionError as unparseable.
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        obj = None
    if obj is not None:
        yield from _unwrap_json(obj, wrapper_keys)
        return
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (json.JSONDecodeError, RecursionError):
            continue
        yield from _unwrap_json(rec, wrapper_keys)
