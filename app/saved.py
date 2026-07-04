# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Saved searches — pure helpers.

A saved search is just a named (page, query-string) pair an analyst can re-run.
Keeping the path/query validation and target-URL building here (pure, no DB, no
request object) makes the routes thin and the logic unit-testable.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode

# Pages a saved search may target. Anything else falls back to the event search.
ALLOWED_PATHS = ("/search", "/alerts")
_MAX_QUERY = 2000
_MAX_NAME = 120


def normalize_path(path: str | None) -> str:
    p = (path or "").strip()
    return p if p in ALLOWED_PATHS else "/search"


def clean_query(query: str | None) -> str:
    """Normalize a query string for storage: drop the leading '?', strip paging
    and empty values, and re-encode canonically (bounded length)."""
    raw = (query or "").lstrip("?")[:_MAX_QUERY]
    pairs = [(k, v) for k, v in parse_qsl(raw, keep_blank_values=False)
             if k not in ("page",) and v]
    return urlencode(pairs)


def clean_name(name: str | None) -> str:
    return (name or "").strip()[:_MAX_NAME]


def target_url(path: str | None, query: str | None) -> str:
    """The safe, re-runnable URL for a saved search."""
    p = normalize_path(path)
    q = clean_query(query)
    return f"{p}?{q}" if q else p


def is_valid(name: str | None, path: str | None) -> bool:
    """A save is valid only with a non-empty name targeting an allowed path."""
    return bool(clean_name(name)) and (path or "").strip() in ALLOWED_PATHS
