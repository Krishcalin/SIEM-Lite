# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Loading and caching the asset/identity index.

The registry lives in the DATABASE, not in a YAML file — unlike `app/cim`, whose
models.yaml is developer-authored content shipped with the build. Assets and
identities are operator data: imported from a CSV export of a CMDB or a directory,
edited in the console, and expected to survive a rebuild. That difference drives
everything here — the loader reads tables, and `reload()` is called after a write
rather than after a file edit.

CACHING, AND THE RACE THAT IS DELIBERATELY NOT POSSIBLE
-------------------------------------------------------
`_cache` and the flag that guards it are the SAME global, published under a lock as
one assignment. A racing thread therefore sees either None (and waits for the lock,
then finds the value the winner stored) or a fully-built index — never a half-built
one, and never a stale sentinel that outlives the value it was guarding.

That is not a hypothetical care: `app/detection/engine.py:_cim` once published a
SEPARATE `_resolved = True` flag before resolving, so a concurrent caller could cache
a permanently dead gate. Keeping the flag and the value as one object is what makes
that shape unrepresentable here.

FAILURE IS NOT CACHED, and the asymmetry with `cim.registry` is deliberate. A CIM
registry that will not parse is a 27KB YAML file re-validated per event, so a
negative entry is essential there. Here a failure means the DATABASE is unreachable,
in which case ingest is already failing at the INSERT — there is no per-event retry
storm to prevent, and memoizing would keep the registry dark after the database came
back. Instead the last good index is RETAINED (see `reload`), so a transient outage
costs freshness rather than every event's context.
"""
from __future__ import annotations

import logging
import threading
from typing import Any, Optional

from .index import EMPTY_INDEX, AssetIndex
from .models import Asset, Identity, normalize_level

log = logging.getLogger("logocean")

_lock = threading.Lock()
_cache: Optional[AssetIndex] = None
#: Bumped on every successful load. Lets a caller notice a reload happened under it
#: without comparing whole indexes — used by the console to decide whether a cached
#: page render is stale.
_generation = 0


def _tuple(value: Any) -> tuple[str, ...]:
    """A text[] column as a tuple of clean labels.

    Lower-cased and de-duplicated here rather than at the point of use, because these
    become `context_tags` and a row whose labels differed only in case would be a
    second, non-matching value in a GIN-indexed array.
    """
    if not value:
        return ()
    items = value if isinstance(value, (list, tuple)) else [value]
    out = {str(v).strip().lower() for v in items if str(v or "").strip()}
    return tuple(sorted(out))


def asset_from_row(row: Any) -> Asset:
    return Asset(
        asset_id=str(row["asset_id"]),
        display_name=str(row.get("display_name") or ""),
        criticality=normalize_level(row.get("criticality")),
        category=_tuple(row.get("category")),
        owner=str(row.get("owner") or ""),
        business_unit=str(row.get("business_unit") or ""),
        environment=str(row.get("environment") or "").strip().lower(),
        watchlist=_tuple(row.get("watchlist")),
        enabled=bool(row.get("enabled", True)),
        notes=str(row.get("notes") or ""),
        source=str(row.get("source") or "manual"),
    )


def identity_from_row(row: Any) -> Identity:
    return Identity(
        identity_id=str(row["identity_id"]),
        display_name=str(row.get("display_name") or ""),
        priority=normalize_level(row.get("priority")),
        department=str(row.get("department") or ""),
        manager=str(row.get("manager") or ""),
        title=str(row.get("title") or ""),
        email=str(row.get("email") or ""),
        watchlist=_tuple(row.get("watchlist")),
        enabled=bool(row.get("enabled", True)),
        notes=str(row.get("notes") or ""),
        source=str(row.get("source") or "manual"),
    )


def build(asset_rows, identity_rows, asset_alias_rows, identity_alias_rows) -> AssetIndex:
    """Assemble an index from four already-fetched row sets. No database access, so a
    test can build a realistic index from literals."""
    return AssetIndex(
        assets=[asset_from_row(r) for r in asset_rows],
        identities=[identity_from_row(r) for r in identity_rows],
        asset_alias={(str(r["alias_type"]), str(r["alias_value"])): str(r["asset_id"])
                     for r in asset_alias_rows},
        identity_alias={(str(r["alias_type"]), str(r["alias_value"])):
                        str(r["identity_id"]) for r in identity_alias_rows},
    )


def load() -> AssetIndex:
    """Read the four tables and build an index. Raises if the database is unusable."""
    from .. import db

    with db.pool().connection() as conn:
        assets = conn.execute("SELECT * FROM assets").fetchall()
        identities = conn.execute("SELECT * FROM identities").fetchall()
        aa = conn.execute(
            "SELECT alias_type, alias_value, asset_id FROM asset_aliases").fetchall()
        ia = conn.execute(
            "SELECT alias_type, alias_value, identity_id FROM identity_aliases"
        ).fetchall()
    return build(assets, identities, aa, ia)


def get_index() -> AssetIndex:
    """The cached index. Degrades to an EMPTY index rather than raising.

    Never propagating is the same rule `db._cim_tags` follows for CIM membership and
    for the same reason: this runs inside the write path, and a registry that cannot
    be read must cost an event its CONTEXT, never the event itself. An empty index
    resolves to `Resolution()`, so the row stores NULL context and a later
    `backfill_assets` fills it in — which is exactly what the backfill exists for.
    """
    global _cache
    if _cache is not None:
        return _cache
    with _lock:
        if _cache is not None:
            return _cache
        try:
            _cache = load()
        except Exception as exc:                    # noqa: BLE001 — see the docstring
            log.warning("asset registry unavailable, events will store no context "
                        "until it loads: %s", exc)
            return EMPTY_INDEX                      # NOT cached — retry next call
        return _cache


def reload() -> AssetIndex:
    """Rebuild from the tables. Called after any registry write, and at startup.

    A FAILED RELOAD KEEPS THE PREVIOUS INDEX. Replacing a working registry with an
    empty one because the database blinked would silently strip context from every
    event ingested during the outage — rows that then look resolved-to-nothing rather
    than unresolved, and that no staleness check would flag, because the fingerprint
    of an empty registry is a perfectly valid fingerprint.
    """
    global _cache, _generation
    with _lock:
        try:
            index = load()
        except Exception as exc:                    # noqa: BLE001
            log.error("asset registry reload failed, keeping the previous index "
                      "(%d asset(s), %d identity(ies)): %s",
                      len(_cache.assets) if _cache else 0,
                      len(_cache.identities) if _cache else 0, exc)
            return _cache if _cache is not None else EMPTY_INDEX
        _cache = index
        _generation += 1
        log.info("asset registry loaded: %d asset(s), %d identity(ies), "
                 "%d alias(es), fingerprint %s",
                 len(index.assets), len(index.identities),
                 len(index.asset_alias) + len(index.identity_alias), index.fingerprint)
        return index


def generation() -> int:
    return _generation


def set_index(index: Optional[AssetIndex]) -> None:
    """Install an index directly — for tests and for `backfill_assets`, which pins one
    index for the whole run so a concurrent reload cannot make the first half of a
    backfill disagree with the second."""
    global _cache, _generation
    with _lock:
        _cache = index
        _generation += 1


def stats() -> dict:
    """Registry counts + fingerprint for /health and the console."""
    index = _cache
    if index is None:
        return {"loaded": False, "assets": 0, "identities": 0, "aliases": 0,
                "fingerprint": None}
    return {"loaded": True,
            "assets": len(index.assets),
            "identities": len(index.identities),
            "aliases": len(index.asset_alias) + len(index.identity_alias),
            "cidrs": len(index.cidrs),
            "fingerprint": index.fingerprint}
