# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Asset & identity registry — declared business context, resolved onto every event.

Phase 3 slice 1 of the transformation roadmap. Answers "whose machine is this, how
much does it matter, and is anyone watching it?" at ingest time, so a detection can
gate on criticality while the event is still streaming and Phase 4's risk scoring has
a multiplier to read.

    from app import assets
    res = assets.resolve(evt, assets.get_index())
    res.asset_id, res.asset_criticality, res.context_tags

Layout:

| module         | role                                                          |
|----------------|---------------------------------------------------------------|
| `models.py`    | frozen value types: Asset, Identity, Resolution               |
| `normalize.py` | what "the same identifier" means — alias canonicalization     |
| `index.py`     | the in-memory lookup, incl. CIDR containment. No database.    |
| `resolve.py`   | event -> Resolution. Pure, and shared with the backfill.      |
| `registry.py`  | loading the index from the tables, and caching it             |
"""
from .index import EMPTY_INDEX, AssetIndex
from .models import (ASSET_ALIAS_TYPES, CRITICALITY, EMPTY, IDENTITY_ALIAS_TYPES,
                     Asset, Identity, Resolution, normalize_level, rank)
from .normalize import (alias_type_valid, asset_candidates, identity_candidates,
                        norm_alias)
from .registry import (build, generation, get_index, load, reload, set_index, stats)
from .resolve import resolve

__all__ = [
    "ASSET_ALIAS_TYPES", "CRITICALITY", "EMPTY", "EMPTY_INDEX",
    "IDENTITY_ALIAS_TYPES", "Asset", "AssetIndex", "Identity", "Resolution",
    "alias_type_valid", "asset_candidates", "build", "generation", "get_index",
    "identity_candidates", "load", "norm_alias", "normalize_level", "rank",
    "reload", "resolve", "set_index", "stats",
]
