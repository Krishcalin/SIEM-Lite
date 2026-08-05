# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Frozen value types for geo/network enrichment.

Pure data — no file, no database, no clock, no socket. `app/enrich/geo.py` builds
these and `app/db.py:_row` writes them, which is what keeps the resolver unit-testable
with nothing on disk. The asset registry's `app/assets/models.py` is the same shape for
the same reason.

WHAT IS STORED, AND WHAT IS DELIBERATELY NOT
--------------------------------------------
Four scalars: two country codes and two AS numbers. City, latitude, longitude and the
AS organisation name are decoded by the reader and then THROWN AWAY, because nothing
in the product reads them and `events` is the largest table in the system — three
years of monthly partitions. A `text` city column would cost more than the whole geo
feature returns. If a map view ever needs coordinates it should join a lookup at query
time from the same database file, not widen the fact table.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class GeoResult:
    """What the geo layer knows about one event.

    Carries RESOLVED VALUES rather than references, exactly like
    `assets.Resolution`: this is written straight onto the event row and nothing
    downstream re-reads the database file.

    `context_tags` carries SCOPE labels only — ``src:private``, ``dst:public`` and the
    rest of `ranges.scope`'s vocabulary, role-prefixed the same way the asset
    registry prefixes its labels. The country code is NOT a tag; it has its own
    column, so an analyst filters on ``src_country = 'CN'`` rather than on an array
    containment against a GIN index.

    The array is SHARED with the asset resolver — `db._row` merges both sets into the
    one `events.context_tags` column. This object therefore never sees the asset
    labels and must not try to reconcile with them.
    """

    src_country: Optional[str] = None       # 2-char ISO 3166-1 alpha-2, UPPER
    dst_country: Optional[str] = None
    src_asn: Optional[int] = None
    dst_asn: Optional[int] = None
    context_tags: tuple[str, ...] = ()

    def is_empty(self) -> bool:
        """True when this event carries nothing worth storing.

        `db._geo_context` short-circuits on it to store NULLs from one named constant,
        so the "nothing resolved" row and the "resolver failed" row cannot drift into
        two different shapes of empty — the rule `_NO_CONTEXT` already enforces one
        column group over.

        `is not None` on the ASNs rather than a truth test: AS 0 is reserved
        (RFC 7607) and `geo.norm_asn` refuses it, but a value type should not depend
        on a validator elsewhere for its own emptiness to be correct.
        """
        return not (self.src_country or self.dst_country
                    or self.src_asn is not None or self.dst_asn is not None
                    or self.context_tags)


#: The "nothing at all" answer, returned by identity rather than rebuilt. An event
#: with no addresses is the common case on host telemetry, so this is the allocation
#: the ingest path skips several million times a day.
EMPTY_GEO = GeoResult()
