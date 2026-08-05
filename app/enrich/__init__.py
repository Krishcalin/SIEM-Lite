# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Enrichment — facts derived from the event itself, with no network and no service.

Phase 3 slice 2. Answers "where on the internet is this address, and is it even ON the
internet?" at ingest time, so a detection can gate on ``src_country`` while the event
is still streaming and an analyst can filter a three-year store on a scalar column
instead of a regex over the message.

    from app.enrich import geo
    res = geo.resolve(evt, geo.get_index())
    res.src_country, res.src_asn, res.context_tags

OFFLINE BY CONSTRUCTION. No sockets: reverse DNS and WHOIS are explicitly out of scope
and deferred to a later on-demand slice. Country and ASN come from a database file the
operator side-loads; scope classification comes from arithmetic and needs no file at
all, which is why an install that side-loads nothing still gets ``src:private`` /
``dst:public`` labels on every row.

STDLIB ONLY. `mmdb.py` is a MaxMind DB reader written from the published format spec
against `struct`/`mmap`/`ipaddress` — the point being that `maxminddb` is not a
dependency of this project and never will be.

Layout:

| module      | role                                                             |
|-------------|------------------------------------------------------------------|
| `models.py` | frozen value types: GeoResult                                    |
| `mmdb.py`   | MaxMind DB v2 binary reader. Pure functions over bytes.          |
| `ranges.py` | built-in special-purpose range classification. No data file.     |
| `csvdb.py`  | a CSV range table — the hand-editable override layer            |
| `geo.py`    | the index (precedence, caching) and the resolver. Pure.          |

`mmdb`, `ranges` and `csvdb` are NOT re-exported here. `app/db.py` imports this
package on the ingest path, so a sibling module that fails to import must not take the
package — and with it the writer — down; `geo.py` imports each one where it is used
and degrades if it is missing.
"""
from .geo import (EMPTY_INDEX, GeoIndex, GeoSource, canonical_tags, generation,
                  get_index, literal_source, mmdb_source, norm_asn, norm_country,
                  range_source, reload, resolve, set_index, stats)
from .models import EMPTY_GEO, GeoResult

__all__ = [
    "EMPTY_GEO", "EMPTY_INDEX", "GeoIndex", "GeoResult", "GeoSource", "canonical_tags",
    "generation", "get_index", "literal_source", "mmdb_source", "norm_asn",
    "norm_country", "range_source", "reload", "resolve", "set_index", "stats",
]
