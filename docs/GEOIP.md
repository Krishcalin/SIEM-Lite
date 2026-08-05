# Geo & network enrichment

Where on the internet an address is — and whether it is on the internet at all —
resolved onto every event as it is stored.

Phase 3 slice 2 of the [transformation roadmap](SPLUNK_TRANSFORMATION_ROADMAP.md), and
the sibling of the [asset & identity registry](ASSETS.md). Same shape, same rules: it
resolves at ingest so a detection can gate on `src_country` while the event is still
streaming, and it carries the same obligation — a database side-loaded today does not
reach yesterday's rows until the backfill runs.

## What it is not

**There is no network here.** No reverse DNS, no WHOIS, no "just this once" HTTP fetch
of a database. Both of those are genuinely useful and both are **deliberately out of
this slice**, deferred to a later on-demand lookup that runs at *query* time, not on the
write path. The reason is not purity: this code runs inside the ingest write path, and a
network call there converts a slow resolver into unbounded backpressure on the queue
that feeds it. An air-gapped install must behave identically to a connected one.

**There is no new dependency.** `maxminddb` is not installed and never will be. The
MaxMind DB reader in `app/enrich/mmdb.py` is written from the published v2 format spec
against `struct`, `mmap` and `ipaddress`.

**City, latitude, longitude and the AS organisation name are not stored.** The reader
decodes them and they are thrown away. Nothing in the product reads them, and `events`
is the largest table in the system — three years of monthly partitions. A `text` city
column would cost more than the whole feature returns. A map view should join a lookup
at query time against the same database file rather than widen the fact table.

## What works with no data file at all

The **scope layer**, and it is the half every install gets. It is arithmetic over the
address, so it needs no database, no configuration and no network:

| label | covers |
|---|---|
| `private` | RFC 1918 |
| `cgnat` | RFC 6598 carrier-grade NAT |
| `loopback`, `link-local`, `multicast` | as defined |
| `documentation` | TEST-NET-1/2/3, `2001:db8::/32` |
| `reserved` | everything else IANA has withheld |
| `public` | routable |

These land in `context_tags` role-prefixed — `src:private`, `dst:public` — so they are
queryable through the **existing** GIN index from the moment this ships:

```
| search context_tags contains dst:public
```

> These tables are explicit RFC/IANA CIDR lists, **not** `ipaddress.is_private`. Two
> measured reasons. `is_private` lumps together what this has to separate — TEST-NET,
> loopback, link-local and reserved space all report `True`. And its answers *move
> between CPython patch releases* (gh-113171 moved CGNAT out of `_private_networks`).
> Deriving stored, backfilled columns from a vocabulary that shifts under a Python
> upgrade would silently reclassify history, and no fingerprint would flag it.

An address that will not parse yields **no label at all** — deliberately not `public`,
which would tag every event carrying a truncated field as internet-facing.

## What lands on an event

Four scalar columns, added to `events` as post-hoc `ALTER`s exactly the way the registry
columns are, plus a contribution to the shared array:

| column | value |
|---|---|
| `src_country`, `dst_country` | ISO 3166-1 alpha-2, upper-case, or NULL |
| `src_asn`, `dst_asn` | AS number, or NULL |
| `context_tags` | the scope labels above, **merged** with the registry's labels |

`src_asn` and `dst_asn` are **`bigint`, not `integer`**. An AS number is a 32-bit
*unsigned* value and RFC 6996 reserves 4200000000–4294967294 for private use — exactly
what an enterprise's internal BGP uses. Those overflow `int4`, and the resulting
`numeric_value_out_of_range` is raised from inside `executemany`, which costs the whole
insert chunk rather than the one row.

**No index is created on these four columns**, and that is a decision rather than an
oversight — the reasoning, and the condition that would reverse it, is written out in
`schema.sql` next to the `ALTER`s. In short: nothing queries them yet, the scope half is
already indexed through `context_tags`, and a country column is low-cardinality enough
that a btree is the wrong tool until a real query exists to measure.

### The shared array

`context_tags` is **one column with two producers**. The registry writes
`host:prod`, `src:pci`, `identity:vip`; geo writes `src:private`, `dst:public`.

Every writer — `db._row` at ingest, `db.backfill_assets` and `db.backfill_geo` — derives
the array through the single `db._derived_context`, so all three emit a byte-identical
result from identical inputs. If any two disagreed, a no-op backfill would see a
difference on every row and rewrite the entire heap, and whichever ran last would strip
the other's labels.

> **Label ownership is not recoverable from the text.** Geo's `src:public` is spelled
> exactly like the label an operator gets by naming a DMZ environment `public`. So
> neither backfill may strip "only its own" labels by matching a vocabulary — it would
> delete an operator's label or double-count it. Both backfills re-derive **both** sides
> and write the merged array, which makes ownership irrelevant rather than ambiguous.

## Side-loading a database

Three optional paths, all empty by default. Set none of them and the four columns stay
NULL — that is configuration, not a fault, and `/health` reports it as mode
`scope-only`.

```bash
GEO_RANGES_CSV=/srv/logocean/geo/ranges.csv          # the override layer
GEO_COUNTRY_DB=/srv/logocean/geo/GeoLite2-Country.mmdb
GEO_ASN_DB=/srv/logocean/geo/GeoLite2-ASN.mmdb
```

There is **no enable flag**, on purpose: the scope layer must never be switchable off by
accident. Pointing a variable at a file is what enables the country/ASN layer.

**Use absolute paths.** A relative path is resolved against the *process* working
directory, so one verified by hand at the repo root loads nothing under a systemd unit
or a container with a different `WorkingDirectory` — and it fails silently, with the
columns simply staying NULL. `/health` and `/api/v1/geo/status` publish both the
configured string **and** the absolute path each source resolved to, for exactly this.

### Where the databases come from

| source | file | gives |
|---|---|---|
| MaxMind GeoLite2 (free, account required) | `GeoLite2-Country.mmdb` | country |
| MaxMind GeoLite2 | `GeoLite2-ASN.mmdb` | ASN |
| DB-IP lite (CC-BY) | `.mmdb` or CSV | country |
| iptoasn.com (public domain) | TSV | ASN, country |

### The CSV format

Auto-detected: delimiter (`,` TAB `;` `|`), header-or-headerless, and which columns are
which. Ranges may be `cidr` **or** `start`/`end` pairs. Accepted header spellings
include `cidr`/`network`/`prefix`, `start_ip`/`ip_from`/`first_ip`,
`end_ip`/`ip_to`/`last_ip`, `country`/`country_iso_code`/`cc`, and
`asn`/`autonomous_system_number`. Unknown columns are ignored — these are vendor output,
not an operator-authored file. `AS13335` and `13335` both parse; AS 0 is dropped
(RFC 7607), and so is a `ZZ` country (the ISO "unknown" code, which would otherwise sit
in the column as a fake answer).

Two things worth knowing before you point it at something:

- **GeoLite2-*Country*-Blocks CSV is refused by name.** It carries `geoname_id` rather
  than ISO codes and is useless without joining the Locations CSV. Half-loading it would
  give an install that resolves nothing and reports no error.
- **Overlapping ranges are flattened, not refused** — narrowest wins, ties by file
  order, which is the same "most specific first" rule the asset registry applies to
  declared CIDRs. Bisection is only correct over disjoint ranges, and refusing the file
  outright would cost a site every country code it has over one bad pair of rows.

Give the file a header if you can. Headerless inference takes the first bare integer as
the ASN and a two-letter cell as a country code, so an AS org literally named `BT` would
read as Bhutan.

### Replacing a database

**On Windows a mapped file cannot be overwritten in place** — `os.replace` over it fails
with `WinError 5` while the service holds the mapping. Write the update as a **new file**
and repoint the variable, or restart. This is inherent to holding the mapping open, not
something the reload path could work around.

## Precedence

Sources are consulted **in order**, and each *field* is filled independently by the first
source that answers it. Country and ASN routinely come from different files — MaxMind
ships them as separate databases — so that is the normal path, not an edge case.

```
GEO_RANGES_CSV  →  GEO_COUNTRY_DB  →  GEO_ASN_DB
```

The CSV is **first** because an operator can edit a CSV and cannot edit a binary database
they downloaded; it is the only override layer available. The cost of that choice is
real: a stale CSV silently outranks a fresh GeoLite2. That is why `/health` reports each
layer's row count, mtime and build string — so it can be seen.

Lookups are **not** skipped for private addresses. Gating on `scope == 'public'` would
save a tree walk on the RFC 1918 traffic that dominates most stores, but it would also
make a CSV mapping internal ranges to site countries unreachable, which is a legitimate
use of the override layer. A bounded per-address memo absorbs the cost instead.

## API

`/api/v1/geo/*` is **read-only**, on the same grounds `/api/v1/registry/*` is: an
`api_keys` row carries no role, `require_api_key` accepts any enabled key, and `/api/` is
exempt from console session auth. There is no console write twin either — the sources are
*files*, named by environment variables and placed by whoever administers the host, which
is deliberately not something an HTTP request can change.

| endpoint | answers |
|---|---|
| `GET /api/v1/geo/status` | what is loaded, resolved paths, fingerprint, `backfill_due` |
| `GET /api/v1/geo/lookup?ip=` | *what would this address resolve to* |

`lookup` runs the **real** resolver against the live index, so it cannot drift from what
ingest would store. Pass `src_ip=` and `dst_ip=` to see both sides of a flow. Its
`normalized` field is the text the lookup actually used — after an IPv4-mapped address is
unwrapped and any `/prefix` dropped — which is usually the answer when a result looks
wrong.

## Backfill

A side-loaded database does **not** reach stored rows, and neither does this slice's
scope labelling reach rows ingested before it. `geo_meta` makes that visible instead of
silent: `/health` reports `backfill_due` and marks the deployment `degraded` until you
run

```python
db.backfill_geo()
```

Chunked, resumable (`start_id=<the returned last_id>`), and it skips rows whose context is
unchanged — so a re-run is nearly free rather than rewriting every heap tuple it touches.
It re-derives through **the same `geo.resolve`** the ingest path uses, never a set-based
SQL equivalent that would be a second implementation of scope classification and
precedence.

It also re-derives the **asset** labels, because it rewrites the shared array — the mirror
of the geo re-derivation `backfill_assets` performs. The two converge in either order.
Neither touches the other's scalar columns.

Only a run that is **both unbounded and completed** advances the stamp. A windowed or
`max_rows`-bounded run has left rows underived, and stamping it would answer "history is
current" over a store that is half migrated.

`backfill_due` is measured against the fingerprint of the sources **as they are now**,
recomputed from the live index — not against the stored `geo_hash`, which is refreshed
only on load and would answer "history is current" for exactly as long as a side-loaded
file had been ignored.

> **One difference from `asset_meta`.** `asset_status` can answer "nothing is declared,
> so nothing is owed". Geo has no such state: scope labels derive with no data file, so
> an empty index is a real derivation with a real fingerprint, and the same guard would
> report a permanent backfill-owed on every fresh install. Instead the *first* stamp on a
> database whose `events` table is still empty seeds `backfill_hash` — a fresh install
> has no history to correct — while an upgrade, which does have rows predating these
> columns, is left unstamped and correctly reports the work as owed.

The fingerprint covers what can change an answer: which sources, in which order, each
one's absolute path, size, mtime and build string, plus a derivation version that is
bumped when the label vocabulary in `app/enrich/geo.py` changes. It is deliberately
**not** a content hash of the file — GeoLite2-City is ~70 MB and hashing it on every
startup would buy only the `cp -p` case.

## Degradation

Context is never worth an event. Every failure below stores the row and costs it only its
geo columns:

| failure | what happens | where it shows |
|---|---|---|
| no database configured | columns NULL | `/health` mode `scope-only` — not degraded |
| a configured file will not load | that layer absent, others still load | `errors` on `/health` |
| the settings fields are missing entirely | geo can never find anything | `errors` — it is otherwise indistinguishable from a healthy install |
| `ranges.py` fails to import | **every** row loses its scope labels | `scope_available: false` — nothing else reports it |
| a resolver defect | four columns NULL, counter increments | `write_state.failures` |

A per-source lookup failure is caught per address and counted rather than logged per
event: unlike a transient database outage, a corrupt `.mmdb` is a *static file* that will
fail identically on every single row, so unrate-limited logging would flood at full
ingest rate. The first failure is logged in full, then every thousandth.

`geo.reload()` does **not** raise for a bad file — a source that will not parse becomes a
value on `index.errors` and the rest of the index still loads and is cached. A *failed*
reload keeps the previous index rather than replacing it with an empty one, because
silently stripping country and ASN from every subsequent event would produce rows that
look resolved-to-nothing rather than unresolved, and an empty index's fingerprint is a
perfectly valid fingerprint that no staleness check would flag.

## Layout

| file | role |
|---|---|
| [`app/enrich/models.py`](../app/enrich/models.py) | frozen value type: `GeoResult` |
| [`app/enrich/ranges.py`](../app/enrich/ranges.py) | built-in scope classification. No data file |
| [`app/enrich/mmdb.py`](../app/enrich/mmdb.py) | MaxMind DB v2 reader. Pure functions over bytes |
| [`app/enrich/csvdb.py`](../app/enrich/csvdb.py) | the CSV range table — the editable override layer |
| [`app/enrich/geo.py`](../app/enrich/geo.py) | the index (precedence, caching) and the resolver. Pure |
| `app/db.py` | `_derived_context` (the merge), the `geo_meta` stamp, `backfill_geo` |

## What is verified against a real PostgreSQL

[`tests/test_integration_geo.py`](../tests/test_integration_geo.py) is the DB-level gate.
Every assertion in it re-queries the database rather than trusting the return value of the
function that did the writing. It covers what no DB-free test can:

* the four `ALTER TABLE` columns apply and **recurse into every month partition**;
* `src_asn` / `dst_asn` really are `bigint` — an RFC 6996 private-use ASN (4200000000)
  round-trips, and the same statement against an `integer` column was measured raising
  `NumericValueOutOfRange` from inside `executemany`, taking the whole chunk with it;
* `_GEO_STAMP_UPSERT`'s `CASE WHEN %(seed)s::boolean` binds as intended — both arms;
* `geo_meta` creates, seeds on a fresh install and stays NULL on an upgrade;
* the **`context_tags` merge**, on a freshly ingested row *and* on a backfilled one, in
  both backfill orders — neither producer's labels are lost;
* `backfill_geo` re-derives from a psycopg `inet` **object** (not a string), including the
  IPv4-mapped form;
* neither backfill rewrites an already-correct row — proven with `xmin`, Postgres's own
  record of the heap tuple, rather than with the counter the backfill computes for itself;
* the whole operator side-load path: a real CSV on disk → `Settings` → `geo.reload()` →
  a stored `events` column, plus the missing-file case landing in `/health`.

### Verified against databases MaxMind actually built

The reader is a binary-format parser written from the published v2 spec, with no
`maxminddb` to check it against. Its own test file round-trips through a writer *this
project also wrote* — which proves the offset chain is internally coherent and cannot
prove it agrees with a real file, because **a reader and a writer that misunderstand
the format the same way round-trip perfectly**. A wrong answer there is not a crash; it
is a plausible wrong country on a stored event.

So [`tests/test_mmdb_conformance.py`](../tests/test_mmdb_conformance.py) asserts known
answers against MaxMind's own published test databases:

| checked | against |
|---|---|
| all three record sizes (24 / 28 / 32-bit) | `MaxMind-DB-test-ipv4-*.mmdb` |
| `81.2.69.160` → **GB**, registered **US** | `GeoIP2-Country-Test.mmdb` |
| `89.160.20.112` → **SE**, registered **DE** — the two differ, which pins `_from_mmdb_record`'s precedence on a real record | `GeoIP2-Country-Test.mmdb` |
| `2a02:d300::1` → **UA** (IPv6) | `GeoIP2-Country-Test.mmdb` |
| `1.128.0.1` → **AS1221 Telstra Pty Ltd** | `GeoLite2-ASN-Test.mmdb` |
| every data type, incl. `uint128`, float-vs-double precision and `unicode! ☯ - ♫` | `MaxMind-DB-test-decoder.mmdb` |
| the full chain: setting → `_open_mmdb` → `MMDBReader` → GeoLite2 record shape → resolved column | both databases |

The 28-bit split — the middle byte whose nibbles feed two different records, and the
likeliest bug in any from-spec reader — is covered by MaxMind's own fixture for it.

**The databases are not vendored.** They are MaxMind's files, and this repo carries no
third-party data. The CI integration job fetches them and fails the build if the fetch
breaks, because a conformance suite that silently skips is worse than one that does not
exist — the reader would *look* verified. Locally, point `MMDB_TEST_DATA` at a directory
of them; the module docstring has the two-line fetch.

### What is still not verified

The **CSV loader's vendor fixtures are synthesized** from the documented formats rather
than taken from a downloaded DB-IP or iptoasn file. The parsing rules are measured — every
one is executed against those fixtures, including the unrouted-leading-row case that used
to delete the country column for a whole file — but a real export could still carry a
header spelling, a quoting quirk or an encoding nobody anticipated. When a real range CSV
is available, `RangeTable.load()` it and check `len()`, `stats()` and a handful of known
answers before trusting the column.

Loading a 400,000-row ASN table takes about 5 seconds and ~250 MB peak, dominated by
`ipaddress` parsing. That is a one-time startup cost, but it is visible in service start
time and there is no size bound on an operator-supplied file.
