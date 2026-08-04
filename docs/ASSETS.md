# Asset & identity registry

Declared business context, resolved onto every event as it is stored.

Phase 3 slice 1 of the [transformation roadmap](SPLUNK_TRANSFORMATION_ROADMAP.md). It
answers three questions a SIEM cannot answer from the log data alone — *whose machine
is this, how much does it matter, and is anyone watching it?* — and it answers them at
ingest, so a detection can gate on criticality while the event is still streaming and
Phase 4's risk scoring has a multiplier to read.

## What it is not

There is already an `entities` table. It is **observational**: one row per actor seen
in the data, created automatically at ingest, whose `first_seen` is exactly what UEBA's
"new entity" anomaly reads.

The registry is **declared** — what an operator says about a host or a person. The two
are deliberately separate tables and are joined only at resolution time. Folding them
together would let a CSV import rewrite a baseline that a detection depends on, and
would make "is this asset declared?" unanswerable, because every observed value would
also be a row.

## The shape

| table | holds |
|---|---|
| `assets` | criticality, category, owner, business unit, environment, watchlist |
| `asset_aliases` | `(alias_type, alias_value) → asset_id` |
| `identities` | priority, department, manager, title, watchlist |
| `identity_aliases` | `(alias_type, alias_value) → identity_id` |

Aliases live in their own table rather than as array columns because *that* is the
lookup: resolution is a single primary-key hit, not a scan with an array-containment
predicate. The primary key is also the collision guard — two assets claiming one
hostname is refused by the database rather than resolved by whichever row is read
first, which is the difference between a registry and a guess.

Asset aliases: `hostname`, `fqdn`, `ip`, `cidr`, `mac`.
Identity aliases: `email`, `upn`, `sam`, `employee_id`, `cn`.

## What lands on an event

Five columns, added to `events` as post-hoc `ALTER`s exactly the way `cim_models` is:

| column | value |
|---|---|
| `asset_id`, `asset_criticality` | the **subject** asset |
| `identity_id`, `identity_priority` | resolved from `user_name` |
| `context_tags` | GIN-indexed, role-prefixed labels from **every** side that resolved |

The subject asset is resolved `host_name → src_ip → dst_ip`. `host_name` first because
it names the machine the event is *about*; `src_ip` before `dst_ip` because where only
addresses are present the source is the actor.

For a flow between two declared hosts that ordering is a genuine choice, and the losing
side would be invisible if the subject column were the only output. It is not:

```
| search context_tags contains dst:crown-jewel
```

still finds traffic **to** a crown jewel on a row whose subject is the source. Splunk ES
carries roughly twenty `src_*`/`dest_*` columns for this; on a table that retains three
years of partitions those columns are the expensive choice, so both sides fold into one
indexed array and only the subject gets scalar columns.

> **Why denormalize at all**, rather than joining `assets` at query time: a detection
> rule must be able to gate on criticality while the event is still streaming through
> the pipeline, before any row exists to join to. That is the same constraint that made
> `cim_models` a plain column, and it carries the same obligation — see *Backfill*.

## Alias resolution

`jdoe`, `CORP\jdoe` and `john.doe@corp.example` resolve to one identity, if the
operator declared them. **The registry never guesses at a third.**

Everything in `app/assets/normalize.py` is identity-preserving — case, whitespace,
address form, separator style:

- hostnames and emails lower-cased; a dotted name yields the FQDN *and* its short label
- addresses through `ipaddress`, so `10.1.1.1` and `010.1.1.1` cannot be two aliases of
  two different assets — and an IPv4-mapped `::ffff:10.1.1.1` unwraps to `10.1.1.1`,
  which dual-stack sockets and JVM servers emit constantly
- `AA-BB-CC-DD-EE-FF`, `aabb.ccdd.eeff` and `aa:bb:cc:dd:ee:ff` all become one MAC
- `CORP\JDoe` → `corp\jdoe`, **domain preserved** — dropping it would merge one domain's
  `jdoe` with a partner's

The one thing that looks like a free win and is deliberately absent: an email's local
part is never offered as a username. `jdoe@partner.example` resolving to the internal
`jdoe` would attribute an outside party's actions to an employee, in the table a
detection reads to decide who to alert on. A wrong merge here does not degrade
gracefully.

Exact aliases beat containment, and the most specific CIDR wins:

```
ip    10.1.2.50    → srv-db-01     (declared individually — beats the subnet)
cidr  10.1.2.0/24  → office-net
cidr  10.0.0.0/8   → corp-wide     (10.1.2.7 belongs to the /24, always)
```

## Backfill

A registry edit does **not** reach stored rows. `asset_meta` is what makes that visible
instead of silent: `/health` reports `backfill_due` and marks the deployment `degraded`
until you run

```python
db.backfill_assets()
```

Chunked, resumable (`start_id=<the returned last_id>`), and it skips rows whose context
is unchanged — so a re-run after a no-op edit is nearly free rather than rewriting every
heap tuple it touches.

It re-derives through **the same `assets.resolve`** the ingest path uses, never a
set-based SQL equivalent. A SQL twin would have to re-implement candidate extraction,
the most-specific-CIDR rule and the subject precedence, and any drift between the two
would surface as a corrected row differing from an identically-shaped freshly ingested
one, for no reason visible to anybody. `backfill_cim` documents the same rule.

`backfill_due` is measured against the fingerprint of the registry **as it is now**,
recomputed from the live tables — not against the stored `registry_hash`, which is
refreshed only on load and would answer "history is current" for exactly as long as an
edit had been ignored.

The fingerprint covers only what can change a resolution: criticality, category,
watchlist, environment, `enabled`, and the aliases. Editing an owner or a note does not
demand a full re-derive.

## Degradation

Context is never worth an event. If the registry cannot be read, `assets.get_index()`
returns an empty index, the row stores `NULL` context, and `/health` says so — the same
policy `db._cim_tags` follows for CIM membership. A failed *reload* keeps the previous
index rather than replacing it with an empty one, because silently stripping context
from every event during a database blip would produce rows that look
resolved-to-nothing rather than unresolved, and no staleness check would flag them.

## Layout

| file | role |
|---|---|
| [`app/assets/models.py`](../app/assets/models.py) | frozen value types |
| [`app/assets/normalize.py`](../app/assets/normalize.py) | what "the same identifier" means |
| [`app/assets/index.py`](../app/assets/index.py) | the in-memory lookup, incl. CIDR containment |
| [`app/assets/resolve.py`](../app/assets/resolve.py) | event → Resolution. Pure, shared with the backfill |
| [`app/assets/registry.py`](../app/assets/registry.py) | loading from the tables, and caching |
| `app/db.py` | CRUD, the `asset_meta` stamp, `backfill_assets` |
