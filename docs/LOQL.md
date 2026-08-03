# LOQL — LogOcean Query Language

LOQL is LogOcean's piped search/transform language (Splunk-SPL-shaped) — Backbone #1 of
the [Splunk transformation roadmap](SPLUNK_TRANSFORMATION_ROADMAP.md). A query is a
pipeline of stages separated by `|`; each stage compiles to **parameterized SQL** over
the month-partitioned `events` table.

```
vendor=paloalto action=deny | stats count as n by src_ip | sort -n | head 10
```

**Why it's safe:** every value, jsonb key, and glob you type becomes a *bound parameter* —
the compiler emits only fixed SQL skeletons, so a malformed or hostile query is a clean
`400`, never SQL injection. The compiler is a pure function (`app/loql/compiler.py`),
unit-tested by asserting the SQL it emits.

## Run it

`POST /api/v1/query` (API-key auth, same as `/api/v1/ingest`):

```bash
curl -X POST http://host:8000/api/v1/query -H "X-API-Key: lo_..." \
     -H "Content-Type: application/json" \
     -d '{"query": "vendor=fortinet action=deny | top 10 src_ip", "limit": 500}'
# -> {"fields":[...], "rows":[...], "count":N, "elapsed_ms":M, "truncated":false}
```

Guardrails (config `LOQL_*`): a per-query `statement_timeout` (`LOQL_TIMEOUT_MS`, 30s), a
hard row cap (`LOQL_MAX_ROWS`, 100k), and a default result `LIMIT` (`LOQL_DEFAULT_LIMIT`,
1000) — so one heavy query can't starve ingest on the shared Postgres.

> **Maintainer note — the timeout is applied with `SELECT set_config('statement_timeout',
> %s, true)`, never `SET LOCAL statement_timeout = %s`.** psycopg3 binds server-side, so
> the latter reaches PostgreSQL as `SET LOCAL statement_timeout = $1`, and `SET` is a
> *utility* statement whose grammar has no parameter slot — it fails to parse with SQLSTATE
> 42601 before the query itself is ever sent. That is not a corner case: it made **every**
> LOQL query fail, and it shipped undetected because the integration job was reporting
> green while executing zero tests. `set_config(text, text, bool)` is an ordinary function
> in an ordinary `SELECT`, so it binds normally; the value goes as **text** (an int gets
> 42883 "no function matches"), and the third argument `true` is the `is_local` flag —
> i.e. the `SET LOCAL` half of the intent, so the timeout cannot leak onto a pooled
> connection. Before parameterizing any new utility statement here, check it against
> PostgreSQL's utility-statement list.

## Fields

Field names are the `events` columns: `event_time` (alias `_time`), `vendor`, `product`,
`log_type`, `severity`, `action`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`,
`app`, `user_name`, `host_name`, `rule_name`, `bytes_total`, `message`.

**Schema-on-read:** any *other* field name is read from the raw event JSON
(`raw ->> 'name'`), so you can query fields no column exists for — e.g. `errorCode=0` or
`stats count by eventName`.

**Values** with spaces or special characters (IPs, paths, wildcards) must be quoted:
`src_ip="10.0.0.1"`, `url="/admin*"`. Bare words are string values (`vendor=cisco`) or,
with no operator, a full-text term (`failed login`).

**Reserved and mixed-case names are handled for you.** A field or output label that
collides with a PostgreSQL keyword (`user`, `time`, `left`, …) or that is not all
lower-case is emitted **double-quoted**, at every site — the `AS` label *and* the next
stage's reference to it. So `| rename user_name as user | stats count by user` works and
means the column, not `CURRENT_USER`; and `stats count by eventName` comes back in the
API's `fields` array as `eventName`, not folded to `eventname`. Ordinary identifiers stay
bare.

### Two names you cannot output: `raw` and `search_tsv`

Every **row-level** stage carries two columns beside its own — `raw` (the original event
JSON, which is what schema-on-read reads from and what drill-down shows) and `search_tsv`
(the full-text vector a bareword search matches). They are plumbing rather than fields:
they are not listed in the `fields` array and you never name them to get them.

Because they ride along on every row, a stage that *labels* one of them would emit two
columns of that name, and the next reference is ambiguous. So the compiler rejects the
label up front:

```
vendor=okta | fields raw
vendor=okta | eval raw = 1
vendor=okta | rename vendor as raw
vendor=okta | bin span=1h _time as search_tsv
```

each fail with

> `fields cannot output a column named 'raw' - every row-level stage carries 'raw',`
> `'search_tsv' beside its own columns (the raw event and its full-text vector), so a`
> `second column of that name is ambiguous to every stage after this one; read a key out`
> `of the raw event by naming the key, or pick another label`

To read *inside* the raw event, name the key — that is what schema-on-read is for
(`| stats count by eventName`), not `| fields raw`.

**After an aggregation the restriction lifts,** because there is no longer a raw event to
carry: `| stats count as raw by vendor` is legal, and so is anything downstream of it.

`| fields - raw` is accepted and does nothing, exactly like dropping any name that is not
a column — the carried columns are not in the column list, so there is nothing to remove.

### `eval` and the time axis

`timechart` and `bin` need a real timestamp column, and `eval` can take one away or hand
one over. Both directions are tracked:

```
... | eval t = _time | where t > "-24h"      # t is still a timestamp — relative literals work
... | eval event_time = vendor | timechart span=1h count
# -> timechart needs the _time field, which an earlier stage removed or overwrote
#    with a non-timestamp value (available: …)
```

The rule is the one `stats by` already uses: the result keeps the source column's type
only when the expression **is** that column. Anything computed (arithmetic, concat, a
function) is text, boolean or numeric, and is no longer a time column.

### `sort` and the stages after it

`ORDER BY` is rendered against the column list as it stands at the **end** of the
pipeline, not where the `sort` was written, so later stages have to keep the sort key
reachable. Three outcomes, all decided at compile time:

| After a `sort` | Result |
|---|---|
| `rename` the sort key | the order **follows the rename** — `\| sort -bytes_total \| rename bytes_total as bt` orders by `bt` |
| `fields` that drops the sort key | **compile error**: `fields would remove 'bytes_total', which the preceding sort orders the result by - add it to the fields list, or sort by a field you are keeping` |
| `stats` | the sort is **dropped** — the aggregate builds a new set of columns, so sort *after* it (`\| stats count as n by src_ip \| sort -n`) |
| `timechart` / `top` / `rare` | dropped and **replaced by the stage's own** order — `_time` ascending, `count` descending, `count` ascending respectively |

The error is the useful case: left alone it compiled to an `ORDER BY` naming a column the
final projection no longer had, which PostgreSQL rejects at execution time as the
analyst's mistake rather than the query's.

## Commands (batch 1)

| Command | Purpose | Example |
|---------|---------|---------|
| *(search)* | Filter — the implicit first stage | `vendor=paloalto action=deny status>=400` |
| `where` | Filter by an expression | `... \| where length(user_name) > 3` |
| `eval` | Compute a new field | `... \| eval mb = bytes_total / 1048576` |
| `fields` | Keep (or `-` drop) columns | `... \| fields src_ip, user_name` |
| `rename` | Rename a column | `... \| rename user_name as user` |
| `sort` | Order (`-` desc, `+`/none asc) | `... \| sort -bytes_total` |
| `head` | Keep the first N | `... \| head 20` |
| `dedup` | Keep the first row per key | `... \| dedup src_ip` |
| `stats` | Aggregate, optionally `by` groups | `... \| stats count, dc(user_name) by vendor` |
| `top` | Most common values (+ percent) | `... \| top 10 src_ip` |
| `rare` | Least common values | `... \| rare 10 action` |
| `timechart` | Aggregate into time buckets | `... \| timechart span=1h count by severity` |
| `bin` | Bucket `_time` into a span | `... \| bin span=5m _time` |
| `datamodel` | Source a CIM data model (first stage only) | `from datamodel:Authentication` |

**Search operators:** `=` `!=` `<` `<=` `>` `>=`, `like`, `in (a, b, c)`, `and` / `or` /
`not`, parentheses, and implicit `AND` between terms. `=`/`!=` against a value containing
`*`/`?` becomes a wildcard match. Time comparisons understand relative literals:
`_time > "-24h"`, `_time >= "now"`.

**`stats`/`timechart`/`top` functions:** `count` · `count(field)` · `sum` · `avg` · `min`
· `max` · `dc` (distinct-count) · `values` · `list`. Name outputs with `as`:
`stats count as hits by host_name`.

**`where`/`eval` expressions:** arithmetic `+ - * / %`, string concat `.`, comparisons,
`and`/`or`/`not`, `in`, and functions `lower upper length abs round ceil floor trim
coalesce substr replace if(cond,a,b) isnull isnotnull`.

## CIM data models

Instead of searching `events` directly, a query can source a **CIM data model** — a
versioned, vendor-agnostic schema. Two spellings, one parse tree
(`parse("| datamodel Web") == parse("from datamodel:Web")`):

```
| datamodel Authentication | stats count by user, action | sort -count
from datamodel:Authentication action=failure | top 10 src
from datamodel:"Industrial" | stats count by protocol, operation
```

The name is a display name **or** a tag, case-insensitively (`Industrial` == `ics`), and
it must be the **first** stage. `| datamodel X` is only legal after a bare match-all, so
`vendor=okta | datamodel X` is refused — and a search predicate cannot ride on the
`| datamodel` stage itself. To filter, either use the `from` form
(`from datamodel:X action=failure`) or add an explicit stage
(`| datamodel X | search action=failure`, or `| where …`). Eleven models ship:
Authentication, Network, Web, DNS, Endpoint, Change, Malware, IDS, Industrial, Email,
Vulnerability.

Inside a data model the **field vocabulary is the model's**: Authentication gives you
`user`, `src`, `dest`, `dvc`, `action`, `signature`, `app`, `severity`, `vendor_product`
(plus `vendor`, `product`, `log_type`, `message`, `raw`). Unmapped jsonb keys still work
via schema-on-read. But a normalized `events` column the model **replaced** —
`user_name`, `src_ip`, `bytes_total`, … — is a **hard error** listing what is available,
rather than a schema-on-read miss that would compile fine and answer NULL in every row.

The compiled source filters on the GIN-indexed membership column with the **tag bound**
like every other value:

```sql
SELECT id, event_time, …, user_name AS "user", … , raw
FROM events WHERE cim_models @> ARRAY[%s]::text[]
```

The projection mirrors `SELECT * FROM cim_<tag>` exactly, so a LOQL data-model query and
the model's SQL view return one shape. Full reference: [docs/CIM.md](CIM.md).

> `datamodel=X` as a *predicate* is unaffected — it is still an ordinary schema-on-read
> field comparison, not a source.

## Examples

```
# failed logons per user, across every identity source that maps to the model
from datamodel:Authentication action=failure | stats count as fails by user | sort -fails

# OT writes to controllers, by protocol
from datamodel:ics | where is_write = "true" | stats count by protocol, action

# brute force: sources with many failed logons in the last day
action="failed-logon" _time > "-24h" | stats count as fails by src_ip | where fails > 20 | sort -fails

# noisiest firewall rules by traffic
vendor=paloalto | stats sum(bytes_total) as bytes by rule_name | sort -bytes | head 15

# hourly deny volume per vendor
action=deny | timechart span=1h count by vendor

# rare admin actions (schema-on-read on a raw field)
eventName="*Admin*" | top 20 userIdentity
```

## Not yet (batch 2+)

`eventstats` / `streamstats` / `transaction` (window verbs), `rex` / `spath`, macros, and
`lookup` — see the transformation roadmap. Unquoted wildcard values and dotted field paths
(`a.b.c`) also land in a later batch; quote values and use `raw` sub-keys via `spath` when
it ships. There is also **no UI search box for LOQL yet** — it is reachable via
`POST /api/v1/query` and the `/datamodels` member counts; `/search` still uses the
filter-based form.

`from datamodel:<CIM>` **shipped** with Backbone #2 — see [CIM data models](#cim-data-models).
