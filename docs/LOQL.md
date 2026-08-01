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

## Commands (batch 1)

| Command | Purpose | Example |
|---------|---------|---------|
| *(search)* | Filter — the implicit first stage | `vendor=paloalto action=deny status>=400` |
| `where` | Filter by an expression | `... | where length(user_name) > 3` |
| `eval` | Compute a new field | `... | eval mb = bytes_total / 1048576` |
| `fields` | Keep (or `-` drop) columns | `... | fields src_ip, user_name` |
| `rename` | Rename a column | `... | rename user_name as user` |
| `sort` | Order (`-` desc, `+`/none asc) | `... | sort -bytes_total` |
| `head` | Keep the first N | `... | head 20` |
| `dedup` | Keep the first row per key | `... | dedup src_ip` |
| `stats` | Aggregate, optionally `by` groups | `... | stats count, dc(user_name) by vendor` |
| `top` | Most common values (+ percent) | `... | top 10 src_ip` |
| `rare` | Least common values | `... | rare 10 action` |
| `timechart` | Aggregate into time buckets | `... | timechart span=1h count by severity` |
| `bin` | Bucket `_time` into a span | `... | bin span=5m _time` |

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

## Examples

```
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

`eventstats` / `streamstats` / `transaction` (window verbs), `rex` / `spath`, macros,
`lookup`, and `from datamodel:<CIM>` — see the transformation roadmap. Unquoted wildcard
values and dotted field paths (`a.b.c`) also land in a later batch; quote values and use
`raw` sub-keys via `spath` when it ships.
