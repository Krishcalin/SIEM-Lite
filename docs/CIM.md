# CIM — LogOcean's Common Information Model

CIM is LogOcean's versioned, vendor-agnostic **data-model layer** — Backbone #2 of the
[Splunk transformation roadmap](SPLUNK_TRANSFORMATION_ROADMAP.md), and the companion to
[LOQL](LOQL.md). A **data model** is a named schema (`Authentication`, `Network`, `Web`,
…) plus a **membership rule** that decides which normalized events belong to it, so a
detection or a search binds to *what an event is* instead of *who made the box*:

```
| datamodel Authentication | stats count by user, action     # LOQL
datamodels: web                                              # a detection rule
SELECT * FROM cim_ics WHERE is_write = 'true'                # SQL
```

Onboarding a new source into a model is a **registry edit** (`app/cim/models.yaml`) — no
code change, no schema migration.

- [How membership works](#how-membership-works)
- [The eleven shipped models](#the-eleven-shipped-models)
- [Querying a data model](#querying-a-data-model)
- [Binding a detection rule](#binding-a-detection-rule)
- [The registry — `models.yaml`](#the-registry--modelsyaml)
- [Adding a model](#adding-a-model)
- [Operator runbook](#operator-runbook)
- [Migration note — Windows Security dedup](#migration-note--windows-security-dedup)
- [Settings](#settings)
- [Internals](#internals)

## How membership works

Membership is **materialized on the event row**. `events.cim_models` is a plain
`text[]` column, filled per row **in Python at ingest** from `app.cim.match.tags_for(evt)`
— exactly the way `search_tsv` is filled from `normalize.tsv_text(evt)`:

```
parse → NormalizedEvent → db._row()  ┬─ "tsv":        tsv_text(evt)
                                     └─ "cim_models": cim_models_for(evt)   →  INSERT
```

An event in no model stores **`NULL`, not `'{}'`**, so the GIN index stays proportional to
tagged rows. The tags in a row are sorted alphabetically, so reordering `models.yaml` never
churns stored values.

```sql
-- schema.sql
ALTER TABLE events ADD COLUMN IF NOT EXISTS cim_models text[];
CREATE INDEX IF NOT EXISTS events_cim_models_idx ON events USING GIN (cim_models);
```

Every read path uses the same index-usable containment predicate:

```sql
cim_models @> ARRAY['authentication']::text[]
```

### Why it is NOT a generated column

The obvious design — `cim_models text[] GENERATED ALWAYS AS (…) STORED` — is a dead end
here, for two independent reasons. Both are load-bearing, so they are written down rather
than rediscovered:

1. **PostgreSQL 16 freezes a generation expression at `ADD COLUMN`.** Rewriting one needs
   `ALTER COLUMN … SET EXPRESSION`, which is **PostgreSQL 17+**, and `docker-compose.yml`
   pins `postgres:16`. A generated column would therefore have made every future edit to
   `models.yaml` unreachable on an existing database — the exact opposite of a
   data-not-code registry. (Dropping and re-adding the column rewrites the whole heap and
   destroys the values in the meantime.)
2. **Detection needs membership *before* the `INSERT`.** `pipeline.write_stream` evaluates
   every event against the rules as it streams, while rows are only flushed to the table
   in chunks — so a rule bound to a data model would have nothing to read. Evaluating in
   Python gives detection, ingest and backfill **one evaluator**, not two.

`app.cim.sql.membership_sql(model)` still emits the equivalent SQL predicate and stays
runnable as the readable *spec* of membership (and for ad-hoc audit queries) — but
`app.cim.match` is the authoritative evaluator. The two read the same frozen
`app.cim.spec` objects; the three deliberate points where they differ (whitespace
stripping, jsonb array subscripts, container values) are tabulated in the `app/cim/match.py`
module docstring.

### One view per model

`db.init_cim()` runs on every startup and rebuilds one **`cim_<tag>` view** per model,
projecting the model's CIM field names over its members:

```sql
CREATE VIEW cim_authentication AS
SELECT id, event_time, action AS "action", app AS "app", host(src_ip) AS "src",
       host_name AS "dest", host_name AS "dvc", user_name AS "user",
       rule_name AS "signature", severity AS "severity",
       concat_ws(':', vendor, product) AS "vendor_product",
       vendor, product, log_type, message, raw
FROM events
WHERE cim_models @> ARRAY['authentication']::text[]
```

The projection is: `id`, `event_time`, the model's fields, then whichever of `vendor`,
`product`, `log_type`, `severity`, `message` a field name has **not** taken (here
`severity` is a field, so it is not repeated), then `raw` for drill-down. `src_ip`/`dst_ip`
are `inet`, so a column source emits `host(col)`.

Views are DROP + CREATE (a `fields:` edit changes the projection list, which
`CREATE OR REPLACE` cannot do), applied **one transaction per model**, and views of models
that no longer exist are dropped. The per-model boundary is deliberate: run as a single
transaction, one operator-owned object depending on one `cim_<tag>` view made a blocked
`DROP` (SQLSTATE 2BP01) roll back *all eleven* views, on every restart, for ever. The
model — not the statement — is the retry unit, because a failed `DROP` leaves the old view
and the `CREATE` that follows would then fail with 42P07. A blocked model keeps its
previous definition, is logged naming the view, and appears in `init_cim`'s `failed` list
and on `/health.cim.views_failed`; the others still refresh. Every output label is
**double-quoted, unconditionally** — an
unquoted `user_name AS user` is accepted by `CREATE VIEW`, but a later bare `SELECT user`
parses as `CURRENT_USER` and returns the connection role on every row. Quoting everything
avoids keeping a keyword list in step with the server version; for an already-lower-case
identifier a quoted label and a bare folded one are the same column.

> `cim_` is a **reserved view namespace**: `init_cim` drops any view matching
> `^cim_[a-z][a-z0-9_]*$` — exactly what `sql.view_name` emits — that is not a current
> model tag. A view named `cimbogus` or `CIM_Report` is left alone. The drop is
> deliberately **without CASCADE** and runs in its own savepoint, so if you built
> something on top of `cim_authentication` the drop fails, is logged, and startup
> continues — rather than silently deleting your object.

## The eleven shipped models

Nine are populated by the parsers that ship today; **Email and Vulnerability are empty by
design** and say so on `/datamodels` — they are the schema those models will project once
a mail-gateway or a scanner source onboards, not broken detections.

| Model | Tag / view | What belongs to it | CIM fields |
|---|---|---|---|
| **Authentication** | `authentication`<br>`cim_authentication` | Any `log_type` in signin/authentication/auth/authpriv; all Okta system-log; Windows Security event ids 4624/4625/4634/4647/4648/4768/4769/4771/4776/4740; auditd `USER_*`; M365 `UserLoggedIn`/`UserLoginFailed`; FortiGate `type=event` login/logout; Cisco IOS `SEC_LOGIN` and ASA AAA message ids | `action` `app` `src` `dest` `dvc` `user` `signature` `severity` `vendor_product` |
| **Network** | `network`<br>`cim_network` | traffic/forward/flow/conn/netflow/vpn/decryption/firewall; the nine OT protocols; Cisco ASA/Firepower/IOS; PAN-OS *type* `TRAFFIC` (any subtype); FortiGate *type* `traffic` | `action` `src` `dest` `src_port` `dest_port` `transport` `app` `bytes` `user` `dvc` `rule` `vendor_product` |
| **Web** | `web`<br>`cim_web` | access/http/url/urls/webfilter/proxy — Apache+Nginx, Zeek/Suricata HTTP, PAN URL-filtering, Meraki, FortiGate webfilter, CEF proxy | `action` `src` `dest` `dest_port` `user` `url` `http_method` `status` `http_user_agent` `site` `app` `vendor_product` |
| **DNS** | `dns`<br>`cim_dns` | dns / dns-query / dnsquery | `src` `dest` `query` `record_type` `answer` `user` `dvc` `vendor_product` |
| **Endpoint** | `endpoint`<br>`cim_endpoint` | all Sysmon; all CrowdStrike Falcon; process/file/registry/image-load/pipe/driver kinds, auditd `execve`/`syscall`, FIM `file-audit`/`fileintegrity`/`file`; Windows Security 4688/4689 | `action` `dvc` `user` `process` `process_name` `parent_process` `file_name` `registry_path` `process_hash` `signature` `src` `dest` `vendor_product` |
| **Change** | `change`<br>`cim_change` | config/audit/api_audit/activity; GitHub, GitLab, CloudTrail, GCP Cloud Audit, Azure + O365, Nutanix Prism audit; Windows account-management + 1102; PAN-OS SYSTEM subtype `general` (commit / content-update) | `action` `object` `command` `user` `src` `dvc` `status` `signature` `severity` `vendor_product` |
| **Malware** | `malware`<br>`cim_malware` | ransomware-alert/wildfire/virus/malware/quarantine; Falcon `detection`; Nutanix Data Lens | `action` `signature` `file_name` `file_hash` `category` `user` `dest` `src` `severity` `vendor_product` |
| **IDS** | `ids`<br>`cim_ids` | alert/ids/ips/threat/intrusion/waf; PAN-OS THREAT subtypes vulnerability/spyware/flood/scan/packet (virus + wildfire go to Malware, url to Web) | `action` `signature` `category` `severity` `src` `dest` `dest_port` `transport` `user` `dvc` `vendor_product` |
| **Industrial** | `ics`<br>`cim_ics` | the nine `app/ot.py:OT_PROTOCOLS` — modbus, dnp3, s7comm, cip, enip, bacnet, iec104, opcua, profinet — after `zeek_ics.enrich()`. **Also members of Network.** No Splunk CIM equivalent; this one is LogOcean's | `protocol` `operation` `is_write` `action` `function_code` `unit_id` `register` `quantity` `src` `dest` `src_port` `dest_port` `session_id` `vendor_product` |
| **Email** | `email`<br>`cim_email` | **empty by design** — email/smtp/mail/exchange/message-trace, forward-looking | `action` `src` `dest` `src_user` `recipient` `subject` `user` `signature` `vendor_product` |
| **Vulnerability** | `vulnerability`<br>`cim_vulnerability` | **empty by design** — a scanner vendor (qualys/tenable/rapid7/nessus/openvas/nexpose) AND a vulnerability `log_type`. Both halves are required on purpose: a firewall IPS detection is *not* a scanner finding | `signature` `cve` `severity` `dest` `dvc` `category` `user` `vendor_product` |

**Multi-model membership is normal.** An OT session is `['ics', 'network']`; a Falcon
detection is `['endpoint', 'malware']`; a CloudTrail `ConsoleLogin` is
`['authentication', 'change']`.

Measured over all 34 bundled `samples/` files (97 parsed events), membership is:
authentication 15 · network 32 · web 6 · dns 4 · endpoint 19 · change 17 · malware 5 ·
ids 6 · ics 11 · email 0 · vulnerability 0 — **3 events carry no tag** (a schemaless
generic-JSON flow record with no type key at all, a `local0` application syslog line, and a
LEEF cross-source correlation meta-alert). Those are genuinely unclassifiable shapes, not
registry gaps.

`/datamodels` renders all of this live from the registry, with an opt-in **Count members
(30d)** button.

## Querying a data model

### LOQL

Two spellings, one AST — `parse("| datamodel Web") == parse("from datamodel:Web")`:

```
| datamodel Authentication | stats count by user, action | sort -count
from datamodel:Authentication action=failure | top 10 src
from datamodel:ics | stats count by protocol, operation
```

The model name is a **display name or a tag, case-insensitively** (`Industrial` ==
`ics` == `INDUSTRIAL`), and it must be the **first** stage. A search predicate rides on
the `from datamodel:X …` form only — with the `| datamodel X` spelling, filter in an
explicit later stage (`| datamodel X | search action=failure`, or `| where …`).

Inside a data model the field vocabulary *is* the model's (`user`, `src`, `dest`,
`signature`, …). Unmapped jsonb keys still work via schema-on-read, but a normalized
`events` column the model **replaced** (`user_name`, `src_ip`, `bytes_total`, …) is a
**hard error** naming what is available — left to schema-on-read it would compile fine and
answer NULL in every row, which reads as "there were no such events". See
[docs/LOQL.md](LOQL.md#cim-data-models).

### SQL

`SELECT * FROM cim_<tag>` returns the same shape the LOQL source produces — the model's
fields, then the passthroughs `vendor`, `product`, `log_type`, `severity`, `message` that a
field name has not taken, then `raw`, with `id` and `event_time` in front.

The one difference is the tail: the view ends with `raw`, while `| datamodel X` **carries**
`raw` and `search_tsv` through its stages (so schema-on-read still reaches unmapped keys)
and returns neither as a result column. Subtracting `raw` makes the two lists identical,
which is asserted per model against a live database by
`test_cim_view_and_loql_datamodel_project_the_same_columns` — the two projections come from
independent emitters (`cim.sql.create_view_ddl` and the LOQL compiler's `_cim_select`), so
the parity is checked rather than assumed.

```sql
SELECT "user", src, action FROM cim_authentication WHERE action = 'failure';
SELECT protocol, operation, register FROM cim_ics WHERE is_write = 'true';
```

### Membership only

```sql
SELECT * FROM events WHERE cim_models @> ARRAY['endpoint']::text[];   -- GIN-indexed
```

## Binding a detection rule

Add `datamodels:` (or the singular alias `datamodel:`) to any per-event rule:

```yaml
id: lo-web-sqli-example
title: SQL injection attempt in a web request
datamodels: web                 # a tag …
# datamodels: Web               # … or the display name
# datamodels: [web, ids]        # … or several: ANY of them (OR)
# datamodel:  web               # … singular alias, same thing
detection:
  sel:
    message|contains: ["union select", "' or 1=1"]
  condition: sel
```

Semantics, all deliberate:

| Binding | Behaviour |
|---|---|
| **omitted** | unbound → match-all. Every rule written before this gate behaves exactly as it did, and a pack with no bound rules pays **nothing** — the registry is never walked. |
| **several models** | **ANY** of them, following the engine's convention that a value list is an OR. |
| **with `logsource:`** | **AND**ed. Both are narrowing filters: "this kind of event, from that source". |
| **a name that resolves to nothing** | the rule is **DEAD**, not match-all — a typo must never silently widen a detection to every event. `tests/test_rule_quality.py` fails CI on it. |
| **on a `correlation:` rule** | rejected by the linter. Correlation rules filter in SQL via `db.correlate` and never reach `match_rule`, so a binding there would silently do nothing. |

Membership is resolved **at most once per event** and shared by every bound rule.
The CIM layer is failure-contained three ways: a broken registry degrades to "no
registry" (one log line, not a dead pipeline), a registry that raises during evaluation
degrades to "no tags", and a dead binding disables that one rule. Nothing can reach
`evaluate_event`.

**Shipped conversions** (5 rules): the four `T1190` web-exploitation rules
(`web_sql_injection`, `web_path_traversal`, `web_command_injection`, `web_xss_attempt`)
dropped their hand-rolled `log_type: [access, http]` selection for `datamodels: web` — and
became strictly more correct, since the Web model also covers PAN URL filtering, Meraki
`urls`, FortiGate `webfilter` and CEF `proxy`, where a SQLi was previously invisible.
`ot_it_to_ot_write` dropped `log_type: [modbus, dnp3, s7comm, cip, enip]` for
`datamodels: ics`, which is the canonical **nine** protocols — so a BACnet / IEC-104 /
OPC-UA / PROFINET write crossing the IT→OT boundary is now caught too.

`ot_cip_write` was deliberately **not** converted: its `log_type: [cip, enip]` selection is
protocol-specific by design, and binding it to `ics` would let its `ot.is_write` selection
fire on Modbus.

`workbench.test_rule()` returns `datamodel_ok` alongside `logsource_ok`, plus `datamodels`
(what the rule binds to) and `event_datamodels` (what the sample event actually is) — so a
miss can be reported as "you bound to `web`, this event is `network`" rather than "no
match". The `/workbench` page renders this next to the existing `logsource` signal — but
only for a rule that actually declares `datamodels:`, since an unbound rule is match-all
and a permanent "ok" badge would be noise.

## The registry — `models.yaml`

`app/cim/models.yaml` is **data**. It is loaded and fully validated at startup by
`app.cim.registry.load()`; a typo fails loudly there instead of becoming broken SQL or a
silently-empty data model later.

```yaml
version: 1
models:
  - name: Authentication          # display name (LOQL / rules resolve it)
    tag: authentication           # membership token + view name cim_authentication
    version: 1
    description: >
      Login / logon / SSO / credential-validation activity …
    membership: [ … ]             # OR of clauses (see below)
    fields:    [ … ]              # the projected schema (see below)
```

A model's `name` and `tag` share **one key space** (`by_name` resolves names first, then
tags), so they must not collide across the registry. `DNS`/`dns` is fine — that is one key.

### Fields

Exactly one source key per field. Names must match `^[a-z][a-z0-9_]*$`, be unique within
the model, and may not be one of the **reserved** names `id` / `event_time` / `raw` /
`search_tsv` / `cim_models`. `description:` is optional. A field is simply **null** for a
source that does not provide it — exactly as in Splunk CIM.

The reserved list is every column a projection emits *unconditionally*, so a field of the
same name would be a duplicate column. `search_tsv` is on it even though the `cim_<tag>`
view does not project it: the LOQL `| datamodel` source carries `raw, search_tsv` on every
row-level stage, so a field called `search_tsv` loaded cleanly, built a valid view, and
then failed the next bareword search with `42702 column reference "search_tsv" is
ambiguous`. The list is *derived* from the projection's own column tuples rather than
restated, so adding a passthrough column reserves its name in the same edit — and
`| fields raw` and friends are refused on the LOQL side by the same tuple (see
[LOQL.md](LOQL.md#two-names-you-cannot-output-raw-and-search_tsv)).

```yaml
fields:
  - {name: src,    column: src_ip}                     # a normalized events column
  - {name: kind,   const: ics}                         # a fixed string
  - {name: vp,     expr: vendor_product}               # a whitelisted named SQL snippet
  - {name: q,      raw: query}                         # ONE top-level jsonb key
  - {name: orig,   raw: id.orig_h}                     # STILL one key — dots are never split
  - {name: query,  raw: [query, QueryName, dns_query]} # ordered alternatives → COALESCE
  - {name: cat,    raw: [[alert, category], category]} # a nested path, then a flat key
  - {name: op,     raw: [[ot, operation]]}             # a SINGLE nested path = a list of a list
```

`column:` accepts any `events` column (`src_ip`/`dst_ip` are `inet`, emitted as
`host(col)`). `expr:` accepts only whitelisted named snippets — today just
`vendor_product` → `concat_ws(':', vendor, product)`.

### Membership

`membership:` is a **list of clauses**. An event belongs to the model when **ANY** clause
matches (OR); within a clause **EVERY** term must match (AND). Comparison is
case-insensitive on both sides.

```yaml
membership:
  # short form — the KEY is the source
  - {log_type: [security], vendor: [microsoft]}
  - {raw:event_id: [4624, 4625]}                      # "raw:" prefix = ONE literal jsonb key

  # long form — the VALUE is a mapping; the key becomes a free-form label
  - vendor: [microsoft]
    product: [windows]
    event_id:
      raw: [event_id, EventID, "Event ID", Id, [Event, System, EventID]]
      values: [4624, 4625]
  - proto: {column: log_type, values: [modbus, dnp3]}
  - op:    {raw: [[ot, operation]], values: [write, control]}
  - log_type: {values: [security]}                    # no source key → the LABEL is the source,
                                                      # so it must be a term column or "raw:<key>"
```

- `values:` is **required** in the long form.
- A term may read a **column** — one of `vendor`, `product`, `log_type`, `severity`,
  `action`, `protocol`, `app`, `user_name`, `host_name` — or **any** jsonb key.
  `const:` and `expr:` are rejected in terms.
- Values must be **quoted strings or integers**. Bare `yes` / `no` / `on` / `off` /
  `true` / `false` / `null` are YAML 1.1 booleans and `None`, and are **rejected on load**
  (they used to compile to `'true'`/`'false'`/`'none'` and match nothing, forever). Strings
  are stripped and lower-cased.
- **Duplicate mapping keys anywhere in the file are a hard error.** PyYAML silently keeps
  the last, so two `event_id:` terms in one clause would quietly lose one — and a lost
  membership term is invisible, because an empty data model looks exactly like "there were
  no such events".

### Multi-key and nested sources

This is the syntax you actually need when extending the registry, because vendors spell
the same concept differently and some of them nest it.

**Alternatives vs nesting are distinguished structurally, never by a delimiter:**

| YAML | Compiles to | Means |
|---|---|---|
| `raw: EventID` | `(raw ->> 'EventID')` | one top-level key |
| `raw: id.orig_h` | `(raw ->> 'id.orig_h')` | **still one key** — Zeek writes literal dotted top-level keys |
| `raw: [EventID, event_id]` | `COALESCE((raw ->> 'EventID'), (raw ->> 'event_id'))` | ordered alternatives, first non-null wins |
| `raw: [[alert, category]]` | `(raw #>> ARRAY['alert', 'category'])` | a single **nested path** — a one-element list of a list |
| `raw: [[alert, category], category]` | `COALESCE((raw #>> ARRAY['alert','category']), (raw ->> 'category'))` | nested, then flat, in one COALESCE |

A **top-level list is alternatives**; a **list nested inside it is a segment list**. A
jsonb key is NEVER split on `.` — dot-splitting would break every Zeek mapping and
silently empty the Network model. Nesting has to be spelled out, which is why a segment
list is a list and not a dotted string. Both operators are `IMMUTABLE`.

Quoted keys containing a space work (`"Event ID"`); the Python evaluator walks one dict
level per segment (a non-dict on the way down yields no value for that alternative only)
and the SQL uses an `ARRAY[…]` constructor rather than an `'{a,b}'` array literal, so a key
containing a space, comma or brace can never break out of array-literal quoting.

### Honesty rules the shipped file is held to

Verified by parsing every file in `samples/` with its real parser and evaluating the
clauses:

1. Every clause matches ≥1 event in the sample corpus, or is annotated `# unsampled`
   (a real parser path with no sample) or `# forward-looking` (a source LogOcean does not
   parse yet).
2. No clause tests a **vendor alone** — vendor is always paired with product, log_type,
   action or a jsonb key.
3. No clause keys on a value a parser cannot emit. Note especially that
   `paloalto_syslog.py` / `paloalto_csv.py` / `fortinet_fortigate.py` put the **subtype**
   in `log_type` (end / deny / vulnerability / forward), so the PAN and FortiGate clauses
   read the real *type* out of `raw` — which is what makes them subtype-proof.
4. On a populated model, a field mapping no member source can ever provide is deleted
   rather than shipped null-by-construction.

## Adding a model

1. Append a `- name: … tag: … version: 1 description: … membership: … fields: …` block to
   `app/cim/models.yaml`. Keep the `tag` distinct from every other model's name *and* tag.
2. Restart. `db.init_cim()` creates `cim_<tag>`; the model appears on `/datamodels`, in
   LOQL `| datamodel <Name>`, and as a valid `datamodels:` binding.
3. Run the **membership backfill** (below) so events already in the store get the new tag.

Nothing else needs to change — no Python, no schema migration, no test edit. The LOQL test
`test_every_registered_model_compiles` walks the live registry, so a new model is covered
automatically.

## Operator runbook

The whole operator story is two rules:

| You edited | To apply | Events already stored |
|---|---|---|
| **`fields:`** (the projection) | **restart** — `db.init_cim` drops and recreates the views | correct as soon as the views are rebuilt: a field is computed **on read** from `raw` and the columns, so nothing is re-derived per row |
| **`membership:`** (who belongs) | **restart, then run the backfill** | **stale until the backfill runs** — `events.cim_models` was stamped under the old rule. New events are correct from the next ingest |

**Run it:** *Admin* → **Backfill membership** (admin-gated, audited as `cim.backfill` /
`cim.backfill.finished`). It runs in the background and redirects immediately — it is
`UPDATE` traffic across every partition, so holding the request open would hand you a
gateway timeout instead of an answer. One run at a time; a second click is refused and
audited as `cim.backfill.denied`.

Programmatically:

```python
from app import db
res = db.backfill_cim()                # keyword-only: chunk, start_id, max_rows, since, until
# res -> {"scanned":…, "updated":…, "unchanged":…, "chunks":…, "last_id":…,
#         "done":…, "full_pass":…, "registry_version":…, "seconds":…}
db.backfill_cim(start_id=res["last_id"])   # resume an interrupted or bounded run
```

It re-derives every row **in Python** (one evaluator — a set-based
`UPDATE … WHERE membership_sql()` would be a second one, and the two are documented as
differing in three places), is keyset-paginated and committed per chunk (bounded WAL,
resumable), and **skips rows whose tags are unchanged** — so a re-run after a cosmetic
edit is zero writes.

**How you know it is due.** `cim_meta` holds one row stamping which registry the views
were built from and which one the stored `cim_models` values were derived under, using a
**membership fingerprint** (a sha256 over a canonicalized rendering of every term, sorted
at each level). It changes iff the membership *rule set* changes — not when someone
reorders `models.yaml`, and not for a `fields:`-only edit. `db.cim_status()["backfill_due"]`
is `True` when they diverge, and a red banner appears on `/datamodels` and `/admin`.
The stamp is advanced **only by an unbounded, completed run** — a bounded pass must never
claim history is current.

**Restart required, and why the order matters.** `get_registry()` parses and validates
`models.yaml` **once per process** and caches it for the process lifetime — nothing
re-reads the file while the app runs. So an edit is not live until a restart, and
`db.cim_status()` reports the two questions separately:

| Key | Means | Fix |
|---|---|---|
| `restart_required` | the file on disk no longer matches the registry this process loaded at boot | restart |
| `backfill_due` | the rows already stored were tagged under a different membership rule than the one on disk | `backfill_cim`, **after** the restart |

`backfill_due` is measured against the **file**, not the cached registry, and that is
load-bearing: measured against the cache, an edit made before the restart is invisible
(old-vs-old compares equal), and a backfill run in that window would re-derive every row
under the **old** rule and then stamp `backfill_hash` with the old fingerprint — reporting
history as current under a rule that had never been applied to a single row. Hence the
banner on `/admin`: **restart first, then backfill.**

`GET /health` reports
`{"cim": {"enabled", "registry_version", "applied", "views", "views_failed", "error",
"backfill", "untagged_events", "write_error"}}`, plus a top-level `status` of `ok` or
`degraded` and a `degraded` list naming each reason. The HTTP status stays **200** either
way — the process is alive and answering, and pulling it out of rotation over a reporting
view would turn a partial outage into a total one.

**If the DDL fails** (a bad `fields:` entry), the app still starts and still ingests
correctly — the views are read-side only, and membership is stamped in Python. What
degrades is `SELECT * FROM cim_<tag>`, `| datamodel …` and `/datamodels`, and `/health`
says so. `db.init_cim` applies each model in **its own transaction**, so one model's
failure (typically SQLSTATE 2BP01: an operator-owned view depends on `cim_<tag>`) costs
that view alone and the other ten still refresh; the failures are listed in
`/health.cim.views_failed` and on `/datamodels`. Nothing is ever dropped with `CASCADE`.

**A models.yaml that will not *parse*** is handled differently again, and the split is
deliberate:

* **Startup refuses to boot.** `main._require_cim_registry()` → `db.validate_cim_registry()`
  runs as the *first* statement of the lifespan, before the database is touched, and
  **unconditionally** — including under `CIM_ENABLED=false`, because that flag gates the
  `cim_<tag>` views only and never the per-row stamp. `models.yaml` ships with the repo,
  so a registry that will not parse is a deploy error and the YAML author's own message at
  boot is the most useful thing the process can produce.
* **The write path degrades and never raises.** If the registry breaks *after* boot (a
  live edit plus `cim.reload()`), `db._cim_tags` stores the event with `cim_models = NULL`
  and counts it in `db.cim_write_state()` instead of aborting the insert. This reverses an
  earlier argument that the write path should "fail loudly" because a wrongly-tagged event
  is silent, durable corruption. The premise holds — which is why the failure is counted,
  surfaced on `/health` as `untagged_events` and repairable with `backfill_cim` — but the
  conclusion did not: `streaming._flush` answers *any* exception from the write by
  discarding the buffered batch, so a raising `_row` turned one bad YAML file into
  permanent, silent loss of every syslog and API event. An untagged row is visible and
  repairable; a dropped event is neither.
* **The failure is remembered, not re-suffered.** The degraded write path above calls
  `get_registry()` **once per event**, and success-only caching meant a registry that
  would not parse left the cache empty and re-parsed the 27 KB file for every event —
  serialized behind a process-global lock. The handler became the outage. `get_registry()`
  therefore caches the *failure* too: the first caller parses and raises, and callers
  inside the next `_FAILURE_TTL_SECONDS` (**30 s**) get the same error replayed without
  touching the file. Each one gets a fresh exception object carrying the original type and
  message — the same object re-raised would grow its own traceback without bound.
* **Recovery needs no restart.** The negative entry is time-boxed rather than permanent,
  so an operator who fixes `models.yaml` is picked up within the window on its own.
  `cim.reload()` drops the entry outright and re-reads immediately, which is the explicit
  version of the same thing; a `reload()` that fails in turn re-arms it, because the
  ingest path is about to resume calling per event.

**Datamodel-bound detection rules follow the same shape, one layer up.** The detection
engine resolves the registry once and reuses the handle for every event, so a rule with
`datamodels:` never re-resolves per event. A *failed* resolution used to be permanent —
one bad moment switched every bound rule off until someone restarted the process — and is
now retried on its own 30 s wall, with both transitions logged exactly once (the failure
at ERROR, the recovery at WARNING). While it is down, only the bound rules are disabled;
every other rule keeps firing.

The two walls are independent and sit **in series**, which is worth knowing when you are
watching a fix land: the engine's retry is usually answered from the registry's remembered
failure rather than a re-parse (cheap), but because the engine's wall is armed fractionally
first, a fixed file is picked up in **30–60 s** rather than 30. It is bounded and
self-correcting. To skip the wait, `cim.reload()` **then** restart or reset — `reload()` is
the half that drops the registry's entry, and nothing else can.

## Migration note — Windows Security dedup

**One-time, affects `app/parsers/windows_security.py` only.**

To make the Windows membership clauses reachable at all, the parser now writes the
resolved Event ID back into the record as `raw["event_id"]` (an **int**, so
`raw ->> 'event_id'` renders the canonical digit string `4688` — a CSV cell exported as
`"04688 "` would not have matched). Every export shape spells it differently (`Id`,
`EventID`, `Event ID`); the vendor's own key is copied through byte-for-byte untouched and
the canonical key is only *added* beside it. When no id can be resolved, no key is added
at all.

**The consequence:** `app.normalize.dedup_hash` hashes `json.dumps(evt.raw, sort_keys=True)`,
so every Windows Security event now has a **different `dedup_hash`** than the same event
ingested before this change. Re-uploading a previously-ingested Windows Security export
will **INSERT duplicates** instead of deduping via `events_dedup_idx`.

**What to do:** delete the old batch first (Admin → batches), or accept the duplicates. No
other parser's `raw` shape changed, and going forward dedup works normally.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `CIM_ENABLED` | `true` | Gates the **database-side half only** — the per-model `cim_<tag>` views. Membership tagging at ingest is not optional; detections and LOQL read the column. |
| `CIM_COUNT_DAYS` | `30` | Window for the opt-in member counts on `/datamodels` (lets the planner prune partitions). `0` disables counting. |
| `CIM_COUNT_TIMEOUT_MS` | `5000` | Budget for the **whole** count sweep, not per model — the page can never hang for one timeout per data model. |
| `CIM_BACKFILL_CHUNK` | `2000` | Rows per committed chunk of the Admin backfill. |

## Internals

```
app/cim/
  spec.py        frozen dataclasses — the contract. CimSource / CimField / CimTerm /
                 CimClause / CimModel / CimRegistry / CimError. No SQL, no I/O.
  registry.py    load + validate models.yaml into that contract (get_registry / reload).
                 Rejects YAML-1.1 booleans, duplicate mapping keys, duplicate field names,
                 and name/tag collisions.
  match.py       the runtime evaluator — tags_for(evt) / cim_models_for(evt), plus the
                 readable reference walk term_matches / clause_matches / model_matches.
                 Pure; both paths bottom out in one function so a term can only ever be
                 decided one way.
  sql.py         the ONLY place CIM becomes SQL: source_sql / field_value_sql /
                 membership_sql / membership_predicate / create_view_ddl / ddl_statements.
  models.yaml    the registry (data).
```

Consumers: `db._row` (ingest stamping) · `db.init_cim` / `db.backfill_cim` /
`db.cim_status` (DDL + history + drift) · `loql.compiler` (`| datamodel`) ·
`detection.engine` (`datamodels:`) · `main.py` (`/datamodels`, `/admin/cim/backfill`,
`/health`) · `workbench.test_rule`.

**Membership is resolved once per ingested event.** It is wanted twice — by the detection
`datamodels:` gate as the event streams, and by `db._row` when the chunk flushes — so
`pipeline.write_stream` walks the registry once and threads the answer to both:
`db.insert_events(conn, chunk, batch_id, cim_tags=[...])` and
`engine.evaluate_event(evt, tags=...)`. `cim_tags` is index-aligned with the events and
`None` at a position means "unresolved, derive this one"; a length mismatch is a
`ValueError` rather than a silent shift. Both parameters are optional and are probed with
`inspect.signature` once per batch, so any caller that omits them — the backfill, a test
double, an older build — still derives membership itself.

One subtlety worth keeping: when the pipeline's own resolution raises, it threads `None`
and **not** an empty set. `None` sends the event to `db._cim_tags`, which owns the
degraded write and counts it; a confident `frozenset()` would be stored as "belongs to no
model" and `/health` would report zero untagged events while every row went in untagged.

The whole layer is **DB-free and unit-testable**: `models.yaml` loads, membership
evaluates, and the view DDL is emitted without a PostgreSQL anywhere. Only `db.py` touches
the database.

## Not yet

- **`cim_email` and `cim_vulnerability` are empty** until an email-security or
  vulnerability-scanner source onboards (roadmap Phase 2). They are defined and ready.
- **Correlation rules are not datamodel-bound** — they filter in SQL via `db.correlate`,
  which reads normalized columns, not `cim_models`.
- **No CIM tag/eventtype layer beyond membership** — `tags:`/`eventtypes:` as separate
  addressable objects, `rex`/`spath` and macros are still roadmap Phase 1 items.
- **No acceleration** — `| datamodel X | stats …` scans the (GIN-indexed) members. The
  rollup layer that would make it a `tstats` substitute is roadmap Phase 7.
