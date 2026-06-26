# CLAUDE.md — SIEM-Lite / LogOcean

Guidance for Claude Code (and other agents) working in this repository.

## What this is

**LogOcean** — a self-hosted log parser, indexer, and long-term store for
**network, endpoint, cloud, and identity** logs from many vendors (**23 parsers**,
see `app/parsers/`). Logs arrive three ways — manual **web upload**, the
**HTTP ingest API** (`POST /api/v1/ingest`), or the **syslog receiver**
(UDP/TCP/TLS) — and all share one parse → normalize → store pipeline. The app
parses, normalizes, full-text indexes, and stores events in PostgreSQL with a
**≥ 3-year retention** policy.

Being grown toward a Wazuh-like SIEM (agentless): Phase 1 (live ingestion),
Phase 2 (Sigma-based **detection & alerting**), Phase 3 (**notifications &
agentless response**), and Phase 4 (**agentless collectors & feeds**) are
complete — ingested events are evaluated against detection + correlation rules,
raising alerts you triage in the UI (`/alerts`); newly-raised alerts are sent to
notification channels and can trigger response playbooks (audited at `/responses`);
and scheduled collectors pull vendor logs (Okta/GitHub/GitLab, AWS CloudTrail,
Entra ID, Microsoft 365) while other tools push findings via the ingest API. Phase 5 adds **built-in auth + RBAC**
(`AUTH_ENABLED`; roles admin/analyst/viewer, server-side sessions), an **audit
log**, and **compliance coverage** (`/compliance`: MITRE→PCI/NIST/CIS/HIPAA).

- **Stack:** Python 3.12, FastAPI + Uvicorn, Jinja2 (server-rendered UI),
  PostgreSQL 16 via `psycopg` 3 (+ `psycopg_pool`), `python-dateutil`.
- **Repo:** https://github.com/Krishcalin/SIEM-Lite · **License:** see `LICENSE`.
- **Run:** `docker compose up --build` → http://localhost:8000 (Postgres + app).

## Architecture / data flow

Three inputs share one core. `pipeline.py` is the source-agnostic
parse→normalize→insert path; upload, the HTTP API, and the syslog receiver each
add their own batch lifecycle around it.

```
 upload (web) ───────────────┐
 POST /api/v1/ingest (key) ──┤─► detect.py ─► parsers/<vendor>_<fmt>.py ─► NormalizedEvent
 syslog UDP/TCP/TLS ─► queue ┘        ─► pipeline.write_stream ─► normalize.py (dedup + FTS)
                                       ├─► db.insert_events ─► events (month-partitioned, GIN)
                                       └─► detection engine (per event) ─► alerts ─► /alerts
 scheduler (every CORRELATION_INTERVAL) ─► correlation rules (SQL over events) ─► alerts
```

Live sources (syslog) buffer in a bounded async queue (`streaming.py`) drained by
writer workers that batch-insert; queue counters are on `GET /health`. One
normalized schema across all sources; the **full original record is always kept**
in `events.raw` (jsonb) so nothing is lost and any field stays searchable.

**Detection** (`app/detection/`) runs two ways: per-event rules (Sigma-subset)
are evaluated inline in `pipeline.write_stream` as events are stored, and
correlation/threshold rules are evaluated on a schedule by SQL aggregation over
`events`. Both raise rows in `alerts` (deduped per rule+event / rule+group+window).
Rules live in `rules/*.yml`; the `detection_rules` table tracks enablement.

**Alert actions** (`app/alert_actions.py`) fan each *newly-raised* alert (gathered
post-commit via `insert_alerts(return_inserted=True)`) to two background workers:
`notify` (webhook/email channels, filtered by `NOTIFY_MIN_LEVEL`) and `response`
(agentless playbooks in `playbooks/*.yml` — a webhook POST to your automation/SOAR
endpoint or a `log` action, audited in `response_actions`). Both run on their own
threads so slow network I/O never blocks ingest.

**Collectors** (`app/collectors/`) are agentless pull connectors: a scheduler runs
each enabled, credential-configured collector every `COLLECTOR_INTERVAL`, fetching
new records since a stored `cursor` (the `collectors` table) and feeding them
through `ingest.ingest(..., source_type="collector")` — so pulled logs get the same
detect/alert/respond treatment. Token sources (Okta/GitHub/GitLab) live in
`sources.py`; signed/OAuth sources in `cloud.py` — **AWS CloudTrail** (`LookupEvents`,
SigV4-signed via stdlib `hmac`/`hashlib`), **Entra ID** sign-ins (Microsoft Graph) and
**Microsoft 365** unified audit (Office 365 Management Activity API), the latter two
using the OAuth2 client-credentials flow. Each collector re-shapes vendor JSON into the
exact form its parser expects; all signing/URL/response logic is in pure, unit-tested
functions (network isolated in `_http_get`/`_http_post`). Inbound *push* feeds (other
tools → the ingest API) use `clients/logocean_push.py`.

## Repository layout

```
app/
  main.py        FastAPI routes + UI (dashboard, upload, search, event, admin) + lifespan
  api.py         HTTP ingest API: POST /api/v1/ingest (API-key auth)
  config.py      env-driven settings (DB_DSN, RETENTION_YEARS, INGEST_*, SYSLOG_*, ...)
  models.py      NormalizedEvent dataclass (the common schema)
  auth.py        password hashing (pbkdf2) + role ranking + require_role dependency
  compliance.py  MITRE technique -> framework control mapping + coverage report
  util.py        tolerant parse_ts / clean_ip / to_int; hash_api_key / extract_api_key
  detect.py      best-effort vendor+format auto-detection
  normalize.py   dedup_hash() + tsv_text()
  pipeline.py    source-agnostic core: parse_events / apply_fallback_time / write_stream
  ingest.py      per-batch orchestration (sha, batch, source tagging) around pipeline
  streaming.py   bounded async ingest queue + batching writer workers (backpressure)
  db.py          pool, schema/partition mgmt, insert, search, stats, purge, api_keys, alerts
  receivers/
    syslog.py    UDP/TCP/TLS syslog receiver -> queue (RFC 6587 framing)
  detection/
    engine.py    Sigma-subset evaluator (per-event): flatten, match, condition grammar
    correlation.py  threshold/window rules over events (SQL) + background scheduler
    runtime.py   load rules, sync the registry, hold the engine singleton
  alert_actions.py  fan newly-raised alerts to notifications + response
  notify/        channels.py (webhook/email) + dispatcher.py (background thread)
  response/      engine.py — agentless playbooks + audit log (background thread)
  collectors/    base.py + sources.py (Okta/GitHub/GitLab) + cloud.py (AWS SigV4 /
                 Entra+M365 OAuth) + runner.py (scheduler)
  parsers/       paloalto_csv, paloalto_syslog, fortinet_fortigate, cisco_asa, cisco_ios,
                 meraki, zeek_tsv, zeek_json, crowdstrike_csv, crowdstrike_json,
                 windows_security, suricata_eve, cef, generic_syslog, generic_json,
                 aws_cloudtrail, gcp_audit, azure_activity, m365_audit, entra_signin,
                 okta_system_log, github_audit, gitlab_audit  (23 total)
  templates/     base, dashboard, upload, search, event, alerts, alert, responses,
                 compliance, admin, login
  static/style.css
rules/           detection + correlation rules (Sigma-subset YAML)
playbooks/       agentless response playbooks (match + action YAML)
clients/         logocean_push.py — copy-into-your-tool helper to push to the API
schema.sql       events, ingest_batches, api_keys, alerts, detection_rules,
                 response_actions, collectors, users, sessions, audit_log
samples/         one example file per format (used by tests)
tests/           test_parsers, test_api_auth, test_streaming, test_syslog, test_detection,
                 test_pipeline, test_correlation, test_notify, test_response, test_collectors
docker-compose.yml, Dockerfile, requirements.txt, .env.example
```

## Conventions (follow these when extending)

- **Every parser** exposes `parse(content: str) -> Iterator[NormalizedEvent]` and is
  registered in `app/parsers/__init__.py` (`PARSERS` + `FORMAT_LABELS`). The format
  key is what the UI dropdown and `detect.py` return (e.g. `paloalto_csv`).
- **Normalize, don't lose data.** Map what you can onto `NormalizedEvent`'s common
  fields and put the entire original record in `raw`. CSV/JSON field resolution uses
  a *candidate-name* helper (`_g(row, "name1", "name2", ...)`, case-insensitive) so
  parsers tolerate header/shape differences across versions and export types.
- **Timestamps:** always go through `util.parse_ts` (handles epoch s/ms/µs, ISO, and
  vendor date strings; returns aware UTC). `ingest.py` falls back to upload-time and
  tags `raw["_parse_note"]` if a row has no parseable timestamp — rows are never dropped.
- **Severity** is stored as the human-readable **name** (`Critical`/`High`/... ,
  `critical`/`informational`) for cross-vendor consistency — CrowdStrike parsers
  prefer `SeverityName` over the numeric `Severity`.
- **IPs** are validated with `clean_ip` (invalid → NULL) and stored in `inet` columns;
  SQL casts them explicitly (`%(src_ip)s::inet`).
- **SQL safety:** all user input is parameterized; never string-format user values
  into SQL. Partition names are computed from timestamps (not user input), so the
  f-string DDL in `db.ensure_partitions` is safe.

## Storage & retention (important)

- `events` is `PARTITION BY RANGE (event_time)`; partitions are **monthly**
  (`events_YYYYMM`), created on demand at ingest, with an `events_default` catch-all.
  Time-range searches prune to the relevant months.
- Indexes are declared on the **parent** table so they propagate to all partitions:
  GIN on `search_tsv` (full-text) and `raw` (jsonb), btree on time/vendor/ip/user/host,
  and a UNIQUE `(dedup_hash, event_time)` for idempotent ingest.
- **Retention = dropping whole monthly partitions** older than the cutoff (instant).
  The floor is `RETENTION_YEARS` (default 3); `db.purge_older_than` and the Admin page
  never purge below it. Default keeps everything; set `AUTO_PURGE=true` to enforce the
  floor on startup.
- **Dedup:** `normalize.dedup_hash` = sha256 over (vendor + event_time + canonical raw).
  Re-uploading the same/overlapping export inserts via `ON CONFLICT DO NOTHING`.

## Parser-accuracy gotchas

- **Palo Alto CSV** maps by column header → robust across PAN-OS versions.
- **Palo Alto syslog** is **positional**. The maps in `paloalto_syslog.py`
  (`_COMMON`, `_TRAFFIC_TAIL`, `_THREAT_TAIL`, and the SYSTEM/CONFIG offsets) target
  the PAN-OS 10/11 common layout; **field order can drift by version**. The parser
  always preserves the full positional list in `raw["fields"]`, so data is never lost
  and offsets can be retuned. The `samples/paloalto_syslog.log` fixtures are crafted to
  the documented offsets — if you change the maps, update the sample + tests together.
- **CrowdStrike** CSV/JSON resolve fields from multiple candidate names to cope with
  detection vs incident vs FDR shapes; JSON flattens nested `event`/`metadata`.
- **Fortinet FortiGate** is `key=value` (quoted values tolerated); numeric `proto` is
  mapped to tcp/udp/icmp/…; timestamp comes from `date`+`time` (not the ns `eventtime`).
- **Windows Security** extracts target account / source IP / logon type from the
  `Message` text (one code path for both the CSV and JSON exports); event-id → action
  via a small map. Account list: take the **last** non-`-`/non-`NULL SID` value.
- **Suricata EVE** keys off `event_type`; alert severity 1/2/3 → high/medium/low;
  `flow.bytes_*` summed into `bytes_total`.
- **CEF** keeps the real device vendor/product on the event; the extension parser
  slices on ` key=` boundaries (values may contain spaces) and unescapes `\| \= \\`.
- **Cisco ASA/Firepower** keys off the `%FAC-LEVEL-ID:` token (severity = the syslog
  level, *not* the `<PRI>`); the 5-tuple/bytes/user are mined from the free-text
  message — `src`/`dst` win, else `from`/`to`, else Built `for`(foreign)/`to`(local).
- **Zeek** is driven by the `#separator`/`#fields`/`#path`/`#unset_field` header, so
  column order comes from the file; `ts` is epoch-seconds-with-fraction (pass through
  `float()` before `parse_ts`); `-`/`(empty)` become NULL; multiple logs may concatenate.
- **Generic syslog** decodes `<PRI>` → facility/severity names, then RFC 5424 (version
  digit first) or RFC 3164 (`Mmm dd hh:mm:ss`); unrecognized lines keep the whole line
  as the message. It is the **catch-all**, so `detect.py` checks it **last**.
- **Cloud/identity JSON** (CloudTrail, M365, Entra, Okta) all use `util.iter_json_records`
  (handles single object / array / NDJSON / `{"Records"|"value":[…]}` wrappers) and a
  case-insensitive `_g` to tolerate camelCase (Graph) vs PascalCase (Azure Monitor).
  Success/failure action comes from the vendor's outcome field (`errorCode==0`,
  `ResultStatus`, `responseElements.ConsoleLogin`, `outcome.result`).
- **Cisco IOS/IOS-XE/NX-OS** keys off `%FACILITY-SEVERITY-MNEMONIC:` (alpha mnemonic) —
  distinct from ASA's numeric message id, so its detect regex requires a letter-led
  mnemonic and won't match ASA. 5-tuple mined from ACL `ip(port) -> ip(port)`, user
  from `[user: …]` / `by …`, source from `[Source: …]`.
- **Cisco Meraki** is RFC 5424 syslog whose body is `<etype> key=value… note:` — the
  event type is the log_type; `src`/`dst` may carry `:port` (use `split_ip_port`);
  `pattern:`/`request:`/`message:` becomes the message. Detected before generic syslog.
- **Zeek JSON** mirrors `zeek_tsv` but from `LogAscii::use_json` records (dotted keys like
  `id.orig_h`); path comes from `_path` or is inferred from the fields present.
- **GCP/Azure/GitHub/GitLab** JSON each map their own shape: GCP `protoPayload.*`
  (methodName / principalEmail / callerIp); Azure `operationName` + `identity.claims`
  (operationName/resultType may be `{value,localizedValue}`); GitHub `action`/`actor`/
  `actor_ip` with epoch-ms `@timestamp`; GitLab actor + action under `details`.
- **Generic JSON (`generic_json`)** is the JSON catch-all and the **fallback for
  unrecognized JSON** (replacing the old CrowdStrike default). It flattens one level so
  ECS keys (`source.ip`, `event.action`) resolve and maps many candidate names; vendor
  defaults to `"json"`. Keep it last in `_detect_json`.
- **Detection ordering (`detect.py`)** is specific-before-generic. JSON is routed by
  record keys: `event_type`+net → Suricata; `ProviderName`+`Id` → Windows;
  `eventSource`+`eventName` → CloudTrail; `Workload`+`Operation` → M365; `eventType`+
  `actor` → Okta; `userPrincipalName`/`appDisplayName` → Entra; `id.orig_h` → Zeek JSON;
  `protoPayload` → GCP; `operationName`+azure-keys → Azure; `action`+`actor` → GitHub;
  `entity_type`+`details` → GitLab; `metadata`+`event` (both) or `aid`/`cid`/… →
  CrowdStrike; else **generic_json**. Text formats match `CEF:n|`, then `%ASA-…` (numeric)
  → Cisco ASA, then `%FAC-SEV-MNEMONIC` (alpha) → Cisco IOS, then Zeek `#fields`, then PAN
  syslog, then Fortinet KV, then Meraki, then CSV headers, and finally **generic syslog**.

## Adding a new format / vendor

1. Create `app/parsers/<vendor>_<fmt>.py` with `parse(content)`.
2. Register it in `app/parsers/__init__.py` (`PARSERS`, `FORMAT_LABELS`).
3. Teach `app/detect.py` to recognize it (prefer a strict signature — e.g. a regex
   over distinctive header/positional tokens — to avoid cross-vendor false positives;
   a stray field value like `SYSTEM` must not trip another vendor's detector).
4. Add a `samples/` fixture and a test in `tests/test_parsers.py`.

## Adding a detection rule

Drop a YAML file in `rules/`. **Per-event** rules use the Sigma-subset format
(`detection:` with selections + `condition:`); reference normalized field names
(`action`, `src_ip`, `user_name`, …) or any `raw` key (case-insensitive), and tag
with `attack.tNNNN` / `attack.<tactic>`. **Correlation** rules use a `correlation:`
block (`match` / `group_by` / `window` / `threshold`) over normalized columns.
Rules are loaded on startup and synced into `detection_rules`; enable/disable from
the Admin page (applies live). Match logic is unit-tested in `tests/test_detection.py`
(per-event) and `tests/test_correlation.py` (correlation) — no DB needed.

## Adding a response playbook

Drop a YAML file in `playbooks/` with a `match` (any of `rule_id` / `min_level` /
`techniques`) and an `action` (`type: log`, or a webhook intent like `block_ip`
with a `target` alert field). Webhook actions POST `{playbook_id, action, target,
alert}` to `RESPONSE_WEBHOOK_URL` (your automation/SOAR endpoint) — LogOcean stays
agentless and lets that platform enforce. Every run is audited in `response_actions`
and shown at `/responses`. Matching/execution is tested in `tests/test_response.py`.

## Adding a collector

Subclass `collectors.base.Collector` in `app/collectors/sources.py` with `name`,
`fmt` (an existing parser key), `configured()`, and `fetch(cursor) -> FetchResult`
(content text + advanced cursor). Keep the HTTP call in `_http_get` and make the
URL builder + cursor advancement pure functions so they're testable without
network (see Okta/GitHub/GitLab + `tests/test_collectors.py`). Register it in
`runner.build_collectors()` and add its credentials to `config.py`/`.env.example`.
The framework persists the cursor, feeds the response through `ingest.ingest`, and
shows status on the Admin page. For sources needing SigV4/OAuth (AWS/Entra/M365),
prefer the **push** path: have an external job pull + POST to the ingest API.

## Testing

```bash
pip install pytest python-dateutil
PYTHONPATH=. python -m pytest tests/ -q      # PowerShell: $env:PYTHONPATH="."
```

- `test_parsers.py` — parsers + auto-detection over the bundled samples.
- `test_api_auth.py` — API-key hashing + header extraction.
- `test_streaming.py` — ingest-queue grouping, the async worker loop, backpressure drop.
- `test_syslog.py` — TCP framing (RFC 6587 octet-counting + newline) and format resolution.
- `test_detection.py` — Sigma-subset matching, condition grammar, the rule library.
- `test_pipeline.py` — inline detection in `write_stream` (DB inserts mocked).
- `test_correlation.py` — correlation rule loading, window parsing, alert dedup.
- `test_notify.py` — severity routing, payload builders, the dispatcher thread.
- `test_response.py` — playbook loading/matching, action execution, the worker.
- `test_collectors.py` — URL building, cursor advancement, the run→ingest glue.
- `test_auth.py` — password hashing/verify, role ranking, the RBAC dependency.
- `test_audit.py` — the `_audit` helper's actor/IP resolution (DB write mocked).
- `test_compliance.py` — technique→control mapping + the coverage report builder.

All tests are **DB-free** (the async-queue and pipeline tests mock the writers).
`psycopg` must be importable to load `db`/`streaming`, but no live Postgres is
needed; full DB-integration tests (TestClient + Postgres) run in CI/Docker. Run
the suite after any parser/detector/pipeline/rule change.

## Security / ops notes

- `AUTH_ENABLED=true` turns on built-in login + RBAC (admin/analyst/viewer; the
  `auth_guard` middleware protects the UI, `require_role(...)` gates mutating
  routes, `/api/*` keeps its API-key auth). Off by default — then run behind SSO /
  a reverse proxy or on a trusted host.
- Security-relevant actions (login/logout, purge, key/rule/collector/user changes,
  alert triage, upload) are recorded in `audit_log` via `main._audit(...)` and
  shown on the Admin page.
- The Postgres volume IS the 3-year archive — back it up.
- Don't commit `.env`, uploads, or `pgdata/` (already in `.gitignore`).
