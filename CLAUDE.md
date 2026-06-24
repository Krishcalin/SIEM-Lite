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

Being grown toward a Wazuh-like SIEM (agentless): Phase 1 (live ingestion) is
complete; Phase 2 is a Sigma-based detection/alerting engine.

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
                                       ─► db.insert_events ─► events (month-partitioned, GIN)
                                       ─► search / export
```

Live sources (syslog) buffer in a bounded async queue (`streaming.py`) drained by
writer workers that batch-insert; queue counters are on `GET /health`. One
normalized schema across all sources; the **full original record is always kept**
in `events.raw` (jsonb) so nothing is lost and any field stays searchable.

## Repository layout

```
app/
  main.py        FastAPI routes + UI (dashboard, upload, search, event, admin) + lifespan
  api.py         HTTP ingest API: POST /api/v1/ingest (API-key auth)
  config.py      env-driven settings (DB_DSN, RETENTION_YEARS, INGEST_*, SYSLOG_*, ...)
  models.py      NormalizedEvent dataclass (the common schema)
  util.py        tolerant parse_ts / clean_ip / to_int; hash_api_key / extract_api_key
  detect.py      best-effort vendor+format auto-detection
  normalize.py   dedup_hash() + tsv_text()
  pipeline.py    source-agnostic core: parse_events / apply_fallback_time / write_stream
  ingest.py      per-batch orchestration (sha, batch, source tagging) around pipeline
  streaming.py   bounded async ingest queue + batching writer workers (backpressure)
  db.py          pool, schema/partition mgmt, insert, search, stats, purge, api_keys
  receivers/
    syslog.py    UDP/TCP/TLS syslog receiver -> queue (RFC 6587 framing)
  parsers/       paloalto_csv, paloalto_syslog, fortinet_fortigate, cisco_asa, cisco_ios,
                 meraki, zeek_tsv, zeek_json, crowdstrike_csv, crowdstrike_json,
                 windows_security, suricata_eve, cef, generic_syslog, generic_json,
                 aws_cloudtrail, gcp_audit, azure_activity, m365_audit, entra_signin,
                 okta_system_log, github_audit, gitlab_audit  (23 total)
  templates/     base, dashboard, upload, search, event, admin
  static/style.css
schema.sql       partitioned events table, FTS + indexes, ingest_batches, api_keys
samples/         one example file per format (used by tests)
tests/           test_parsers.py, test_api_auth.py, test_streaming.py, test_syslog.py
                 (all run with NO database needed)
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

## Testing

```bash
pip install pytest python-dateutil
PYTHONPATH=. python -m pytest tests/ -q      # PowerShell: $env:PYTHONPATH="."
```

- `test_parsers.py` — parsers + auto-detection over the bundled samples.
- `test_api_auth.py` — API-key hashing + header extraction.
- `test_streaming.py` — ingest-queue grouping, the async worker loop, backpressure drop.
- `test_syslog.py` — TCP framing (RFC 6587 octet-counting + newline) and format resolution.

All tests are **DB-free** (the async-queue test mocks the writer). `psycopg` must
be importable to load `db`/`streaming`, but no live Postgres is needed; full
DB-integration tests (TestClient + Postgres) run in CI/Docker. Run the suite
after any parser/detector/pipeline change.

## Security / ops notes

- No built-in auth — run behind SSO / a reverse proxy or on a trusted host.
- The Postgres volume IS the 3-year archive — back it up.
- Don't commit `.env`, uploads, or `pgdata/` (already in `.gitignore`).
