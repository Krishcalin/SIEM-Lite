<p align="center">
  <img src="docs/banner.svg" alt="LogOcean" width="800"/>
</p>

# LogOcean

[![tests](https://github.com/Krishcalin/SIEM-Lite/actions/workflows/tests.yml/badge.svg)](https://github.com/Krishcalin/SIEM-Lite/actions/workflows/tests.yml)

A self-hosted **log parser, indexer, and long-term store** for **network, endpoint,
cloud, and identity** logs from many vendors. Logs arrive three ways — **web upload**,
the **HTTP ingest API**, or the **syslog receiver** (UDP/TCP/TLS) — and LogOcean
parses and normalizes them, indexes them for full-text + structured search, and
retains them in PostgreSQL for **≥ 3 years**.

```
 upload (web) ───────────────┐
 POST /api/v1/ingest (key) ──┤─► auto-detect ─► parse ─► normalize ─► store (Postgres)
 syslog UDP/TCP/TLS ─► queue ┘     format                common      month-partitioned
                                                          schema      events + FTS index
                                                                           │
                                                  search ◄── filters + full-text ◄──┘
```

> Being grown toward a Wazuh-like agentless SIEM: Phase 1 (live ingestion) is done;
> Phase 2 adds a Sigma-based detection/alerting engine.

## Features

- **Twenty-three parsers**, auto-detected on upload:
  - *Network / firewall:*
    - Palo Alto NGFW **CSV export** (Monitor ▸ Logs ▸ Export)
    - Palo Alto NGFW **syslog** (positional payload; Traffic / Threat / System / Config)
    - Fortinet **FortiGate** syslog (`key=value`; traffic / UTM / event)
    - Cisco **ASA / Firepower (FTD)** syslog (`%ASA-L-NNNNNN` message IDs)
    - Cisco **IOS / IOS-XE / NX-OS** syslog (`%FACILITY-SEVERITY-MNEMONIC`)
    - Cisco **Meraki** syslog (flows / urls / ids-alerts / security_event)
    - **Zeek** (Bro) **TSV** (`conn` / `dns` / `http` … via the `#fields` header)
    - **Zeek** (Bro) **JSON** (`LogAscii::use_json`; NDJSON or array)
  - *Endpoint / IDS / host:*
    - CrowdStrike Falcon **CSV export** (detections / incidents)
    - CrowdStrike Falcon **JSON** (array, single object, `{"resources":[…]}`, or NDJSON / FDR)
    - **Windows Security Event Log** (CSV, or `Get-WinEvent | ConvertTo-Json`)
    - **Suricata** EVE JSON (alert / flow / dns / http / tls; NDJSON or array)
  - *Cloud / identity (JSON):*
    - **AWS CloudTrail** (`{"Records":[…]}`, single event, or NDJSON)
    - **Google Cloud** Audit Logs (`protoPayload` AuditLog; array / NDJSON / `entries`)
    - **Microsoft Azure** Activity Log (`{"records":[…]}` or REST list)
    - **Microsoft 365** Unified Audit Log (Management API / `Search-UnifiedAuditLog`)
    - **Microsoft Entra ID** (Azure AD) sign-in logs
    - **Okta** System Log (auth / admin activity)
    - **GitHub** audit log (`repo.*` / `git.*` / `org.*` actions)
    - **GitLab** audit events (`/audit_events`)
  - *Generic:*
    - **CEF** — Common Event Format (ArcSight & many firewalls / WAFs / proxies / AV)
    - **Generic syslog** — RFC 3164 (BSD) and RFC 5424 catch-all
    - **Generic JSON / NDJSON** — flat or Elastic Common Schema (ECS) catch-all
- **Normalization** to one common schema (time, vendor, type, src/dst IP+port, user,
  host, action, severity, rule, bytes, message) — the **full original record is kept**
  in a `jsonb` column so nothing is lost and any field stays searchable.
- **PostgreSQL storage**, RANGE-**partitioned by month**, with GIN full-text, a `jsonb`
  GIN index, and btree indexes on the common fields.
- **Web UI**: dashboard (volume, partitions, storage), drag-drop upload, search
  (time range + vendor/type/IP/user/host/severity/action + full-text), event detail
  (pretty raw record), CSV export, and an admin/retention page.
- **3-year retention** as policy: monthly partitions make purge a cheap partition
  DROP. The app **never purges below `RETENTION_YEARS`**; purge is manual unless
  `AUTO_PURGE=true`.
- **Idempotent ingest**: every record has a dedup hash, so re-uploading the same
  file (or overlapping exports) does not create duplicates.

## Quick start (Docker)

```bash
cp .env.example .env          # optional: adjust retention / limits
docker compose up --build     # starts Postgres + the app
# open http://localhost:8000
```

Then **Upload** a file (try the ones in `samples/`), and **Search**.

## Quick start (local, without Docker)

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# point at a Postgres you control:
export DB_DSN="postgresql://logocean:logocean@localhost:5432/logocean"   # PowerShell: $env:DB_DSN=...
uvicorn app.main:app --reload
```

The schema (tables, partitions, indexes) is created automatically on startup.

## Live ingestion (HTTP API & syslog)

Besides manual upload, LogOcean accepts logs in near-real-time through two front
doors that share the same detect → parse → normalize → store pipeline.

**HTTP ingest API.** Create a key on the **Admin** page, then POST raw log content:

```bash
curl -X POST "http://localhost:8000/api/v1/ingest?format=auto&filename=fw.log" \
     -H "X-API-Key: lo_..." --data-binary @fw.log
# -> {"batch_id": 42, "format": "...", "total": N, "inserted": N, ...}
```

`format` may be `auto` or any format key; auth is `X-API-Key` or `Authorization:
Bearer`. Only the sha256 of each key is stored (the plaintext is shown once).

**Syslog receiver.** Set `SYSLOG_ENABLED=true` to listen on UDP+TCP (default
port 5514; TLS optional). Point a collector or device at it:

```bash
logger -n localhost -P 5514 -d "<134>1 2026-06-24T10:00:00Z fw test message"
```

Messages flow through a bounded async queue with writer workers that batch-insert,
so a burst never blocks the receiver; queue counters are on `GET /health`. TCP
framing supports both octet-counting (RFC 6587) and newline-delimited streams.

## How to export the logs to upload

| Source | How to export | Upload as |
|---|---|---|
| Palo Alto NGFW | Monitor ▸ Logs ▸ (Traffic/Threat/URL/System/Config) ▸ **Export to CSV** | Palo Alto CSV (auto) |
| Palo Alto NGFW | Syslog file from your collector / forwarder | Palo Alto syslog (auto) |
| Fortinet FortiGate | Syslog from your collector, or FortiAnalyzer ▸ **Log download** | Fortinet FortiGate (auto) |
| CrowdStrike Falcon | Endpoint security ▸ Detections / Incidents ▸ **Export** (CSV) | CrowdStrike CSV (auto) |
| CrowdStrike Falcon | Event Search / API / FDR export (JSON or NDJSON) | CrowdStrike JSON (auto) |
| Windows hosts | `Get-WinEvent -LogName Security` ▸ **Export-Csv** (or **ConvertTo-Json**); or Event Viewer ▸ **Save All Events As CSV** | Windows Security (auto) |
| Suricata IDS/IPS | `eve.json` (NDJSON) or an exported JSON array | Suricata EVE (auto) |
| Cisco ASA / Firepower | Syslog from your collector (lines with `%ASA-…`/`%FTD-…`) | Cisco ASA / Firepower (auto) |
| Cisco IOS / IOS-XE / NX-OS | Device syslog (lines with `%FACILITY-SEV-MNEMONIC`) | Cisco IOS (auto) |
| Cisco Meraki | Dashboard ▸ syslog server output (flows / urls / ids-alerts …) | Cisco Meraki (auto) |
| Zeek (Bro) | `conn.log` / `dns.log` / `http.log` — classic TSV (`#fields`) **or** JSON | Zeek TSV / JSON (auto) |
| AWS CloudTrail | S3/CloudWatch export or `aws cloudtrail lookup-events` (JSON) | AWS CloudTrail (auto) |
| Google Cloud | Cloud Logging export or `gcloud logging read --format json` | Google Cloud Audit (auto) |
| Microsoft Azure | Activity Log export (`{"records":…}`) or `az monitor activity-log list` | Microsoft Azure Activity (auto) |
| Microsoft 365 | `Search-UnifiedAuditLog` ▸ **AuditData**, or Management Activity API (JSON) | Microsoft 365 (auto) |
| Microsoft Entra ID | Sign-in logs via Graph `auditLogs/signIns` or Azure Monitor export (JSON) | Microsoft Entra ID (auto) |
| Okta | System Log API export (JSON array / NDJSON) | Okta System Log (auto) |
| GitHub | Org/Enterprise ▸ audit log ▸ **Export** (JSON / NDJSON) | GitHub audit (auto) |
| GitLab | Admin ▸ `/audit_events` API (JSON) | GitLab audit (auto) |
| Any CEF source | Syslog / file in Common Event Format (`CEF:0\|…`) | CEF (auto) |
| Any syslog source | Plain RFC 3164 / 5424 syslog not matched above | Generic syslog (auto) |
| Any JSON source | Flat or ECS-style JSON / NDJSON not matched above | Generic JSON (auto) |

Auto-detect inspects the header/content; if a file is ambiguous, pick the format
explicitly in the upload form.

## Configuration (`.env`)

| Variable | Default | Meaning |
|---|---|---|
| `DB_DSN` | `postgresql://logocean:logocean@localhost:5432/logocean` | PostgreSQL connection |
| `RETENTION_YEARS` | `3` | Retention floor; purge cannot go below this |
| `PAGE_SIZE` | `100` | Search results per page |
| `MAX_UPLOAD_MB` | `512` | Reject larger uploads / API payloads |
| `AUTO_PURGE` | `false` | If true, drop partitions older than `RETENTION_YEARS` on startup |
| `INGEST_QUEUE_MAX` | `10000` | Async ingest queue capacity (live sources) |
| `INGEST_WORKERS` | `2` | Writer workers draining the queue |
| `INGEST_FLUSH_MAX` / `INGEST_FLUSH_MS` | `2000` / `1000` | Flush a buffer at N events or N ms |
| `SYSLOG_ENABLED` | `false` | Listen for syslog (UDP+TCP) |
| `SYSLOG_UDP_PORT` / `SYSLOG_TCP_PORT` | `5514` / `5514` | Syslog ports (0 disables a transport) |
| `SYSLOG_FORMAT` | `auto` | Fixed parser for messages, or `auto` (per-message detect) |
| `SYSLOG_TLS_CERT` / `SYSLOG_TLS_KEY` | — | Enable TLS on syslog-over-TCP |

## Project layout

```
Log-Parser-Storage/
├── docker-compose.yml      # Postgres + app
├── Dockerfile
├── schema.sql              # partitioned events table, FTS, indexes, batches
├── requirements.txt
├── app/
│   ├── main.py             # FastAPI routes + UI + lifespan
│   ├── api.py              # HTTP ingest API (POST /api/v1/ingest, API-key auth)
│   ├── config.py
│   ├── db.py               # pool, partitions, insert, search, stats, purge, api_keys
│   ├── pipeline.py         # source-agnostic parse → normalize → insert core
│   ├── ingest.py           # per-batch orchestration (sha, batch, source tagging)
│   ├── streaming.py        # bounded async ingest queue + batching writer workers
│   ├── receivers/syslog.py # UDP/TCP/TLS syslog receiver → queue
│   ├── detect.py           # format auto-detection
│   ├── normalize.py        # dedup hash + full-text blob
│   ├── models.py           # NormalizedEvent
│   ├── util.py             # tolerant time/IP/int coercion; API-key helpers
│   ├── parsers/            # paloalto_{csv,syslog}, fortinet_fortigate, cisco_{asa,ios}, meraki,
│   │                       #   zeek_{tsv,json}, crowdstrike_{csv,json}, windows_security, suricata_eve,
│   │                       #   cef, generic_{syslog,json}, aws_cloudtrail, gcp_audit, azure_activity,
│   │                       #   m365_audit, entra_signin, okta_system_log, github_audit, gitlab_audit
│   ├── templates/          # dashboard, upload, search, event, admin
│   └── static/style.css
├── samples/                # one example file per format
└── tests/                  # test_parsers, test_api_auth, test_streaming, test_syslog (no DB needed)
```

## Tests

```bash
pip install pytest python-dateutil
PYTHONPATH=. python -m pytest tests/ -q       # PowerShell: $env:PYTHONPATH="."
```

The suite covers parsers + auto-detection (over the bundled samples), API-key
auth, the async ingest queue (grouping, worker loop, backpressure), and syslog
TCP framing. It does **not** require a database (the queue test mocks the writer).

## Data model & retention notes

- `events` is partitioned `BY RANGE (event_time)`; partitions are monthly
  (`events_YYYYMM`) and created on demand at ingest. A `events_default` partition
  catches out-of-range timestamps. Time-range searches prune to the relevant months.
- Retention = dropping whole monthly partitions older than the cutoff (instant,
  no row-by-row delete). The **Admin** page exposes a guarded purge; the floor is
  `RETENTION_YEARS`. For 3-year retention you typically never purge — set
  `AUTO_PURGE=true` only when you want to *stop* keeping data beyond the floor.
- Scale: tuned for manual-upload volumes (tens of millions of rows). For very high
  ingest, batch larger files, add a read replica, or move hot search to OpenSearch.

## Parser accuracy notes

- Palo Alto **CSV** maps by column header (robust across PAN-OS versions).
- Palo Alto **syslog** uses documented positional field maps for Traffic/Threat/
  System/Config (PAN-OS 10/11 common layout). The **complete positional field list
  is preserved** in `raw.fields`, so even if a field index drifts on your PAN-OS
  version, the data is retained and searchable, and the maps in
  `app/parsers/paloalto_syslog.py` are easy to adjust.
- CrowdStrike CSV/JSON resolve each field from multiple candidate names to cope
  with detection vs incident vs FDR shapes.
- **Cisco ASA/Firepower** mines the 5-tuple, bytes and user from the free-text message
  (best-effort `src`/`dst`, `from`/`to`, Built `for`/`to`); the full message is in `raw`.
- **Zeek** reads the `#separator` / `#fields` / `#path` header, so column order is taken
  from the file itself; a file may concatenate several logs (each with its own header).
- **Cloud/identity** JSON (CloudTrail, GCP, Azure, M365, Entra, Okta, GitHub, GitLab) is
  routed by record keys and resolves fields case-insensitively to tolerate camelCase
  (Graph) vs PascalCase (Azure Monitor) and wrapper shapes (`{"Records":…}`,
  `{"records":…}`, `{"entries":…}`, `{"value":…}`).
- **Generic JSON** is the JSON catch-all: it flattens one level so Elastic Common Schema
  keys (`source.ip`, `event.action`, `user.name`) resolve, and maps a wide set of
  candidate field names; anything unmapped stays in `raw`. It is the JSON fallback, so
  a recognized source is never shadowed by it.

## Security

Intended for an internal/analyst host. There is no authentication built in — run it
behind your SSO/reverse proxy or on a trusted network, and keep the Postgres volume
backed up (it is your 3-year archive).
