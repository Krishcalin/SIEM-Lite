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

> Being grown toward a Wazuh-like agentless SIEM. Live ingestion, a Sigma-based
> **detection & alerting** engine, **notifications + agentless response**, and
> **agentless collectors** are in place: events are matched against detection +
> correlation rules, raising alerts you triage at `/alerts`; new alerts are pushed
> to your channels and can trigger response playbooks (audited at `/responses`);
> collectors pull vendor logs while other tools push findings to the API; and
> built-in auth/RBAC plus a `/compliance` coverage view (MITRE→PCI/NIST/CIS/HIPAA)
> round it out.

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

## Detection & alerting

Every ingested event is evaluated against **detection rules**, and a background
scheduler runs **correlation rules** over the event store. Matches raise **alerts**
you can filter, drill into (down to the originating event), and triage
(acknowledge / close) at **`/alerts`**; open-alert counts show on the dashboard.

Rules are YAML files in `rules/` (a Sigma-compatible subset), tagged with MITRE
ATT&CK, and enable/disable from the Admin page (applies immediately). The engine
supports the common Sigma field modifiers so many community rules load as-is:
`contains`/`startswith`/`endswith`/`re` (with `i`/`m`/`s` flags)/`cased`, value
lists with `|all`, `cidr` (IP-in-network), numeric `lt`/`lte`/`gt`/`gte`,
`exists`, `fieldref`, and the `base64`/`base64offset`/`windash` encoding
modifiers for command-line obfuscation — plus the `and`/`or`/`not` + `N of … `
condition grammar.

```yaml
# per-event rule
title: RDP Connection Allowed
id: lo-rdp-allowed
level: medium
detection:
  selection: { dst_port: 3389 }
  permitted: { action: [allow, accept] }
  condition: selection and permitted
tags: [attack.t1021.001, attack.lateral_movement]
```
```yaml
# correlation (threshold) rule — e.g. brute force
title: Brute Force - Failed Logon Burst
id: lo-corr-bruteforce-logon
level: high
correlation:
  match: { action: failed-logon }
  group_by: [src_ip]
  window: 5m
  threshold: 5
tags: [attack.t1110, attack.credential_access]
```

Ships with a starter rule pack (17 detection + 2 correlation rules) covering
failed-logon brute force, denied-connection floods, RDP exposure (incl. external
RDP via `cidr`), ingress-tool transfer, event-log clearing, security-tool
tampering, encoded/download PowerShell (`base64offset`/`windash`), AWS CloudTrail
(logging disabled, root console login, world-open security groups, access-key
creation), Entra ID (risky sign-in succeeded, legacy auth), Okta (admin grant,
MFA deactivation), Microsoft 365 (mailbox forwarding rules), and GitHub (repo
made public). Detection can be turned off with `DETECTION_ENABLED=false`.

### Notifications & agentless response

Newly-raised alerts at or above `NOTIFY_MIN_LEVEL` are delivered to **notification
channels** — a webhook (Slack/Teams/Discord/generic, `WEBHOOK_URL`) and/or email
(`SMTP_*`) — by a background worker, so slow delivery never blocks ingest. Set
`NOTIFY_ENABLED=true` and configure a channel.

Alerts can also trigger **response playbooks** (`playbooks/*.yml`). A playbook
matches alerts (by rule id / severity / technique) and runs an **agentless**
action: a structured webhook POST to your automation/SOAR/firewall/IAM endpoint
(`RESPONSE_WEBHOOK_URL`) carrying the intent, or a `log` action that only records.
LogOcean stays agentless and lets your platform enforce. Every action is audited
at **`/responses`** and on the alert's page.

```yaml
# playbooks/block_bruteforce_source.yml
title: Block brute-force source IP
id: pb-block-bruteforce
match: { rule_id: [lo-corr-bruteforce-logon], min_level: high }
action: { type: block_ip, target: src_ip }   # POSTs {action, target, alert} to your SOAR
revert_after: 600
```

## Agentless collectors & feeds

Two agentless ways to get logs in without manual upload:

- **Pull collectors** — set `COLLECTORS_ENABLED=true` and a collector's credentials.
  A scheduler fetches new records every `COLLECTOR_INTERVAL` seconds, checkpointing a
  per-source cursor so each run only pulls what's new, and feeds them through the same
  parse→detect→alert pipeline. Status + enable/disable are on the **Admin** page.
  Built-in collectors (each activates only when its credentials are set):
  - **Okta** System Log (`OKTA_*`), **GitHub** audit log (`GITHUB_*`), **GitLab**
    audit events (`GITLAB_*`) — token-based REST.
  - **AWS CloudTrail** (`AWS_REGION` + `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`,
    optional `AWS_SESSION_TOKEN`) — `LookupEvents` signed with **AWS SigV4** (stdlib).
  - **Microsoft Entra ID** sign-in logs and **Microsoft 365** unified audit log —
    one Azure app registration (`AZURE_TENANT_ID`/`AZURE_CLIENT_ID`/`AZURE_CLIENT_SECRET`),
    **OAuth2 client-credentials**. Entra uses Microsoft Graph; M365 uses the Office 365
    Management Activity API and additionally needs `M365_ENABLED=true`.
- **Push feeds** — point your own tools (RHEL/Windows/SBOM/AWS audit scanners) at
  the ingest API. Copy [`clients/logocean_push.py`](clients/logocean_push.py):

  ```python
  from logocean_push import push
  push("http://logocean:8000", "lo_...", findings)   # list of dicts -> generic_json
  ```

## Threat-intelligence enrichment

Set `THREATINTEL_ENABLED=true` to match every ingested event against **indicators of
compromise** — IPs, CIDRs, domains, file hashes, and URLs. A hit raises a **Threat
Intelligence Match** alert that flows through the normal alert → notify → response path
(its severity is the highest of the matched indicators).

- **Feeds** — `THREATINTEL_FEEDS` is a comma/space-separated list of local file paths or
  `http(s)` URLs, refreshed every `THREATINTEL_REFRESH_MINUTES`. Each feed may be a plain
  one-indicator-per-line list (`#` comments allowed), a CSV
  (`indicator[,type[,severity[,description]]]`), or JSON (an array of strings or of
  objects). Indicator type is inferred when not given.
- **Manual indicators** — add or remove individual IOCs from the **Admin** page; a
  Reload button re-fetches the feeds.
- **Matching** — indicators are held in an in-memory index for fast per-event lookup;
  the matcher checks the event's src/dst IPs (exact + CIDR) and pulls
  IPs/domains/URLs/hashes out of the normalized fields *and* `raw` (and from free text
  in `message`), so an indicator buried in a log line is still caught.

```bash
# a feed can be as simple as a blocklist file:
echo -e "# bad infra\n203.0.113.5\nevil.example\nhttp://drop.example/x" > feeds/iocs.txt
THREATINTEL_ENABLED=true THREATINTEL_FEEDS=feeds/iocs.txt  # ...then run as usual
```

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
| `DETECTION_ENABLED` | `true` | Evaluate detection + correlation rules and raise alerts |
| `CORRELATION_INTERVAL` | `60` | Seconds between correlation-rule evaluations |
| `NOTIFY_ENABLED` / `NOTIFY_MIN_LEVEL` | `false` / `high` | Send new alerts (>= level) to channels |
| `WEBHOOK_URL` / `WEBHOOK_STYLE` | — / `slack` | Notification webhook (Slack-text or full JSON) |
| `SMTP_HOST` … `SMTP_TO` | — | Email notification channel (host + from + to to activate) |
| `RESPONSE_ENABLED` / `RESPONSE_WEBHOOK_URL` | `false` / — | Run response playbooks; automation endpoint |
| `COLLECTORS_ENABLED` / `COLLECTOR_INTERVAL` | `false` / `300` | Scheduled pull collectors; poll period (s) |
| `OKTA_*` / `GITHUB_*` / `GITLAB_*` / `AWS_*` / `AZURE_*` | — | Per-collector credentials (a collector activates when set) |
| `THREATINTEL_ENABLED` / `THREATINTEL_FEEDS` | `false` / — | Match events against IOC feeds (paths or URLs) |
| `THREATINTEL_REFRESH_MINUTES` / `THREATINTEL_DEFAULT_SEVERITY` | `60` / `high` | Feed refresh period; severity when a feed omits one |
| `AUTH_ENABLED` | `false` | Built-in login + RBAC (else front with SSO/proxy) |
| `ADMIN_USER` / `ADMIN_PASSWORD` | `admin` / — | Bootstrap admin on first run (random password logged if blank) |
| `SESSION_TTL_HOURS` / `SESSION_COOKIE_SECURE` | `12` / `false` | Session lifetime; set secure cookie over HTTPS |
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
│   ├── detection/          # engine.py (per-event Sigma-subset), correlation.py, runtime.py
│   ├── alert_actions.py    # fan new alerts to notifications + response
│   ├── notify/             # webhook + email channels, background dispatcher
│   ├── response/           # agentless response playbooks + audit log
│   ├── collectors/         # pull connectors (Okta/GitHub/GitLab/AWS/Entra/M365) + scheduler
│   ├── threatintel/        # IOC matcher + feed loader + index runtime
│   ├── detect.py           # format auto-detection
│   ├── normalize.py        # dedup hash + full-text blob
│   ├── models.py           # NormalizedEvent
│   ├── auth.py             # password hashing (pbkdf2), roles, RBAC dependency
│   ├── compliance.py       # MITRE technique → framework control mapping + report
│   ├── util.py             # tolerant time/IP/int coercion; API-key helpers
│   ├── parsers/            # paloalto_{csv,syslog}, fortinet_fortigate, cisco_{asa,ios}, meraki,
│   │                       #   zeek_{tsv,json}, crowdstrike_{csv,json}, windows_security, suricata_eve,
│   │                       #   cef, generic_{syslog,json}, aws_cloudtrail, gcp_audit, azure_activity,
│   │                       #   m365_audit, entra_signin, okta_system_log, github_audit, gitlab_audit
│   ├── templates/          # dashboard, upload, search, event, alerts, alert, responses,
│   │                       #   compliance, admin, login
│   └── static/style.css
├── rules/                  # detection + correlation rules (Sigma-subset YAML)
├── playbooks/              # agentless response playbooks
├── clients/                # logocean_push.py — push helper for your own tools
├── samples/                # one example file per format
└── tests/                  # unit: test_{parsers,api_auth,streaming,syslog,detection,
                            #   pipeline,correlation,notify,response,collectors,auth,
                            #   threatintel,...}
                            # integration (real Postgres): conftest.py +
                            #   test_integration_{db,api}.py
```

## Tests

The suite has two tiers. **Unit tests** are DB-free and run anywhere;
**integration tests** (marked `integration`) exercise a real PostgreSQL and
self-skip when `DB_DSN` is unset.

```bash
pip install pytest python-dateutil
# Unit only (no database) — the default local experience:
PYTHONPATH=. python -m pytest tests/ -m "not integration" -q   # PowerShell: $env:PYTHONPATH="."

# Integration (needs Postgres + httpx); point DB_DSN at a throwaway database:
pip install httpx
DB_DSN=postgresql://logocean:logocean@localhost:5432/logocean \
  PYTHONPATH=. python -m pytest tests/ -m integration -q
```

The **unit** tests cover parsers + auto-detection (over the bundled samples),
API-key auth, the async ingest queue (grouping, worker loop, backpressure),
syslog TCP framing, the detection engine (Sigma-subset matching, all field
modifiers + condition grammar), inline detection in the pipeline,
correlation-rule loading/dedup, notification routing + dispatcher, response
playbook matching/execution, collector URL/cursor logic (incl. AWS SigV4 +
Microsoft OAuth helpers), threat-intel (IOC classification, feed parsing,
matching + alerting), auth (password hashing, role ranking, the RBAC
dependency), the audit helper, and the compliance coverage report — all without
a database (the queue, pipeline, and worker tests mock the writers).

The **integration** tests run against an actual PostgreSQL 16 and verify what
mocks can't: month-partition auto-creation, the GIN full-text index, inet/CIDR
search, ON CONFLICT dedup, retention purge dropping whole partitions, the
correlation SQL, the pipeline write path raising alert rows (detection and
threat-intel), alert insert/dedup/queries, the IOC/auth/collector/registry
round-trips, and the HTTP stack end-to-end (TestClient → API-key auth → ingest →
detect). CI runs the unit tier on Python 3.11–3.13 and the integration tier
against a Postgres service container (`.github/workflows/tests.yml`).

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

Set `AUTH_ENABLED=true` for **built-in login + RBAC** (roles: `admin` / `analyst` /
`viewer`). An admin is bootstrapped on first run from `ADMIN_USER`/`ADMIN_PASSWORD`
(a random password is logged if blank); manage users from the Admin page. Passwords
are pbkdf2-hashed and sessions are server-side (revocable). Use `SESSION_COOKIE_SECURE=true`
behind HTTPS. Security-relevant actions (login/logout, purge, key/rule/collector/user
changes, alert triage, upload) are recorded in an **audit log** on the Admin page.
With auth off, run behind your SSO/reverse proxy or on a trusted network. Either way,
keep the Postgres volume backed up (it is your 3-year archive).

**Input hardening.** Ingest treats all log content as untrusted: uploads and the API
body are size-capped (`MAX_UPLOAD_MB`) and streamed so a huge payload can't exhaust
memory; a deeply-nested JSON "bomb" is rejected before parsing by an explicit
depth guard (`_MAX_JSON_DEPTH`, version-stable — not reliant on the interpreter
raising `RecursionError`); CSV exports neutralize spreadsheet formula injection; and
correlation/search SQL uses whitelisted columns with fully parameterized values.
