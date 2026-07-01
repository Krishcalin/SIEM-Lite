# CLAUDE.md — SIEM-Lite / LogOcean

Guidance for Claude Code (and other agents) working in this repository.

## What this is

**LogOcean** — a self-hosted log parser, indexer, and long-term store for
**network, endpoint, cloud, and identity** logs from many vendors (**27 parsers**,
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
**Threat-intel enrichment** (`THREATINTEL_ENABLED`) matches events against IOC
feeds and raises alerts on hits. **Triage & tuning** adds alert assignment, notes,
suppression/allowlist rules, and **cases** (`/cases`) that group related alerts
into one investigation. **Dashboards & reporting** add charts, top-N analytics, a
print-friendly `/reports` page, and ATT&CK-Navigator / CSV exports. **UEBA**
(`UEBA_ENABLED`, `/risk`) baselines every user/host/IP and scores entity risk +
new-entity / new-association anomalies beyond the rules.

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
                                       ├─► UEBA entity baselines (entities / entity_links)
                                       └─► detection + threat-intel (per event) ─► suppression
                                              filter ─► alerts ─► /alerts ─► triage / cases
 scheduler (every CORRELATION_INTERVAL) ─► correlation rules (SQL over events) ─► alerts
 alerts ─► notify + response · dashboards / /reports (charts, ATT&CK-Navigator, CSV)
```

Live sources (syslog) buffer in a bounded async queue (`streaming.py`) drained by
writer workers that batch-insert; queue counters are on `GET /health`. One
normalized schema across all sources; the **full original record is always kept**
in `events.raw` (jsonb) so nothing is lost and any field stays searchable.

**Detection** (`app/detection/`) runs two ways: per-event rules (Sigma-subset)
are evaluated inline in `pipeline.write_stream` as events are stored, and
correlation/threshold rules are evaluated on a schedule by SQL aggregation over
`events`. Both raise rows in `alerts` (deduped per rule+event / rule+group+window).
Rules live in `rules/*.yml`; the `detection_rules` table tracks enablement. The
`engine.py` evaluator supports the common Sigma field modifiers — `contains` /
`startswith` / `endswith` / `re` (`i`/`m`/`s` flags) / `cased`, `|all`, `cidr`,
numeric `lt`/`lte`/`gt`/`gte`, `exists`, `fieldref`, and `base64` /
`base64offset` / `windash` — so most community rules load unmodified (gated only
by whether our parsers populate the referenced field). The shipped pack is 30
detection + 3 correlation rules across Windows, network, AWS, Entra, Okta, M365,
GitHub, **Tripwire FIM** (critical-file / web-shell / persistence / monitoring-
disabled / object-removed per-event rules gated on `vendor|contains: tripwire` and
matching the changed path via `message` + LEEF `attributes.resource`, plus a
mass-change-burst correlation rule grouped by `host_name`), and a **Sysmon /
endpoint** pack that matches the fields `sysmon.py` lifts onto `raw`
(`Image`/`ParentImage`/`CommandLine`/`TargetObject`) plus the event-kind
`log_type` — office-spawns-shell, LOLBin proxy exec, registry Run-key persistence,
WMI persistence, LSASS dump, shadow-copy deletion, schtasks, command-line log
clearing. Command-line rules match `CommandLine` OR `message` so they also fire on
non-Sysmon sources that fill `message`.

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

**Threat intelligence** (`app/threatintel/`) matches each event against IOC feeds
inline in `pipeline.write_stream`. Feeds (local files or http(s) URLs; line/CSV/JSON,
type inferred) are parsed by `feeds.py` and stored in the `iocs` table by source;
`runtime.py` builds an in-memory `IocIndex` (IPs/CIDRs/domains/hashes/URLs) and a
scheduler refreshes feeds on a timer. `matcher.py` is pure: it pulls observables from
the event's normalized fields + `raw` (and extracts IPs/domains/URLs/hashes from free
text), and a hit becomes one `ti-ioc-match` alert (`ti_alert`) at the highest matched
severity — flowing through the same notify/respond path. Off unless
`THREATINTEL_ENABLED`; manual indicators are managed on the Admin page.

**Triage & tuning** (`app/triage/`) covers alert workflow + noise control.
`suppression.py` is a pure matcher: a `Suppression` is an AND of `rule_id` /
`vendor` / `user_name` / `host_name` / `src_ip` (exact or CIDR) conditions;
`runtime.py` holds the `SuppressionIndex` (rebuilt from the `suppressions` table).
`pipeline.write_stream` checks each newly-built alert (detection + threat-intel)
against the index — a match stores it as `status='suppressed'` (kept for audit,
excluded from the default `/alerts` view and from notify/respond) and bumps the
rule's `hit_count`. Alerts also carry an `assignee` and threaded `alert_notes`,
edited from the alert detail page (`/alert/{id}` assign/note/suppress routes);
suppressions are managed under Admin. Reload the index after any change via
`triage_runtime.reload_index()`.

**Cases / incidents** group related alerts into one investigation. An alert points
at its case via `alerts.case_id`; `cases` carries status (open/investigating/
closed), assignee, summary and a `severity` that **rolls up** to the highest of its
members (`app/severity.py:max_severity`, applied in `db.add_alerts_to_case`). The
`/cases` list + `/case/{id}` detail manage them; `db.related_open_alerts` finds
open, un-cased alerts sharing a src_ip/user/host with the case so they can be
folded in. Notes live in `case_notes`. Create/add from an alert via
`/alert/{id}/case`.

**Dashboards & reporting.** The dashboard (`/`) and the print-friendly `/reports`
page (selectable 7–90d period) share `main._alert_analytics(days)` — alert
severity/status counts, an alert-volume time series (`db.alerts_over_time`), and
top-N breakdowns (`db.top_rules` / `top_alert_sources` / `top_event_sources` +
`alert_technique_counts`). Charts are pure server-rendered CSS bars via the
`templates/_macros.html` `hbar` / `timebars` macros — no JS chart lib. Exports:
`GET /reports/attack-navigator.json` (`app/navigator.py:build_layer` → an ATT&CK
Navigator layer-4.5 doc scored by technique alert volume) and `GET /alerts.csv`
(streamed, `_csv_safe`d, honours the `/alerts` filters via `db.alerts_iter`).

**UEBA / entity risk** (`app/risk.py`, on by default `UEBA_ENABLED`) moves beyond
signature rules to behaviour. `pipeline.write_stream` maintains per-event
**baselines** incrementally — `entities` (user/host/ip first/last-seen + count) and
`entity_links` (user↔ip, user↔host, host↔ip) upserted with `LEAST/GREATEST` in the
write txn (`risk.event_entities`/`event_links` are pure). The `/risk` page ranks the
**riskiest** users/hosts/IPs (`db.top_risk_entities`: attributed alerts, severity-
weighted via `risk.weight_case_sql` and recency-decayed with `power(0.5, age/half_life)`
— half-life mirrors `risk.decay`), and surfaces **anomalies**: `new_entities`
(first-seen in 24h) and `new_associations` (a link whose subject entity predates it
— an established actor with a new peer). `/entity?etype=&value=` is the per-entity
drill-down (baseline, activity, associations, alerts).

## Repository layout

```
app/
  main.py        FastAPI routes + UI (dashboard, upload, search, event, alerts, cases,
                 risk, reports, compliance, admin) + lifespan
  api.py         HTTP ingest API: POST /api/v1/ingest (API-key auth)
  config.py      env-driven settings (DB_DSN, RETENTION_YEARS, INGEST_*, SYSLOG_*, ...)
  models.py      NormalizedEvent dataclass (the common schema)
  auth.py        password hashing (pbkdf2) + role ranking + require_role dependency
  compliance.py  MITRE technique -> framework control mapping + coverage report
  util.py        tolerant parse_ts / clean_ip / to_int; hash_api_key / extract_api_key;
                 iter_json_records (+ _exceeds_json_depth deep-nesting guard);
                 gunzip_capped (bounded gzip decompression for ingest)
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
  threatintel/   matcher.py (IocIndex + classify + ti_alert) + feeds.py (parse/load) +
                 runtime.py (index singleton + feed sync + scheduler)
  triage/        suppression.py (Suppression + SuppressionIndex) + runtime.py (index)
  severity.py    canonical severity order + max_severity (case roll-up)
  navigator.py   ATT&CK Navigator layer export (pure build_layer)
  risk.py        UEBA entity/association extraction + risk scoring (pure)
  collectors/    base.py + sources.py (Okta/GitHub/GitLab) + cloud.py (AWS SigV4 /
                 Entra+M365 OAuth) + runner.py (scheduler)
  parsers/       paloalto_csv, paloalto_syslog, fortinet_fortigate, cisco_asa, cisco_ios,
                 meraki, zeek_tsv, zeek_json, crowdstrike_csv, crowdstrike_json,
                 windows_security, sysmon, linux_auditd, web_access, suricata_eve, cef,
                 leef, generic_syslog, generic_json, aws_cloudtrail, gcp_audit,
                 azure_activity, m365_audit, entra_signin, okta_system_log,
                 github_audit, gitlab_audit  (27 total)
  templates/     base, dashboard, upload, search, event, alerts, alert, cases, case,
                 risk, entity, responses, compliance, report, admin, login, _macros
  static/style.css
rules/           detection + correlation rules (Sigma-subset YAML)
playbooks/       agentless response playbooks (match + action YAML)
clients/         logocean_push.py — copy-into-your-tool helper to push to the API;
                 logocean_import.py — bulk-import a large [.gz] file in size-bounded chunks
schema.sql       events, ingest_batches, api_keys, alerts (+assignee +case_id),
                 alert_notes, suppressions, cases, case_notes, entities, entity_links,
                 detection_rules, response_actions, collectors, users, sessions,
                 audit_log, iocs
samples/         one example file per format (used by tests)
tests/           unit (DB-free): test_parsers, test_api_auth, test_streaming, test_syslog,
                 test_detection, test_pipeline, test_correlation, test_notify, test_response,
                 test_collectors, test_auth, test_audit, test_compliance
                 integration (real Postgres, marked `integration`): conftest.py +
                 test_integration_db.py + test_integration_api.py
pytest.ini       registers the `integration` marker
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
- **JSON input safety:** `util.iter_json_records` (and `detect._first_json_record`)
  reject a payload nested past `_MAX_JSON_DEPTH` (100) via `util._exceeds_json_depth`
  *before* `json.loads` — a version-stable guard against deep-nesting DoS (do **not**
  rely on the interpreter raising `RecursionError`; CPython ≥3.12 doesn't at moderate
  depths). NDJSON is unaffected (depth resets per record). Keep new JSON parsers on
  `iter_json_records` so they inherit this.
- **Compressed input:** both ingest front doors (web `/upload` and `POST
  /api/v1/ingest`) sniff the gzip magic bytes and transparently decompress via
  `util.gunzip_capped`, which reads only `limit + 1` decompressed bytes so a
  **decompression bomb** is never fully expanded — the `MAX_UPLOAD_MB` budget then
  applies to the *decompressed* size (a corrupt/oversize gzip → 413). The web-UI /
  API filename has its `.gz` stripped before `detect_format` so suffix hints still
  work. Bulk historical loads (e.g. a 3-year QRadar LEEF export) use
  `clients/logocean_import.py`, which chunks a large `[.gz]` file line-aligned under
  the limit and POSTs each chunk (idempotent ingest makes re-runs safe).

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
- **LEEF** (`leef.py`) is the format **Tripwire Log Center / Enterprise** forwards in
  (also QRadar, Juniper, Check Point). Header is pipe-delimited like CEF (real device
  vendor/product kept). Attributes are **tab**-separated in LEEF 1.0; LEEF 2.0's 6th
  header field names the delimiter — a literal char (`^`) or hex (`x09`/`0x09` for tab,
  `x5E` for caret) via `_resolve_delim`. `sev` is **1-10** (10 highest). When wrapped in
  a syslog header, the host/time before `LEEF:` are used as a fallback (kept in
  `raw.syslog_host`/`syslog_time`); if the tab separators were flattened to spaces in
  transit, it falls back to ` key=` boundary splitting. Full attribute dict (e.g. a FIM
  event's `resource`/`policy`) is preserved in `raw.attributes`.
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
- **Sysmon (`sysmon.py`)** is the key Windows **endpoint** telemetry. Same Event Log
  export shape as `windows_security` (JSON `ConvertTo-Json` / CSV), so it's told apart
  by the Sysmon provider name or the Sysmon-only `ProcessGuid` (routed **before**
  windows_security in `_detect_json`; the CSV branch checks for `sysmon` in the
  content). Named EventData (`Image`/`CommandLine`/`DestinationIp`/`TargetObject`/…)
  lives in the rendered `Message` for the `Get-WinEvent` shape, so it's parsed from the
  `Key: Value` lines (a named `EventData` object from Winlogbeat/NXLog is also honored).
  EventID → kind label; **process kinds mirror windows_security** (EID 1 →
  `process-create` like 4688, EID 5 → `process-exit`) so cross-vendor rules match both.
  The parsed fields are **lifted onto `raw`** (so `Image`/`CommandLine`/`TargetObject`
  are searchable + rule-matchable, and future Sigma-import maps directly) and
  `CommandLine` flows into `message` (so existing command-line rules fire on endpoint
  telemetry).
- **Linux auditd (`linux_auditd.py`)** — one event per line; `type=NAME
  msg=audit(EPOCH.mmm:seq):` header gives type + time + correlation id. A tolerant
  key=value scanner handles quoted values; **`USER_*` records nest acct/addr/res inside
  an inner `msg='…'` blob, which is expanded**. EXECVE `a0..aN` args are reassembled
  into the command line (so command-line rules fire on Linux); execve syscall (59/322)
  and EXECVE → `action=process-create`; login types → `logon`/`failed-logon`.
- **Web access (`web_access.py`)** — Apache/Nginx CLF & combined; the client IP →
  `src_ip`, method → `action`, the full request line → `message` (path-traversal / tool
  signatures match), status → `rule_name` + severity (4xx warning / 5xx error), size →
  `bytes_total`; the optional referer + user-agent (combined only) go in `raw`. The
  Apache `[dd/Mon/yyyy:HH:MM:SS ±ZZZZ]` stamp swaps its first `:` for a space so
  `parse_ts` reads it.
- **Generic JSON (`generic_json`)** is the JSON catch-all and the **fallback for
  unrecognized JSON** (replacing the old CrowdStrike default). It flattens one level so
  ECS keys (`source.ip`, `event.action`) resolve and maps many candidate names; vendor
  defaults to `"json"`. Keep it last in `_detect_json`.
- **Detection ordering (`detect.py`)** is specific-before-generic. JSON is routed by
  record keys: `event_type`+net → Suricata; Sysmon provider / `ProcessGuid` → Sysmon;
  `ProviderName`+`Id` → Windows;
  `eventSource`+`eventName` → CloudTrail; `Workload`+`Operation` → M365; `eventType`+
  `actor` → Okta; `userPrincipalName`/`appDisplayName` → Entra; `id.orig_h` → Zeek JSON;
  `protoPayload` → GCP; `operationName`+azure-keys → Azure; `action`+`actor` → GitHub;
  `entity_type`+`details` → GitLab; `metadata`+`event` (both) or `aid`/`cid`/… →
  CrowdStrike; else **generic_json**. Text formats match `CEF:n|`, then `LEEF:n|` (Tripwire
  Log Center / QRadar), then `%ASA-…` (numeric)
  → Cisco ASA, then `%FAC-SEV-MNEMONIC` (alpha) → Cisco IOS, then Zeek `#fields`, then PAN
  syslog, then Fortinet KV, then Meraki, then auditd (`type=… msg=audit(…):`), then
  Apache/Nginx access (CLF/combined), then CSV headers, and finally **generic syslog**.

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
(`action`, `src_ip`, `user_name`, …) or any `raw` key (case-insensitive), apply
field modifiers (`|contains`, `|cidr`, `|gte`, `|base64offset|contains`,
`|windash`, `|exists`, `|fieldref`, …), and tag with `attack.tNNNN` /
`attack.<tactic>`. **Correlation** rules use a `correlation:` block (`match` /
`group_by` / `window` / `threshold`) over normalized columns.
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

Two tiers: **unit** (DB-free, run anywhere) and **integration** (marked
`integration`, need a live PostgreSQL — they self-skip when `DB_DSN` is unset).

```bash
pip install pytest python-dateutil
PYTHONPATH=. python -m pytest tests/ -m "not integration" -q   # unit (default)

pip install httpx                                              # for the API integration test
DB_DSN=postgresql://logocean:logocean@localhost:5432/logocean \
  PYTHONPATH=. python -m pytest tests/ -m integration -q       # integration
```

Unit:

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
- `test_threatintel.py` — IOC classification, feed parsing (line/CSV/JSON), the
  IocIndex matcher (exact/CIDR/embedded), and the `ti_alert` builder.
- `test_triage.py` — suppression matching (single/AND conditions, CIDR, empty-rule
  guard) and `SuppressionIndex` first-match.
- `test_severity.py` — severity ranking + `max_severity` (case roll-up helper).
- `test_navigator.py` — ATT&CK Navigator layer scoring / sorting / gradient.
- `test_risk.py` — UEBA entity/link extraction, severity weights, half-life decay,
  decayed scoring, and the SQL weight-CASE builder.

Integration (`tests/conftest.py` provides the `pg` + `clean_db` fixtures):

- `test_integration_db.py` — schema/partition creation, GIN FTS + inet/CIDR
  search, ON CONFLICT dedup, retention purge (drops whole partitions), the
  correlation SQL, the pipeline write path raising alerts (detection +
  threat-intel) and suppressing matched ones, alert insert/dedup/queries +
  assignment/notes, case grouping (severity roll-up, related-alert discovery,
  status transitions), the alert analytics aggregations, UEBA (entity baselines,
  new-entity/new-association anomalies, risk ranking), and the IOC/suppression/
  rule-registry/api-key/user-session/collector/batch round-trips — all real Postgres.
- `test_integration_api.py` — the FastAPI stack via TestClient against a real
  DB: `/health`, API-key auth (401/200), ingest→detect end-to-end, and the
  dashboard / `/reports` / Navigator-JSON / `/alerts.csv` endpoints.

The unit tier is **DB-free** (the async-queue and pipeline tests mock the
writers); `psycopg` need only be importable. The integration tier runs against a
real PostgreSQL 16 — locally via `DB_DSN`, and in CI as a service container (see
`.github/workflows/tests.yml`: a `pytest` job per Python 3.11–3.13 for unit, plus
an `integration` job with Postgres). Run the relevant tier after any
parser/detector/pipeline/rule/`db.py` change.

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
