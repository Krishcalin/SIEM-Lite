# CLAUDE.md — SIEM-Lite / LogOcean

Guidance for Claude Code (and other agents) working in this repository.

## What this is

**LogOcean** — a self-hosted log parser, indexer, and long-term store for
**network, endpoint, cloud, and identity** logs from many vendors (**29 parsers**,
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
Entra ID, Microsoft 365, GCP Cloud Audit Logs) while other tools push findings via the ingest API. Phase 5 adds **built-in auth + RBAC**
(`AUTH_ENABLED`; roles admin/analyst/viewer, server-side sessions), an **audit
log**, and **compliance coverage** (`/compliance`: MITRE→NIST/CIS/ISO 27001/SOC 2/
PCI/HIPAA + IEC 62443 / NERC CIP for OT).
**Threat-intel enrichment** (`THREATINTEL_ENABLED`) matches events against IOC
feeds and raises alerts on hits. **Triage & tuning** adds alert assignment, notes,
suppression/allowlist rules, and **cases** (`/cases`) that group related alerts
into one investigation. **Dashboards & reporting** add charts, top-N analytics, a
print-friendly `/reports` page, and ATT&CK-Navigator / CSV exports. **UEBA**
(`UEBA_ENABLED`, `/risk`) baselines every user/host/IP and scores entity risk +
new-entity / new-association anomalies beyond the rules. **Kill-chain
reconstruction** (`KILLCHAIN_ENABLED`, `/killchain`) stitches related alerts across
ATT&CK tactics into attack stories and promotes them to cases. A **detection-engineering
workbench** (`/workbench`) maps ATT&CK coverage, flags noisy/never-fired rules, and tests
Sigma rules against sample events. An optional **AI SOC copilot** (`COPILOT_ENABLED`,
Claude) explains alerts, summarizes cases, and drafts Sigma rules from natural language.
**OT / ICS monitoring** (`/ot`) ingests **Zeek + ICSNPP** telemetry (Modbus / DNP3 /
S7comm / CIP / EtherNet-IP …), enriching it into a normalized control-plane `action`
+ `ot.*` fields, with an **ATT&CK-for-ICS** rule pack, kill-chain, Navigator layer,
a controller **asset inventory** + master→controller baselining, and **IEC 62443 /
NERC CIP** compliance — fully passive/agentless (never touches a device).

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
by whether our parsers populate the referenced field). The shipped rule pack is
90 detection + 10 correlation rules across Windows, network, AWS, GCP, Azure, Entra, Okta,
M365, GitHub, GitLab, Nutanix, OT/ICS, **Tripwire FIM** (critical-file / web-shell / persistence / monitoring-
disabled / object-removed per-event rules gated on `vendor|contains: tripwire` and
matching the changed path via `message` + LEEF `attributes.resource`, plus a
mass-change-burst correlation rule grouped by `host_name`), and a **Sysmon /
endpoint** pack that matches the fields `sysmon.py` lifts onto `raw`
(`Image`/`ParentImage`/`CommandLine`/`TargetObject`) plus the event-kind
`log_type` — office-spawns-shell, LOLBin proxy exec, registry Run-key persistence,
WMI persistence, LSASS dump, shadow-copy deletion, schtasks, command-line log
clearing. Command-line rules match `CommandLine` OR `message` so they also fire on
non-Sysmon sources that fill `message`. The pack also includes an **OT / ICS**
group (8 per-event + 1 correlation) tagged with **ATT&CK for ICS** (`T0NNN`)
matching the Zeek-ICSNPP enrichment (`action` / `log_type` / `ot.*`) — see the OT
section below, and a **Nutanix Prism Central** group (VM/cloud-instance deletion via
the REST API gated on `action: DELETE` + `restEndpoint|contains: /vms/`, cluster
unregister/detach and user/role/auth change matched on the audit `message`, plus a
Flow microseg drop-burst correlation grouped by `src_ip`), and a **Nutanix Files /
Data Lens** group (ransomware-extension / ransom-note write gated on `action` in
create/write/rename + `rule_name|endswith` a known crypto extension, share ACL
`security-change`, plus a mass-file-deletion-per-`user_name` correlation). On top of
that base, the **detection-coverage programme** (phases 2–5, see below) added a
high-fidelity **Windows/Sysmon endpoint** pack, a **cloud + identity** pack
(GCP/Azure/GitLab/Okta/M365/GitHub), a **Linux + web-exploitation** pack (auditd TTPs +
`T1190` SQLi/traversal/cmd-injection/XSS/web-shell + Suricata IDS passthrough), and
**cardinality (distinct-count) correlation** (password spray / distributed brute force /
port scan / host sweep). Shipped total: **90 detection + 10 correlation rules**.

**OT / ICS monitoring** (`app/parsers/zeek_ics.py`). LogOcean is passive/agentless
for OT — it never touches a device, only ingests sensor telemetry. **Zeek + ICSNPP**
(CISA/INL Industrial Control Systems Network Protocol Parsers) writes `modbus.log` /
`dnp3.log` / `s7comm.log` / `cip.log` … in the usual Zeek `#fields` shape; the Zeek
parsers call `zeek_ics.enrich(path, row)` which — for an OT `#path` — lifts the
control-plane operation onto the normalized **`action`** (`write-registers` /
`plc-stop` / `program-download` / `cold-restart` / `disable-unsolicited` /
`write-attribute` …), sets `log_type` to the canonical protocol, and adds an
**`ot.*`** dict to `raw` (`ot.protocol`, `ot.operation` = read/write/control,
`ot.is_write`, `ot.function_code`, `ot.unit_id`, `ot.address`, …) so every OT field
is rule-matchable without a schema change. The OT rule pack (`rules/ot_*.yml` +
`rules/correlation_ot_scan.yml`) matches on those. ATT&CK for ICS also flows into
kill-chain reconstruction (the ICS tactics `evasion` / `inhibit-response-function` /
`impair-process-control` are merged into `KILL_CHAIN_TACTICS` for one IT→OT chain)
and the Navigator export (`build_layer(..., domain="ics-attack")`, served at
`/reports/attack-navigator.json?domain=ics-attack`; ICS techniques are `T0NNN`).
`enrich` is pure/DB-free; `zeek_ics` is an enrichment helper, **not** a registered
parser (so `PARSERS` is still 27). Serial Modbus and L2 GOOSE/SV need a sensor that
sees them; OT response stays passive (alert / IT-boundary enforcement, never a
device command).

**OT analysis (`/ot`, Phase D).** `app/ot.py` is pure (asset/conversation
classification + activity roll-up); `db.ot_assets` / `db.ot_conversations` /
`db.ot_activity_summary` do the SQL aggregation over `events` (filtered to
`OT_PROTOCOLS`, the single source of truth `db` imports from `ot`; `raw->'ot'->>...`
reads the enrichment). The `/ot` page shows a **controller asset inventory** (dst_ip =
the PLC/RTU server side), **master→controller conversations** classed by
`ot.classify_conversation` (`new-writer` = a source first seen in 24h already issuing
write/control — the key OT signal; `new` / `known` otherwise), and read/write/control
volume per protocol. All read-only over events — no schema change, no ingest-path
touch. The **IT→OT conduit-violation** rule (`rules/ot_it_to_ot_write.yml`) is a
Sigma-subset rule using `src_ip|cidr` / `dst_ip|cidr` selections to flag a
write/control command crossing the IT→OT boundary (Purdue / IEC 62443 zone model);
the CIDRs are operator-tuned placeholders (sample lab range 10.60.0.0/16).

**OT compliance (Phase E).** `app/compliance.py` adds **IEC 62443-3-3** (System
Requirements) and **NERC CIP** frameworks, with `MAP` entries for the ICS techniques
(T0855/T0836/T0843/T0889/T0858/T0813/T0816/T0814/T0878/T0846) → IEC SRs + CIP
standards (+ NIST 800-53). The `/compliance` view iterates `FRAMEWORKS` generically,
so enabling the OT rule pack lights up the mapped OT controls automatically. The 10
enterprise techniques additionally carry **NIST 800-53 / CIS v8 / ISO 27001 (2022
Annex A) / SOC 2 (Trust Services Criteria) / PCI DSS v4 / HIPAA** control mappings;
add a new framework by giving each technique a `MAP[tech][framework]` list and adding
it to `FRAMEWORKS` — the report + page pick it up with no other change.

**Alert actions** (`app/alert_actions.py`) fan each *newly-raised* alert (gathered
post-commit via `insert_alerts(return_inserted=True)`) to two background workers:
`notify` (webhook/email channels, filtered by `NOTIFY_MIN_LEVEL`) and `response`
(agentless playbooks in `playbooks/*.yml` — a webhook POST to your automation/SOAR
endpoint or a `log` action, audited in `response_actions`). Both run on their own
threads so slow network I/O never blocks ingest. A playbook `revert_after` makes
the action **time-boxed**: `engine.execute` stamps `revert_at`, and `response/revert.py`
(a `RevertScheduler` polling every `RESPONSE_REVERT_INTERVAL`s) fires the inverse
intent — `block_ip`→`unblock_ip`, `disable_user`→`enable_user`, … (`_REVERT_MAP`,
generic `revert_<x>` fallback) — once it passes, then sets `reverted_at` so each
action is undone exactly once (stamped even on webhook failure so a bad endpoint
can't wedge the loop). The revert is itself audited as a `response_actions` row.

**Collectors** (`app/collectors/`) are agentless pull connectors: a scheduler runs
each enabled, credential-configured collector every `COLLECTOR_INTERVAL`, fetching
new records since a stored `cursor` (the `collectors` table) and feeding them
through `ingest.ingest(..., source_type="collector")` — so pulled logs get the same
detect/alert/respond treatment. Token sources (Okta/GitHub/GitLab) live in
`sources.py`; signed/OAuth sources in `cloud.py` — **AWS CloudTrail** (`LookupEvents`,
SigV4-signed via stdlib `hmac`/`hashlib`), **Entra ID** sign-ins (Microsoft Graph) and
**Microsoft 365** unified audit (Office 365 Management Activity API), the latter two
using the OAuth2 client-credentials flow. **GCP Cloud Audit Logs** live in `gcp.py`
(Cloud Logging `entries:list`) and authenticate with a service-account **signed-JWT**
grant — the RS256 JWT is signed by hand (a tiny DER reader pulls the PKCS#8 key's
modulus/exponent; the signature is `pow(m, d, n)`), so no crypto dependency is added.
Each collector re-shapes vendor JSON into the
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

**Saved searches.** Analysts name and re-run event/alert queries. A saved search is
a `(owner, name, path, query)` row (`saved_searches` table); `path` is `/search` or
`/alerts`, `query` is the URL query string. `app/saved.py` is pure — it validates the
path against an allow-list, strips paging/empties from the query, and builds the
runnable target URL — so the `POST /searches` / `POST /searches/{id}/delete` routes
stay thin. Both pages render a saved-list + "Save current" form via the
`_macros.html:saved_searches` macro. Rows are per-user (`owner` = username, or `''`
when `AUTH_ENABLED` is off); delete is owner-scoped and both actions are audited.

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

**Kill-chain reconstruction** (`app/killchain.py`, pure; `app/killchain_runtime.py`,
DB-backed; on by default `KILLCHAIN_ENABLED`) stitches related alerts into **attack
stories**. `build_chains` links alerts that share an entity (user/host/ip) and fall
within `KILLCHAIN_MAX_GAP_MINUTES` — single-linkage along each entity's timeline via a
union-find, so a campaign chained through intermediate alerts stays one story. A group
qualifies only when it spans ≥ `KILLCHAIN_MIN_TACTICS` distinct ATT&CK tactics (tactic
order in `KILL_CHAIN_TACTICS`). `summarize_chain` emits kill-chain-ordered **stages**,
pivot **entities** (shared by ≥2 alerts), rolled-up severity (`severity.max_severity`),
a narrative, and a stable **signature** (hash of the alert-set). The `/killchain` page
reconstructs live from `db.recent_uncased_alerts` (open, non-suppressed, un-cased in the
window) and promotes a story to a case via `db.create_case_from_story` (reuses
`create_case` + `add_alerts_to_case`; `cases.source='killchain'`, `kc_signature` set).
`KILLCHAIN_AUTOCREATE` runs `killchain_runtime.KillChainScheduler` to auto-promote
stories at/above `KILLCHAIN_MIN_SEVERITY`, de-duped by open `kc_signature`. Reconstructing
over *un-cased* alerts makes it naturally idempotent.

**Detection-engineering workbench** (`app/workbench.py`, pure; `/workbench`) tunes the
rule pack. `coverage_map` groups the rule registry by ATT&CK tactic (kill-chain-ordered
via `killchain.tactic_rank`) and reports techniques covered by **enabled** rules vs gaps
(techniques only on disabled rules), plus an overall %. `rule_health` buckets rules into
noisy / never-fired / stale / disabled from `db.rule_stats(days)` (per-rule all-time +
windowed alert counts via LEFT JOINs, `WORKBENCH_WINDOW_DAYS` / `WORKBENCH_NOISY_THRESHOLD`).
`test_rule(rule_yaml, event_json)` evaluates a Sigma-subset rule against a sample event
with the **production** engine internals (`de.rule_from_dict` + `flatten_event` +
`_eval_selection` + `match_rule`), returning per-selection booleans, logsource match, and
the verdict — never raising on bad input. All three are pure functions over rule dicts.

**AI SOC copilot** (`app/copilot/`, `COPILOT_ENABLED`, off by default) adds Claude-powered
help at three points. `prompts.py` is **pure** (prompt builders for alert-explain /
case-summary / Sigma-from-NL + `extract_yaml` / `valid_sigma` for parsing the reply);
`client.py` wraps the `anthropic` SDK (imported **lazily** so the app runs without the
dep), resolves the key from `COPILOT_API_KEY` or `ANTHROPIC_API_KEY`, and exposes
`explain_alert` / `summarize_case` / `generate_sigma` that take an injected client (→
unit-testable with a fake, no network). Model is `COPILOT_MODEL` (default
`claude-opus-4-8`). Routes `/alert/{id}/explain`, `/case/{id}/summarize`, and
`/workbench/generate` (the last loads the generated rule into the workbench tester) are
analyst-gated + audited, degrade gracefully when unconfigured (`is_configured()`), and
never leak a raw traceback (`CopilotError`). `/health` reports copilot status.

## Repository layout

```
app/
  main.py        FastAPI routes + UI (dashboard, upload, search, event, alerts, cases,
                 killchain, risk, reports, workbench, compliance, admin) + lifespan
  api.py         HTTP ingest API: POST /api/v1/ingest (API-key auth)
  config.py      env-driven settings (DB_DSN, RETENTION_YEARS, INGEST_*, SYSLOG_*, ...)
  models.py      NormalizedEvent dataclass (the common schema)
  auth.py        password hashing (pbkdf2) + role ranking + require_role dependency
  compliance.py  MITRE technique -> framework control mapping + coverage report
                 (NIST/CIS/ISO 27001/SOC 2/PCI/HIPAA + IEC 62443-3-3 / NERC CIP for ICS)
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
                 revert.py — stateful auto-revert of time-boxed actions (scheduler)
  threatintel/   matcher.py (IocIndex + classify + ti_alert) + feeds.py (parse/load) +
                 runtime.py (index singleton + feed sync + scheduler)
  triage/        suppression.py (Suppression + SuppressionIndex) + runtime.py (index)
  severity.py    canonical severity order + max_severity (case roll-up)
  navigator.py   ATT&CK Navigator layer export (pure build_layer)
  risk.py        UEBA entity/association extraction + risk scoring (pure)
  killchain.py   kill-chain reconstruction: chain-building + story summary (pure)
  killchain_runtime.py  DB-backed reconstruct + auto-create scheduler
  ot.py          OT/ICS analytics: OT_PROTOCOLS + asset/conversation classification (pure)
  workbench.py   detection workbench: rule tester + coverage map + rule health (pure)
  coverage.py    ATT&CK (enterprise+ICS) + ATLAS detection-coverage scoreboard (pure)
  saved.py       saved-search path/query validation + target-URL building (pure)
  sigma_import.py  translate community SigmaHQ rules -> our engine (logsource gate; pure)
  copilot/       AI SOC copilot: prompts.py (pure) + client.py (Claude SDK wrapper)
  collectors/    base.py + sources.py (Okta/GitHub/GitLab) + cloud.py (AWS SigV4 /
                 Entra+M365 OAuth) + gcp.py (GCP signed-JWT) + runner.py (scheduler)
  parsers/       paloalto_csv, paloalto_syslog, fortinet_fortigate, cisco_asa, cisco_ios,
                 meraki, zeek_tsv, zeek_json, zeek_ics (OT/ICS enrichment helper — not a
                 registered parser), crowdstrike_csv, crowdstrike_json,
                 windows_security, sysmon, linux_auditd, web_access, suricata_eve, cef,
                 leef, generic_syslog, generic_json, aws_cloudtrail, gcp_audit,
                 azure_activity, m365_audit, entra_signin, okta_system_log,
                 github_audit, gitlab_audit, nutanix_pc, nutanix_files  (29 total)
  templates/     base, dashboard, upload, search, event, alerts, alert, cases, case,
                 killchain, risk, entity, ot, responses, compliance, report, coverage,
                 workbench, admin, login, _macros
  static/style.css
rules/           detection + correlation rules (Sigma-subset YAML)
playbooks/       agentless response playbooks (match + action YAML)
clients/         logocean_push.py — copy-into-your-tool helper to push to the API;
                 logocean_import.py — bulk-import a large [.gz] file in size-bounded chunks
schema.sql       events, ingest_batches, api_keys, alerts (+assignee +case_id),
                 alert_notes, suppressions, cases, case_notes, entities, entity_links,
                 detection_rules, response_actions (+reverted_at), collectors, users,
                 sessions, audit_log, iocs, saved_searches
samples/         one example file per format (used by tests)
tests/           unit (DB-free): test_parsers, test_api_auth, test_streaming, test_syslog,
                 test_detection, test_pipeline, test_correlation, test_notify, test_response,
                 test_collectors, test_auth, test_audit, test_compliance, test_threatintel,
                 test_triage, test_severity, test_navigator, test_risk, test_compression,
                 test_killchain, test_workbench, test_copilot, test_hardening, test_ot,
                 test_saved, test_coverage, test_sigma_import, test_rule_quality,
                 test_medium_hardening
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
  `iter_json_records` so they inherit this. A parser that must decode JSON itself
  (it also handles CSV, e.g. `windows_security`/`sysmon`, or is NDJSON-first like
  `suricata_eve`/`crowdstrike_json`) MUST use `util.json_or_none` (depth-guarded +
  `RecursionError`-safe) — never a bare `json.loads`, which can `RecursionError` on a
  deep payload and abort the whole batch.
- **Untrusted numeric fields:** coerce ports through `util.to_port` (0-65535) and all
  other integers through `util.to_int` (rejects anything outside signed 64-bit). A raw
  `int()` lets a hostile field (`srcport=9999999999`, a 20-digit `bytes=`) overflow the
  typed `integer`/`bigint` column and roll back the entire 5000-row insert chunk.
  `db._row` also clamps ports as a last line of defense for every parser.
- **Detection is exception-isolated:** `DetectionEngine.evaluate_event` runs each rule
  in its own try/except (one bad rule — e.g. an invalid `|re` pattern — can't sink the
  rest) and `pipeline.write_stream` wraps per-event detection + threat-intel so a
  failure stores the event un-alerted instead of aborting the batch. (Residual: `re`
  has no timeout, so a catastrophic-backtracking pattern in an *operator-authored* rule
  can still hang — validate rule regexes.)
- **Remote reads are size-capped:** server-side fetches of a threat-intel feed
  (`feeds.load_feed_source`) or a collector endpoint (`collectors.base._http_get/post`)
  go through `util.read_capped`, so a malicious/compromised remote can't OOM the process.
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
- **Zeek ICS/OT (`zeek_ics.py`)** — when the Zeek `#path` (TSV) or `_path` (JSON) is an
  ICSNPP protocol (`modbus[_detailed]` / `dnp3` / `s7comm[_plus]` / `cip` / `enip` /
  `bacnet` / …, see `PATH_PROTOCOL`), the Zeek parsers call `enrich()` to override
  `action` with the control-plane operation and attach `raw["ot"]`. `log_type` becomes
  the *canonical* protocol (so `modbus_detailed` → `log_type: modbus`) — OT rules target
  `log_type`/`service`, not the raw path. Modbus `func` may be a string
  (`WRITE_MULTIPLE_REGISTERS`) or numeric (`_MODBUS_FUNC` table); DNP3 keys off
  `fc_request`, S7comm off `function_name` (`download`→`program-download`,
  `stop`→`plc-stop`), CIP off `cip_service`. `enrich` never raises — an unknown func
  still yields a `protocol` tag.
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
- **Nutanix Prism Central (`nutanix_pc.py`)** — the private-cloud/HCI management plane,
  forwarded to remote syslog on three **tags** (program names) the parser routes on:
  `api_audit` (REST calls; `INFO <ts> k=v||k=v||…` **double-pipe** kv — `httpMethod` →
  `action`, `restEndpoint` → `rule_name`), `consolidated_audit` (a **JSON** audit/alert
  record — `operationType` → `action`, `clientIp` → `src_ip`, `defaultMsg` → `message`,
  `recordType` → `log_type`, `creationTimestampUsecs` → time; camelCase syslog **or**
  snake_case v3-API export both resolve via an underscore-folding key index), and
  `flow-hitCountN` (Flow Network Security microseg hits — `SRC/DST/PROTO/SPORT/DPORT/
  ACTION` 5-tuple + `ORIG:`/`REPLY:` `BYTES` **summed** into `bytes_total`, `ACTION` →
  `action`, policy name → `rule_name`). Envelope `<PRI>ISO-ts host tag:` is stripped
  first (PRI → severity fallback); a whole-document `{`/`[` payload is treated as an
  **offline JSON export** of the audit trail. Detected before generic syslog by the
  `api_audit|consolidated_audit|flow-hitCount` tag regex (and a bare-JSON export by the
  `affectedEntityList`+`operationType`/`recordType` keys in `_detect_json`).
- **Nutanix Files / Data Lens (`nutanix_files.py`)** — SMB/NFS **file-access audit**
  from the Files **partner-server** notification stream (`vendor_name: syslog`, :1468),
  the same stream Data Lens analyses. Records are JSON — bare object / array / NDJSON,
  a File-Analytics/Data-Lens export, or a JSON payload inside a `<PRI>ts host tag:`
  syslog envelope (stripped first). The exact on-wire **key spelling varies by Files
  version** (public docs wall the schema), so the mapper **folds case + underscores**
  and accepts common snake_case/camelCase names for each verified field: operation /
  object_name(+old) / user_name / client_ip / share_name / protocol_type / status /
  audit_timestamp_usecs. The **operation enum** (`FILE_CREATE`/`FILE_DELETE`/`FILE_READ`/
  `FILE_WRITE`/`DIRECTORY_*`/`RENAME`/`SECURITY`) → normalized `action`
  (create/delete/read/write/rename/security-change) so rules + the mass-delete /
  ransomware correlations match regardless of spelling; path → `rule_name`, share →
  `app`, denied status → `warning`. A Data Lens ransomware/anomaly alert on the stream
  maps to product `data-lens`, `log_type: ransomware-alert`, `severity: critical`.
  **Detected before JSON routing** by the operation-enum regex `_NUTANIX_FILES_RE`
  (works bare or syslog-wrapped), with a `_detect_json` fallback on
  `object_name`+`client_ip`/`share_name` keys.
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
  CrowdStrike; else **generic_json**. **Nutanix Files** file-audit is caught *before*
  JSON routing by the operation-enum regex (bare or syslog-wrapped). Text formats match
  `CEF:n|`, then `LEEF:n|` (Tripwire
  Log Center / QRadar), then `%ASA-…` (numeric)
  → Cisco ASA, then `%FAC-SEV-MNEMONIC` (alpha) → Cisco IOS, then Zeek `#fields`, then PAN
  syslog, then Fortinet KV, then Meraki, then Nutanix PC (`api_audit`/
  `consolidated_audit`/`flow-hitCount` tags), then auditd (`type=… msg=audit(…):`), then
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

**Rule metadata + coverage (Phase 0 of the detection-coverage programme,
`docs/DETECTION_COVERAGE_ROADMAP.md`).** Rules carry optional metadata parsed by
`engine.rule_from_dict` / `correlation.load_correlation_rules`: `fidelity`
(`high`/`medium`/`hunt`, default `medium`), `data_source` (list or comma-string of
ATT&CK-style keys), `references`, and **ATLAS** tags `atlas.aml.tNNNN` (→ a rule's
`atlas_techniques`, alongside the `attack.tNNNN` → `techniques`). `app/coverage.py`
(pure) computes the scoreboard: per-technique/tactic/fidelity/data-source ATT&CK
coverage (enterprise + ICS split) + the curated `ATLAS_MATRIX` (0% until AI/LLM
telemetry lands), and ATT&CK **Navigator** layers scored by *rule coverage* (via
`navigator.build_layer(..., comment_suffix="rule(s)")`). Surfaced at **`/coverage`**
(+ `/coverage.json`, `/coverage/attack-navigator.json?domain=enterprise|ics`) and the
`scripts/coverage_report.py` CLI. **`tests/test_rule_quality.py` is the CI rule-linter**
— unique ids, required title/description, valid level/fidelity, ≥1 `attack.*`/`atlas.*`
tag; every new rule must pass it. When adding a rule, set `fidelity` + `data_source` so
the scoreboard stays accurate.

**Importing community SigmaHQ rules (Phase 1, `app/sigma_import.py`).** `translate(sigma_doc)`
→ `(our_rule_dict | None, skip_reason)`. Design: Sigma `logsource` (category/product/service)
maps to a **gate selection** over our normalized fields (`process_creation` → `{action:
process-create}`, `registry_set` → `{action: [registry-set, registry-add-delete, ...]}`,
`network_connection` → `{action: network-connect}`, windows `security` service → `{vendor:
microsoft, log_type: security}`, cloud by product → `{vendor: aws|gcp|okta|github|microsoft}`),
which is AND-ed into the condition as a synthetic `_lo_logsource` selection (so `logsource:` stays
empty and no engine change is needed). Sigma **field names pass through** — our Sysmon/endpoint
parsers already lift `Image`/`CommandLine`/`TargetObject`/`DestinationPort` onto `raw`, and the
engine resolves raw keys case-insensitively. **Honest skips** with a reason: `unmapped-logsource:*`,
`unsupported-modifier:*` (mods outside `_SUPPORTED_MODS` — utf16/wide/expand/gzip…),
`aggregation-condition` (a `|` count()/near in the condition), `sigma-correlation` (deferred to
Phase 5), `status-deprecated`/`status-unsupported`. Imports carry `fidelity: medium`, `data_source`
from the mapped category, DRL attribution (original id/author + SigmaHQ reference), and id
`sigma-<uuid>`. `engine._rule_files` loads `rules/` **and** `rules/imported/` (the CLI
`scripts/import_sigma.py --src <sigma>/rules --write` target; gitignored, generated per-deployment).
Sample Sigma-format fixtures live in `samples/sigma/`; tests in `tests/test_sigma_import.py`.

**Content + engine phases 2–5 of the detection-coverage programme.** Each hand-authored pack
ships with a positive **and** a benign-negative test and had every hardcoded indicator
adversarially verified against public sources before merge.
- **Phase 2 — Windows/Sysmon high-fidelity endpoint pack** (`rules/sysmon_*.yml`,
  `rules/windows_local_account_created.yml`): LSASS memory access, credential-dumper tools,
  NTDS/SAM extraction, remote-thread injection, BYOVD driver load, UAC registry hijack,
  LSA/AppInit persistence, WDigest, Defender-disable, AMSI/ETW tamper, PsExec/msiexec/BITS,
  Cobalt Strike pipes. Grounding required extending `sysmon.py` `_LIFT` with the EID 6/7/8/10
  fields (`SourceImage`/`TargetImage`/`GrantedAccess`/`ImageLoaded`/…) so rules match the
  rendered-`Message` `Get-WinEvent` export, not only shipper `EventData`.
- **Phase 3 — cloud + identity pack** (`rules/aws_*`, `gcp_*`, `azure_*`, `gitlab_*`, `okta_*`,
  `m365_*`, `github_*`): first-time GCP/Azure/GitLab coverage. Cloud rules key on `action`
  (= eventName/methodName/operationName/Operation/eventType) + bare-keyword search over the
  flattened `raw` (so a value in `requestParameters` / IAM policy bindings matches). **GitLab
  rules must key on the literal underscore `event_name` or discrete `details.*` fields, NOT
  human-readable prose** — a lesson from two rules that matched zero real events until fixed.
- **Phase 4 — Linux + network + web-exploitation pack** (`rules/web_*`, `suricata_*`, `linux_*`):
  web rules gate via a **detection selection** `log_type: [access, http]` (a list in `logsource`
  fails — the matcher is scalar-only), so one rule fires across Apache/Nginx + Zeek + Suricata
  HTTP. Linux rules key on the auditd EXECVE command `sysmon.py`-style. `|contains`/`|re` are
  case-insensitive by default.
- **Phase 5 — behavioural (engine growth, in progress).** `db.correlate` gained an optional
  whitelisted `distinct_col` → `count(distinct <col>)` (see `CorrelationRule.distinct_field`,
  loader key `distinct_count`); a load-time warning fires if the named column isn't in
  `_CORR_COLS`. Enables spray / distributed-brute-force / port-scan / host-sweep. Next:
  temporal-sequence correlation + GeoIP/ASN enrichment → impossible-travel.

Current scoreboard (`scripts/coverage_report.py`): **ATT&CK Enterprise ~82 techniques, ICS 11,
ATLAS 0/31; high-fidelity 36**. When adding a rule, keep IOC lists to indicators you can
corroborate, set `fidelity` + `data_source`, and ship a fire-test.

## Adding a response playbook

Drop a YAML file in `playbooks/` with a `match` (any of `rule_id` / `min_level` /
`techniques`) and an `action` (`type: log`, or a webhook intent like `block_ip`
with a `target` alert field). Webhook actions POST `{playbook_id, action, target,
alert}` to `RESPONSE_WEBHOOK_URL` (your automation/SOAR endpoint) — LogOcean stays
agentless and lets that platform enforce. Add `revert_after: <seconds>` to make the
action time-boxed — LogOcean auto-fires the inverse intent when it expires (see
`response/revert.py`; extend `_REVERT_MAP` for a new action's inverse). Every run is
audited in `response_actions` and shown at `/responses`. Matching/execution/revert is
tested in `tests/test_response.py`.

## Adding a collector

Subclass `collectors.base.Collector` in `app/collectors/sources.py` with `name`,
`fmt` (an existing parser key), `configured()`, and `fetch(cursor) -> FetchResult`
(content text + advanced cursor). Keep the HTTP call in `_http_get` and make the
URL builder + cursor advancement pure functions so they're testable without
network (see Okta/GitHub/GitLab + `tests/test_collectors.py`). Register it in
`runner.build_collectors()` and add its credentials to `config.py`/`.env.example`.
The framework persists the cursor, feeds the response through `ingest.ingest`, and
shows status on the Admin page. Sources needing request signing or OAuth live in
`cloud.py` (AWS SigV4, Entra/M365 client-credentials) or `gcp.py` (service-account
signed-JWT) — keep the signing/token logic pure and unit-tested. When a vendor
needs an SDK you'd rather not add, prefer the **push** path: have an external job
pull + POST to the ingest API.

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
- `test_detection.py` — Sigma-subset matching, all field modifiers + condition
  grammar, and the shipped rule library — incl. the Tripwire-FIM and Sysmon/endpoint
  packs, plus existing rules firing on Sysmon / auditd telemetry.
- `test_pipeline.py` — inline detection in `write_stream` (DB inserts mocked).
- `test_correlation.py` — correlation rule loading, window parsing, alert dedup.
- `test_notify.py` — severity routing, payload builders, the dispatcher thread.
- `test_response.py` — playbook loading/matching, action execution, the worker,
  and stateful auto-revert (inverse-intent mapping, revert execution, sweep glue).
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
- `test_saved.py` — saved-search path/query normalization, target-URL building,
  and validation (the pure helpers behind `/searches`).
- `test_risk.py` — UEBA entity/link extraction, severity weights, half-life decay,
  decayed scoring, and the SQL weight-CASE builder.
- `test_compression.py` — gzip ingest decompression (`gunzip_capped`: round-trip /
  bomb-guard / corrupt / multi-member) and the bulk-import client's line-aligned
  size-bounded chunker.
- `test_killchain.py` — tactic ordering/normalisation, entity extraction, chain
  building (single-linkage, time-gap split, min-tactics qualification, noise
  exclusion), story summary (stage order, severity roll-up, pivot entities,
  signature stability), and reconstruction ordering.
- `test_workbench.py` — rule tester (match / logsource-mismatch / selection-miss /
  field-alias / bad-input), coverage map (counts, gaps, covered-wins-over-disabled,
  kill-chain tactic order), and rule-health bucketing (noisy / never-fired / stale /
  disabled + sorting).
- `test_copilot.py` — copilot prompt builders (alert/case/Sigma), Sigma extraction
  (fenced / bare / prose→None) + validation, and the explain/summarize/generate
  operations against a fake client (no SDK/key/network); config-gating checks.
- `test_hardening.py` — ingest input hardening: the JSON deep-nesting depth guard,
  gzip decompression-bomb cap, oversize-payload rejection, and numeric-overflow
  coercion on hostile log fields.
- `test_ot.py` — OT/ICS: `zeek_ics.enrich` protocol mapping (Modbus/DNP3/S7comm/CIP,
  string + numeric func), the Zeek parsers lifting `action`/`ot.*` from the ICS
  samples, the OT rule pack firing on malicious ops (and staying quiet on reads),
  ICS technique tags, the OT-scan correlation rule, and the Phase-D OT analytics
  (`is_ot_protocol`, conversation classification/ordering, activity roll-up).

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
- **Response hardening (always on):** `auth_guard` attaches security headers to
  every response — `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, and a CSP with `frame-ancestors 'none'`
  (server-rendered UI, so `'unsafe-inline'` style/script is fine). When
  `AUTH_ENABLED`, state-changing UI requests (POST/PUT/PATCH/DELETE, excluding
  `/api/*`) also get a **CSRF** same-origin check (`_csrf_same_origin`: Origin/Referer
  host must match; absent → allowed since the session cookie is SameSite=Lax).
- **Last-admin guard:** `db.is_last_admin` prevents demoting/disabling the final
  enabled admin (self-lockout) on the `/admin/users/*` routes.
- Security-relevant actions (login/logout, purge, key/rule/collector/user changes,
  alert triage, upload, saved-search create/delete) are recorded in `audit_log` via
  `main._audit(...)` and shown on the Admin page.
- The Postgres volume IS the 3-year archive — back it up.
- Don't commit `.env`, uploads, or `pgdata/` (already in `.gitignore`).
