# LogOcean → Splunk-Class SIEM — Transformation Plan of Action

> **Basis:** a 9-agent deep-research pass (Splunk core platform · Enterprise Security · SOAR ·
> UBA · data onboarding · SPL/scale), a completeness critique, and an adversarial plan review,
> mapped against LogOcean's current capabilities. Every recommendation is constrained to the
> LogOcean **charter**: pure-Python, single-PostgreSQL, self-hosted, offline / air-gap, agentless,
> no heavy dependencies.
>
> **Scope:** 8 leverage-ordered phases · a 104-capability gap map across 10 pillars · onboarding
> plans for 10 named sources.

---

## Executive summary — not a rewrite, a backbone upgrade then breadth

LogOcean already owns the hard SIEM primitives: agentless collectors, 29 parsers + auto-detect,
a native Sigma-subset detection engine, correlation, kill-chain stitching, cases, SOAR-lite
playbooks with auto-revert, decayed entity-risk UEBA, threat-intel matching, and an 8-framework
compliance map — all pure-Python on one Postgres. Reaching Splunk parity is **not a rewrite**; it
is building the **two backbones every Splunk feature secretly depends on**, then broadening
onboarding and layering enrichment, risk, statistics, orchestration, reporting, and scale on top.

- **Backbone 1 — LOQL** *(shipped, `ec1ed09` — `app/loql/`, `docs/LOQL.md`)*: a composable piped
  `filter | stats | eval | where | timechart` language that compiles to **parameterized SQL** over
  the partitioned event store. Search, dashboards, data models, RBA, acceleration, federation and
  unbypassable RBAC all hang off it.
- **Backbone 2 — CIM-equivalent normalization** *(shipped — `app/cim/`, `docs/CIM.md`)*: a versioned
  data-model layer over the flat `NormalizedEvent` (Authentication, Network, Web, DNS, Endpoint,
  Change, Malware, IDS, **Industrial/OT**, Email, Vulnerability) so detections bind to a **data
  model, not a vendor**. Membership is a plain, GIN-indexed `events.cim_models text[]` stamped in
  Python at ingest, plus one `cim_<tag>` view per model.
- **Then:** onboarding breadth (EDR/cloud/flow/vuln + the 10 named sources) → asset/identity +
  enrichment fabric → Risk-Based Alerting → statistical UEBA → real SOAR → reporting/metrics →
  scale, multi-tenancy & chain-of-custody.

## North star & positioning

LogOcean is the sovereign, self-hosted, pure-Python answer to Splunk Enterprise + Enterprise
Security + SOAR + UBA: any source onboarded agentlessly and normalized into a versioned CIM;
analysts hunt with a piped query language; detections and statistical anomalies deposit **scored
risk against resolved asset/identity entities** so a handful of context-weighted notables replace
thousands of raw alerts; playbooks orchestrate response behind mandatory human approval and sync
bidirectionally to the SOC's ServiceNow/Jira; investigations reconstruct the attack with full
chain-of-custody — on one PostgreSQL, no per-GB fee, no internet dependency, no black-box ML.

Differentiate on **sovereignty and economics**, not on out-scaling the distributed engine:

1. **No per-GB license** — the single lever that dominates Splunk TCO. Ingest and multi-year
   retention scale on commodity disk, not an entitlement.
2. **Air-gap & sovereign** — every capability works fully offline with side-loadable file bundles;
   runs in classified/defense/OT/regulated enclaves Splunk Cloud can't reach.
3. **One app + one DB** — replaces the forwarder / heavy-forwarder / indexer-cluster /
   search-head-cluster / deployment-server tiers. Agentless: nothing on endpoints.
4. **Transparent** — data-not-code parsers/rules/models/playbooks, deterministic statistics instead
   of opaque ML, a compiler that enforces access control unbypassably.

**The honest trade-off (state it to buyers):** a single-Postgres core has a scale ceiling (tens of
millions to low-billions of events with rollups + cold-tier archival) versus Splunk's petabyte
distributed scale. LogOcean's answer is **horizontal federation of independent sovereign nodes** —
the right design for per-tenant/per-region sovereignty anyway — not clustering a distributed store.
Lead with that story and publish real volume benchmarks; never imply petabyte parity.

## Hardened by adversarial review — what the plan review changed

An adversarial review caught real charter-breaks and sequencing errors. **These are folded into the
roadmap below.**

**Charter-risk substitutions (mandated):**

- **Statistics run in SQL, not Python.** Use Postgres `percentile_cont`, `stddev_samp`, `corr`,
  `regr_*` + two-pass median/MAD. A CPython loop over millions of entity-metrics *will* force a
  numpy import — the highest-probability accidental charter break.
- **OIDC native; SAML via proxy.** Hand-rolled XML-DSig canonicalization is an auth-bypass minefield.
  Do OIDC (RS256, reusing the GCP RS256 pattern); for SAML, document reverse-proxy header auth.
- **PDF = SVG-in-PDF or HTML+print.** "Embedded PNG charts" needs a forbidden rasterizer. Ship
  HTML+CSV first; only a minimal vendored pure-Python PDF with **vector SVG** later.
- **"AI copilot" → deterministic explainer.** A generative copilot can't be offline + no-ML; keep
  the core explainer deterministic (built from anomaly math), scope any LLM as an optional
  side-loaded add-on clearly outside core.
- **GeoIP:** side-load the customer's licensed MaxMind DB + ship an openly-redistributable RIR-derived
  ASN/CIDR table as the offline default. **Cold tier = gzip-JSONL only** (parquet pulls pyarrow).

**Pulled earlier + newly added:**

- **Secrets vault before the collector wave** (Phase 2 stands up a dozen collectors holding
  CrowdStrike/AWS/Graph credentials; today they're plaintext env vars).
- **Query-cost guardrails + job-kill from day one** (the moment LOQL compiles to SQL on the shared
  instance, one heavy query can starve ingest).
- **A single-Postgres performance + storage-sizing benchmark spike** as a *gating deliverable* — the
  cost thesis rests on sustained EPS and bytes/event.
- **jsonb/BRIN index strategy & multi-value fields in LOQL**; an **HLL / t-digest sketch decision**
  shared by acceleration *and* federation (or federated `dc()`/`p95` are wrong); the **CIM tag
  layer** and **asset/identity schema + ingest hook** — all in Phase 1.
- **Coverage holes to close:** Microsoft Defender XDR, GCP audit/Workspace, Kubernetes, Okta System
  Log, Suricata; **retroactive enrichment + detection backfill**; late-arriving-event policy;
  incumbent-SIEM interop; signed community packs (ReDoS-guarded).

---

## The roadmap — eight leverage-ordered phases

Effort tags: **S / M / L / XL**.

### Phase 1 — Analytics & Normalization Backbone
**Goal:** give analysts a real composable query language and give every source a vendor-agnostic
schema, because search, dashboards, data models, RBA, acceleration, federation and RBAC all depend
on these two substrates. Make ingest crash-safe and the shared store un-starvable.

- **[XL] LOQL — SHIPPED** (`ec1ed09`, `app/loql/`, `docs/LOQL.md`) — piped search/transform DSL
  compiling to **parameterized SQL CTE chains**
  (search/where/eval/fields/rename/sort/head/dedup/stats/top/rare/bin/timechart/**datamodel**); the
  single point where per-role row filters & field masks are later injected. Reached via
  `POST /api/v1/query`. *(Splunk: SPL)*
  *Open:* stages that can't map to SQL as a bounded Python post-processor; a UI search box.
- **[L] Window verbs — OPEN** — eventstats / streamstats / transaction via Postgres window functions
  (gap-and-islands with `LAG`). *(Splunk: eventstats/streamstats/transaction)*
- **[XL] CIM domain models — SHIPPED** (`app/cim/`, `docs/CIM.md`) — eleven versioned models
  (Authentication/Network/Web/DNS/Endpoint/Change/Malware/IDS/**Industrial**/Email/Vulnerability)
  from a YAML registry (`models.yaml`), addressable as `| datamodel X` / `from datamodel:X`, as
  `datamodels:` on a detection rule, and as one `cim_<tag>` SQL view per model.
  **Design correction vs the original plan:** membership is a **plain `events.cim_models text[]`
  column, GIN-indexed and filled in Python at ingest — NOT generated columns.** PostgreSQL 16
  freezes a generation expression at `ADD COLUMN` (rewriting one needs `ALTER COLUMN … SET
  EXPRESSION`, PG17+, and docker-compose pins 16), so a generated column would have made every
  future registry edit unreachable on an existing database; and detection needs membership *before*
  the INSERT, since the engine evaluates per event while rows are flushed in chunks. Typed views
  survive as planned. *(Splunk: CIM + Data Models)*
- **[M] CIM tag/eventtype layer (pulled from Ph2) + rex/spath + macros — PARTIAL** — rules select by
  data model today (`datamodels:`), which is the membership half. `tags:`/`eventtypes:` as separate
  addressable objects, and rex/spath + macros for carving never-parsed fields retroactively
  (ReDoS-guarded), are still open. *(Splunk: eventtypes/tags · rex/spath/macros)*
- **[M] Durable ingest queue + ack — OPEN** — Postgres staging spillover behind the fast path;
  synchronous ack mode on the ingest API + syslog-TCP; recover unprocessed rows on restart.
  *(Splunk: HEC ack / persistentQueue)*
- **[S] Query guardrails + index strategy + perf spike — PARTIAL** — shipped: per-query
  `statement_timeout` + row/default-limit caps (`LOQL_TIMEOUT_MS` / `LOQL_MAX_ROWS` /
  `LOQL_DEFAULT_LIMIT` / `LOQL_MAX_AGG_ELEMS`), and the jsonb GIN + expression + `cim_models` GIN
  indexes with month-partition pruning. Open: a running-query registry + kill, BRIN, and the
  published EPS & bytes/event benchmark that gates Phase 2. *(Splunk: Workload Mgmt · Job Inspector)*

**Exit criteria — honest status.**

| Criterion | Status |
|---|---|
| Ad-hoc `stats`/`timechart` over months of data via `/api/v1/query` | **Met.** `eventstats` is not built, and `/search` still uses the filter form — LOQL has **no UI search box**, so it is reachable only through `POST /api/v1/query` (and the `/datamodels` member counts). |
| **≥8 CIM models populated by existing parsers** | **Met — 9 of 11.** Measured over all 34 bundled samples (97 events): authentication 15 · network 32 · web 6 · dns 4 · endpoint 19 · change 17 · malware 5 · ids 6 · ics 11. **Email and Vulnerability are 0 by design** — no shipped parser emits mail or scanner telemetry; they populate when such a source onboards (Phase 2). 3 sample events belong to no model, all genuinely unclassifiable shapes. |
| **A detection binds to a model, not a vendor** | **Met.** `rules/web_{sql_injection,path_traversal,command_injection,xss_attempt}.yml` bind `datamodels: web`; `rules/ot_it_to_ot_write.yml` binds `datamodels: ics`. Both conversions widened real coverage (proxy/URL-filter web logs; the full nine OT protocols). **Correlation rules are NOT datamodel-bound** — they filter in SQL via `db.correlate`, and the linter rejects a binding there. |
| Ingest survives a crash with no in-flight loss | **Open.** No durable queue / ack. |
| No single query can exhaust the instance | **Partly met.** Timeout + row caps are enforced per query; there is no running-query registry or kill. |
| Sizing numbers published | **Open.** The EPS / bytes-per-event benchmark spike has not run. |

### Phase 2 — Onboarding Breadth & Content Packs
**Goal:** win the "do you parse my stack?" evaluation. Secrets vault lands first.

- **[S] Encrypted secrets vault (pulled ahead)** — ✅ **DONE.** AES-256-GCM at rest for every
  collector credential, per-integration slots, all-or-nothing key rotation, admin UI, and
  vault-then-environment resolution so integrations migrate one at a time. Needs the optional
  `cryptography` package — the stdlib has no AES and a hand-rolled AEAD was judged the wrong
  risk; without it the vault disables itself and credentials fall back to environment
  variables. See [docs/VAULT.md](VAULT.md). *(Splunk: SOAR Assets credential store)*
- **[L] CrowdStrike FDR + Event Streams** — ✅ **DONE.** SQS/S3 gzip-NDJSON pull with a hand-rolled
  SigV4 signer (pinned to AWS's published `get-vanilla` vector) + an OAuth2 datafeed resumed by
  per-partition offset, plus the Incidents API. Receipt handles are acked on the NEXT poll, after
  ingest, so a crash cannot delete a notification whose data was never stored.
  *(Splunk: CrowdStrike FDR / Event Streams TAs)*
- **[L] Microsoft Defender XDR** — ✅ **DONE.** Graph `alerts_v2` + M365 incidents, routed on
  `serviceSource` into Endpoint / Authentication / Email — the alert that finally populated the Email
  model. A truncated page walk parks its `@odata.nextLink` and holds the watermark, so a backfill
  past the page cap cannot skip alerts. *(Splunk: M365 Defender / Graph Security TAs)*
- **[L] AWS breadth** — ✅ **DONE.** CloudTrail via S3/SQS at full fidelity (data events included),
  plus GuardDuty, Security Hub (ASFF), Config and Route 53 Resolver.
  *(Splunk: Splunk_TA_aws)*
- **[M] Flow + vuln + Prisma Access + FTD** — ✅ **DONE.** A stdlib-`struct` NetFlow v5/v9/IPFIX
  decoder over UDP and IPFIX-over-TCP, with a bounded template cache; Qualys/Tenable/Rapid7, which
  took the Vulnerability CIM model from 0 to 10 members; a Cortex Data Lake collector; and a Cisco
  FTD parser that delegates Lina lines to `cisco_asa` rather than discarding them. eStreamer is NOT
  built. *(Splunk: Stream · vuln TAs · CDL · Firepower TA)*
- **[M] Ingest Actions + Content Packs + HEC shim** — ✅ **DONE.** drop/mask/route/sample on the one
  path every source shares, reusing the Sigma condition grammar (no eval); versioned packs with
  export/import, digest-addressed; and a HEC-wire endpoint so a forwarder repoints by changing only
  a URL. *(Splunk: Ingest Actions · TA/Splunkbase · HEC)*

**Exit:** ✅ **MET.** All 10 named sources onboard agentlessly at full fidelity;
GuardDuty/Defender/NetFlow/vuln land in CIM; ingest can drop/mask/route with an audit trail; any
source ships & upgrades as one Content Pack; existing HEC senders work unchanged. **All 11 CIM
models are populated** for the first time (Vulnerability 0 → 10, Email 0 → 1). Not built: Cisco
eStreamer, and VPC Flow / WAF arrive through the generic paths rather than dedicated collectors.

### Phase 3 — Asset, Identity & Enrichment Fabric
**Goal:** give every event business + security context (schema + ingest hook defined back in Phase 1).

- **[L] Asset & Identity registry + alias resolution** — ✅ **DONE (slice 1).** Declared assets and
  identities in their own tables, deliberately separate from the observational `entities` baseline;
  alias resolution over hostname/FQDN/IP/CIDR/MAC and email/UPN/SAM, with exact-beats-containment and
  most-specific-CIDR both deterministic. Context is resolved onto every event at ingest
  (`asset_id`, `asset_criticality`, `identity_id`, `identity_priority`, GIN-indexed `context_tags`)
  and corrected for history by `db.backfill_assets`, which re-derives through the SAME resolver.
  See [docs/ASSETS.md](ASSETS.md). *(Splunk: ES Asset & Identity)*
- **[M] Automatic enrichment + query-time lookups** — denormalize asset/identity onto events at
  ingest & via LOQL join; analyst-managed lookup tables (`inputlookup/outputlookup`). *(Splunk: automatic lookups · KV Store)*
- **[M] GeoIP/ASN · reverse-DNS · WHOIS** — offline enrichment framework (side-loaded MaxMind +
  redistributable RIR ASN table). *(Splunk: iplocation)*
- **[M] IOC lifecycle + TAXII/STIX/MISP** — per-indicator confidence, aging/expiry, source-reliability,
  cross-feed dedup, sighting/FP feedback; pure-Python TAXII 2.1 poll + STIX/MISP parsers; side-loadable.
  *(Splunk: ES Threat-Intel framework)*
- **[S] Vuln-context + watchlists** — join Vulnerability CIM to assets so an exploit against an
  unpatched host outranks a patched one; VIP/service-account/crown-jewel multipliers seed RBA.
  *(Splunk: vuln-driven risk · UBA watchlists)*

**Exit:** events carry resolved criticality + geo/ASN; `jdoe` + `john.doe@corp` + `DESKTOP-J` resolve
to one entity; all integration secrets encrypted & rotatable; stale IOCs auto-expire and analyst FP
feedback suppresses them.

### Phase 4 — Risk-Based Alerting & Detection Content
**Goal:** collapse alert fatigue into few high-fidelity, context-weighted entity notables; curated,
tested, narrative-driven content.

- **[L] `risk_events` store + modifiers** — any detection/anomaly/IOC hit emits a scored,
  recency-decayed risk modifier (reuse the existing decay math) against an entity, with ATT&CK.
  *(Splunk: ES Risk Index)*
- **[M] Risk Incident Rules + factors + urgency** — one notable when aggregated entity risk crosses
  a threshold or N tactics/rules contribute; data-not-code multipliers; urgency = severity × asset
  criticality. *(Splunk: Risk Incident Rule · Risk Factors)*
- **[M] Notable lifecycle + disposition** — formal state machine + TP/FP/benign codes + per-alert
  history — the prerequisite that makes MTTR/FP-rate computable. *(Splunk: Notable lifecycle)*
- **[L] Analytic Stories + Use Case Library** — a "story" grouping rules + investigative searches +
  narrative + ATT&CK + required sources (YAML); coverage view keyed to `/sources`; versioned offline
  bundles (air-gapped ESCU). *(Splunk: Analytic Stories · ESCU)*
- **[M] Detection-as-code CI + sequencing rule** — unit-test rules vs labeled malicious/benign
  samples, staged rollout, FP backtest; an ordered A→B→C sequence rule type. *(Splunk: contentctl · Sequenced Events)*

**Exit:** one entity notable demonstrably replaces N raw alerts; urgency reflects asset criticality;
every notable carries disposition + history; ≥10 Analytic Stories ship offline; no rule reaches
"enabled" without passing CI.

### Phase 5 — Statistical UEBA
**Goal:** ~70–80% of practical UEBA value with pure-Python robust statistics feeding RBA — no ML
runtime, fully explainable, offline. **All scoring computed in SQL** (percentile/stddev/MAD), never
a CPython row loop.

- **[L] Statistical anomaly engine + baselines** — per-entity/metric baselines; anomaly when an
  observation exceeds median+k·MAD or an empirical percentile. Starter set mirrors UBA (unusual auth
  volume, new host/geo logon, unusual data-out, off-hours, rare parent-child). *(Splunk: UBA anomaly models)*
- **[M] Peer-group / cohort deviation** — cohorts by dept/role/subnet/asset-class; deviation from
  cohort median/MAD (SQL `PARTITION BY`). *(Splunk: UBA peer-group)*
- **[M] Adaptive/seasonal thresholds** — EWMA + Holt-Winters per hour-of-day/day-of-week bands
  (cardinality-capped). *(Splunk: ITSI adaptive thresholding)*
- **[M] Behavioral C2 + threat templates** — Shannon-entropy DGA scoring + beaconing periodicity;
  named templates chaining anomalies (Compromised-Account, Exfil, Lateral-Movement) → cases.
  *(Splunk: UBA DGA/beaconing · threat models)*
- **[S] Deterministic explanations + tuning** — each anomaly carries its own math; anomaly action
  rules; baseline-health workbench; documents the no-scikit boundary + substitute. *(Splunk: UBA threat detail)*

**Exit:** ≥10 statistical detectors emit into alerts + `risk_events` with deterministic explanations;
cohort + adaptive thresholds measurably cut FPs; the no-ML boundary is documented.

### Phase 6 — SOAR Platform & Investigation
**Goal:** real orchestration with human-in-the-loop safety; slot into an existing SOC's ITSM + on-call
+ investigation workflow.

- **[L] Multi-step playbook DAG** — ordered/branching typed steps (action/filter/decision/format/set/
  prompt/sub-playbook) over a pure in-memory context, **NO eval** (conditions reuse the Sigma
  grammar); run state in Postgres. *(Splunk: Visual Playbook Editor)*
- **[M] Human-in-the-loop approval gate** — a prompt step persists & PAUSES the run instead of firing
  a contain action; `/prompts` page + RBAC routing + timeout policy. *(Splunk: Prompts / action approval)*
- **[L] Response assets + data-not-code action apps + enrichment steps** — target a firewall vs IAM
  vs EDR (encrypted-cred ref + `require_approval`); declarative YAML action templates; read-only
  investigate steps feed later decisions. *(Splunk: Assets · Apps · investigate actions)*
- **[L] ITSM two-way sync + on-call/ChatOps** — ServiceNow SecOps/Jira open/update/close with
  status/owner/disposition back; PagerDuty/Opsgenie escalation + Slack/Teams interactive prompt ack.
  *(Splunk: SOAR ITSM · prompt delivery)*
- **[M] Investigation timeline + workbooks + step-trace + REST** — chronological pinned timeline +
  artifacts + entity swimlanes + Mission-Control cockpit (server-rendered SVG/CSS); case workbooks
  (phases/tasks/SLA); per-run execution trace; inbound REST. *(Splunk: Investigation Workbench · Workbooks · debugger)*

**Exit:** branching playbooks run with enrichment; every destructive action requires approval;
notables sync bidirectionally to ServiceNow/Jira; sev-1s page on-call with ack; each case has a
timeline + workbook; a per-run trace explains exactly what fired and why.

### Phase 7 — Reporting, Dashboards, Acceleration & Metrics
**Goal:** self-service visualization + scheduled/deliverable reporting + the SOC-efficacy and
compliance-attestation surfaces leadership and auditors buy on + acceleration.

- **[L] Acceleration layer (tstats substitute)** — scheduler-refreshed **incremental** rollup tables
  (custom upsert, not matview `REFRESH`) over CIM models on an ingest watermark; LOQL auto-routes
  eligible aggregations to rollups (summariesonly) with a late-data policy. *(Splunk: DMA / tstats)*
- **[L] Dashboard composer + domain dashboards + glass tables** — data-not-code panels bound to saved
  LOQL, token inputs + drilldown; prebuilt Access/Endpoint/Network/Identity dashboards; a composable
  KPI canvas (layout JSON, server-rendered). *(Splunk: Dashboard Studio · Glass Tables)*
- **[M] Scheduled reports + delivery (SVG-in-PDF/HTML)** — saved LOQL as cron reports, HTML+CSV via
  the notifier; optional vendored pure-Python PDF with embedded **vector SVG** (never a rasterizer).
  *(Splunk: Scheduled reports)*
- **[M] SOC efficacy metrics + compliance attestation** — MTTD/MTTR, dwell, alert-to-case ratio,
  FP-rate/rule, analyst workload; scheduled compliance reports + control posture trend + auditor
  evidence packs over the existing 8 frameworks. *(Splunk: ES/Mission-Control metrics · compliance apps)*
- **[M] Ops/health console + metering** — ingest rate, queue depth + writer lag, partition growth,
  detection latency, replication lag, cold-tier status, threshold alerts; per-source/tenant daily byte
  metering (capacity/fairness, not licensing). *(Splunk: Monitoring Console)*

**Exit:** users build dashboards from LOQL panels; scheduled compliance + SOC reports auto-generate &
deliver; long-range dashboards hit rollups not raw partitions; the ops console shows
ingest/queue/lag/replication health per tenant.

### Phase 8 — Platform Scale, Multi-Tenancy, Governance & Chain-of-Custody
**Goal:** enterprise access control, hard tenant isolation, regulatory retention/DR/chain-of-custody,
and an honest, charter-safe scale-out story — without a distributed store.

- **[L] Multi-tenancy (tenant_id + RLS) + RBAC-in-the-compiler** — `tenant_id` everywhere + Postgres
  RLS + partition/schema-per-tenant; fine-grained capabilities, a mandatory `srchFilter` row predicate
  injected into every LOQL compile, field-level masking, per-role quotas — unbypassable because it
  lives in the compiler. *(Splunk: index tenancy · authorize.conf · srchFilter)*
- **[L] OIDC/SAML SSO** — OIDC (RS256, reuse GCP RS256) native; SAML via reverse-proxy header auth;
  IdP groups → roles. *(Splunk: SAML/LDAP)*
- **[L] Cold-tier archival + per-class retention** — detach aged partitions → gzip-JSONL on disk/S3
  (SigV4) with catalog + integrity hash; LOQL transparently includes cold ranges + on-demand rehydrate;
  per-source/tenant/data-class retention replaces the single global drop. *(Splunk: SmartStore · frozen/thaw)*
- **[L] Chain-of-custody + federated search** — legal hold exempting a subject's data, evidence locker
  w/ per-access audit, WORM, signed forensic export, tamper-evident audit hash-chain; federated LOQL
  fans out to peer nodes (shared HLL/t-digest sketches so `dc()`/`p95` merge correctly) — horizontal
  scale-out by federating sovereign nodes. *(Splunk: Data Integrity · Federated Search)*
- **[M] Backup/PITR/DR + privacy ops + config versioning** — `pg_basebackup` + WAL PITR + tested
  restore + HA topology (streaming replication + read replicas + stateless app tier); right-to-erasure
  (tombstone + chain re-anchor), PII discovery, residency pinning; versioned export/import of all
  knowledge objects. *(Splunk: backup/restore · cluster substitute)*

**Exit:** hard tenant isolation via RLS; row/field/index scoping unbypassable in the compiler; legal
hold overrides retention & exports are signed; PITR restore tested with stated RPO/RTO; a careless
query can be inspected + killed; scale beyond one Postgres by federating nodes.

---

## Onboarding plan — the 10 named sources

All agentless (vendor-API collector, push, or S3/SQS pull). Six are at/near parity today; four are
the real build. **"Agentless" note:** it refers to the LogOcean side — Windows/AD still needs a
customer-run forwarder (NXLog/WEF), stated plainly.

| Source | Status | Mechanism | Plan | Eff. |
|--------|:------:|-----------|------|:----:|
| **AWS CloudTrail** | partial | S3-SQS pull (+ existing SigV4 LookupEvents) | Add SNS→SQS→S3 collector fetching gzip CloudTrail JSON via SigV4 — full management + data events, no throttle cap; then GuardDuty/SecurityHub/VPC-Flow/WAF/Config/Route53. | L |
| **Active Directory** | partial | Push (NXLog/WEF/syslog) + optional WinRM/WEF pull | `windows_security.py` handles 4624/4625/4768/4769/4776… on push, and now writes the resolved id back as `raw["event_id"]` so those events reach Authentication / Endpoint (4688/4689) / Change (4720…/1102) in CIM — **see the one-time dedup note in `docs/CIM.md`**. Add GPO/LDAP (5136/5137) + Kerberos/NTLM fields; stage opt-in WinRM/WS-Man. | L |
| **Microsoft O365** | have | O365 Management Activity API (OAuth2) | Harden to multi-workload fan-out (Exchange/SharePoint/AzureAD + DLP.All) → Auth/Change/Email/Web/Data CIM. | S |
| **Microsoft Entra ID** | partial | MS Graph pull (OAuth2) + optional Event Hub | Sign-ins exist; add Graph collectors for directoryAudits, Identity-Protection risk detections/risky-users, provisioning + an `entra_audit` parser. | S |
| **Palo Alto NGFW** | have | Native/CSV syslog push | Parsers cover TRAFFIC/THREAT/SYSTEM/CONFIG. **CIM binding done** — TRAFFIC→Network (read off the *type* in `raw`, so it is subtype-proof), THREAT vulnerability/spyware/flood/scan/packet→IDS, virus/wildfire→Malware, url→Web, SYSTEM `general` + CONFIG→Change. Still open: per-subtype maps (globalprotect/userid/hipmatch). | S |
| **Fortinet FortiGate** | have | key=value / CEF syslog push | Parser covers traffic/utm/event/anomaly. **CIM binding done** — `type=traffic`→Network, `type=event` + login/logout→Authentication, webfilter→Web, virus→Malware. Still open: confirm the CEF variant + a Content Pack wrapper. | S |
| **Cisco (ASA/FTD/IOS)** | partial | %ASA-/%IOS- syslog (have); FTD syslog (gap) + opt-in eStreamer | ASA/IOS at parity. Add an FTD syslog parser (connection/IDS/file/malware) + stage an agentless eStreamer eNcore SSL client-cert pull from FMC (opt-in). | L |
| **Palo Alto Prisma Access (SASE)** | gap | Cortex Data Lake API pull + push cloud-log-forward | No CDL collector today; on-prem PAN parsers reused. Build a Cortex Data Lake collector (cursor by log time) + document the cloud-log-forwarding → syslog/HEC path. | M |
| **CrowdStrike Falcon Pro** | gap | FDR (S3+SQS) & Event Streams (OAuth2 datafeed) | Parsers accept the shapes on push; no collector. Build (1) FDR long-poll SQS → gzip-NDJSON from S3 via SigV4; (2) Event Streams OAuth2 datafeed w/ offset + refresh → Endpoint CIM. Highest-value EDR gap. | L |
| **CrowdStrike Falcon Complete** | gap | Same FDR + Streams + Incidents/Alerts API | Same telemetry plus managed-MDR objects: add an Incidents/Alerts collector → map incidents to LogOcean cases and CrowdStrike actions to the `response_actions` audit trail. | M |

---

## Capability gap map — 104 capabilities across 10 pillars

LogOcean already **has** the detection/correlation/case/threat-intel/compliance core. The P0 **gaps**
cluster in analytics language, RBA, asset/identity, real SOAR, statistical UEBA, and platform scale.

| Pillar | P0 gaps (do first) | Phase |
|--------|--------------------|:-----:|
| Search & Analytics | ~~SPL-equivalent language (LOQL) · stats/eval/where · CIM taxonomy~~ **done**; window verbs · rex/spath/macros · a LOQL UI still open | 1 |
| Ingest / Onboarding | CrowdStrike FDR+Streams · Microsoft Defender XDR · delivery ack | 1–2 |
| ES / RBA / Asset-Identity | Risk index (`risk_events`) · risk incident rules · Asset & Identity framework · auto-enrichment | 3–4 |
| SOAR / Response | Multi-step playbook DAG · HITL approval gate · ITSM two-way sync | 6 |
| UEBA / ML | Statistical anomaly models (~30 types) · quantitative baselines | 5 |
| Admin / RBAC / Audit | Encrypted secrets vault | 2/3 |
| Investigation & Case Mgmt | Notable lifecycle + disposition · investigation timeline | 4/6 |
| Dashboards & Reporting | User-composed dashboards · SOC metrics · compliance attestation | 7 |
| Platform / Scale / Multi-tenant | Multi-tenancy (RLS) · federated search · cold-tier retention | 8 |

**Principled skips** (each with a documented in-charter substitute): Universal/Heavy Forwarder →
push/collector · indexer/search-head clustering → Postgres replication + multi-instance app ·
SmartStore mandate → gzip-JSONL cold tier · scikit/DSDL deep learning → robust SQL statistics ·
OpenSearch backend → deferred.

---

## The eight highest-leverage moves (start here)

1. ~~**LOQL minimal command set with a frozen parse-tree contract** and a strictly parameterized SQL
   compiler that is the single RBAC/row-filter/field-mask enforcement point~~ — **SHIPPED**
   (`ec1ed09`). The row-filter/field-mask injection point exists; the filters themselves are Phase 8.
2. ~~**CIM domain schema + the tag/eventtype binding layer** so detections bind to data models, not
   vendors~~ — **SHIPPED** for the membership half (11 models, `datamodels:` rule binding,
   `from datamodel:` searches). The separate tag/eventtype objects remain open.
3. **Ingest durability (ack/staging) + query-cost guardrails + job-kill** — protect the shared single
   Postgres from day one.
4. **A single-Postgres performance + storage-sizing benchmark** (EPS, bytes/event, hunt latency with
   real indexes) published as honest numbers — validates the cost thesis and gates the Phase-2
   high-volume feeds.
5. **Encrypted secrets vault**, pulled ahead of the collector wave so no integration credential is
   ever stored plaintext.
6. **Asset & Identity table + ingest-time enrichment hook defined now** so Phase-2 sources enrich from
   day one and avoid a mass backfill.
7. **CrowdStrike (FDR + Event Streams) and Microsoft Defender XDR collectors** — the two P0 EDR
   onboarding gaps that decide competitive evaluations.
8. **Commit the statistics-in-SQL mandate and the HLL/t-digest sketch decision early** — de-risks the
   no-numpy constraint for UEBA and unblocks correct acceleration + federated re-aggregation.

## Charter guardrails (non-negotiable)

- **Pure-Python only.** No scikit/numpy/pandas/statsmodels, no TF/PyTorch, no wkhtmltopdf/weasyprint/
  Chromium, no Mongo/Kafka/Spark/OpenSearch, no heavy IdP/cloud SDK. Statistics hand-rolled or in SQL.
- **One PostgreSQL is the only datastore.** Every scale/perf substitute is Postgres-native: rollup
  tables for tstats, RLS+partitioning for tenancy, replication for HA, gzip-JSONL for cold tier.
- **Agentless forever.** Vendor-API collectors, push, syslog, HEC shim. WinRM/WEF/eStreamer are
  agentless network protocols, shipped push-first.
- **Offline / air-gap first.** Threat intel, content, UEBA baselines, reports are side-loadable files.
- **Data-not-code, no eval.** Parsers/mappings/rules/models/playbooks/dashboards are config; LOQL
  compiles to parameterized SQL; conditions reuse the Sigma grammar.
- **Access control unbypassable in the compiler.** Per-role row predicates + field masks injected by
  the LOQL→SQL compiler + Postgres RLS — no query escapes tenant/role scope.
- **Hand-rolled crypto in-charter.** Reuse SigV4/OAuth2/RS256; add AES-GCM for the vault; get a
  third-party review before GA; never invent primitives.
- **Deterministic & unit-testable by construction.** Parser, LOQL (parse-tree + emitted-SQL snapshot),
  playbook, and anomaly are all pure functions with fixtures.
- **Record principled skips explicitly**, each with its documented in-charter substitute.

## Top risks

- **LOQL is XL on the critical path.** Ship a minimal command set first; freeze the parse-tree
  contract early; expand incrementally.
- **Single-Postgres contention.** Analyst SQL + ingest fight the same instance. Query caps + kill from
  Phase 1; route search to a read replica once HA lands.
- **Row-store economics unproven.** jsonb + derived columns (`search_tsv`, `cim_models`) + rollups =
  write amplification & weak compression vs Splunk's ~15%. The sizing benchmark gates the thesis.
  Note the CIM column is *cheaper* than the planned generated column (a short `text[]`, NULL when
  empty, computed once in Python) but is not free, and it makes a membership edit a table-wide
  `UPDATE` pass — hence `db.backfill_cim`'s chunked, resumable, skip-unchanged design.
- **Hand-rolled crypto** (AES-GCM vault, SAML/OIDC). Vetted test vectors, constant-time compares,
  third-party review; prefer OIDC + SSO-proxy over in-core XML-DSig.
- **Parser/TA breadth is a go/no-go.** Splunk's moat is SC4S + hundreds of TAs. Content Pack format +
  community import so coverage grows data-not-code; fund the long tail.
- **Compliance tension.** Right-to-erasure vs tamper-evident hash chains + WORM + legal hold.
  Authorized tombstone + chain re-anchor; legal sign-off.

---

*Synthesized from a 9-agent deep-research workflow (Splunk core platform · Enterprise Security · SOAR
· UBA · data onboarding · SPL/scale), a completeness critique, and an adversarial plan review, mapped
against LogOcean's current capabilities. All recommendations are constrained to the LogOcean charter:
pure-Python, single-Postgres, self-hosted, offline, agentless, no heavy dependencies.*
