# LogOcean Detection-Coverage Roadmap

> **Living document.** Goal: systematically grow LogOcean's rule pack to cover as much of
> **MITRE ATT&CK** (Enterprise + ICS) and **MITRE ATLAS** (adversarial AI) as is *practically
> detectable from the telemetry we ingest*, so that an attack, threat, or exploitation attempt is
> auto-detected the moment its logs land. Updated as phases land — see the Status table.

## 1. Governing principle: coverage is bounded by telemetry

A rule can only fire on a field a parser actually populates. So the reachable coverage is the
**intersection of (framework techniques) × (fields our 29 parsers emit)** — not the whole framework.
We therefore work **data-source-first**: for each parser family we enumerate the ATT&CK data sources
it produces, then the techniques those data sources reveal, then write (or import) tuned rules for
them. Every rule is groundable in real telemetry and testable.

Three sub-principles:

- **Attacks / threats / vulnerabilities, in log terms** = TTP behaviour (ATT&CK), multi-event
  behavioural threats (correlation + threat-intel), and *exploitation attempts* (IDS / web / network,
  e.g. T1190). This is **not** vulnerability *scanning* — LogOcean detects exploitation *in the logs*.
- **Auto-detect-on-ingest already exists.** `app/detection/engine.py` evaluates every event inline at
  ingest; the correlation scheduler runs multi-event rules over the store. This programme is
  **content + a few engine capabilities + measurement**, not a new pipeline.
- **Fidelity beats count.** Every rule carries a fidelity tier (`high` / `medium` / `hunt`), a
  positive test, and a benign-negative test. 300 noisy rules is worse than 120 tuned ones.

## 2. Telemetry → ATT&CK coverage map

| Telemetry (parsers) | ATT&CK data sources | Practically reachable techniques (examples) |
|---|---|---|
| **Windows Security + Sysmon** | process, cmdline, registry, auth, image-load, net, WMI, DNS, pipe | Execution `T1059.*`/`T1047`/`T1053.005`; Persistence `T1547.001`/`T1546.*`/`T1543.003`/`T1505.003`/`T1574.*`; PrivEsc `T1548.002`/`T1134`; Defense-Evasion `T1070.001`/`T1112`/`T1562.001`/`T1218.*`/`T1027`/`T1490`; CredAccess `T1003.*`/`T1558.003`; Discovery `T1057`/`T1087`/`T1018`; Lateral `T1021.*`/`T1550.*`; C2 `T1071`/`T1105`/`T1219`; Impact `T1486`/`T1489`/`T1529` |
| **Linux auditd + web access** | process, cmdline, file, http | `T1059.004`, `T1053.003`, `T1543.002`, `T1546.004`, `T1548.001/.003`, `T1070.002`, `T1003.008`, `T1105`; web → **`T1190`**, `T1505.003`, `T1595` |
| **AWS CloudTrail / GCP / Azure** | cloud audit | `T1078.004`, `T1098.001`, `T1136.003`, **`T1562.008`**, `T1578.*`, `T1552.005`, `T1526`/`T1580`, `T1530`/`T1537`/`T1567.002`, `T1496`, `T1485`/`T1531` |
| **Entra / Okta / M365** | identity, auth, mailbox | `T1078`, **`T1110.003/.004`**, **`T1621`**, `T1556.*`, `T1098.005`, `T1484`, `T1114.003`, `T1538`/`T1087.004` |
| **PAN / Forti / Cisco / Zeek / Suricata** | net flow, IDS, DNS, TLS | `T1595`/`T1046`, `T1071`/`T1095`/`T1571`/`T1572`/`T1090`, `T1568.002`, `T1041`/`T1048`, `T1498`/`T1499`; Zeek → beaconing, DNS tunnelling, rare-JA3 |
| **GitHub / GitLab** | VCS audit | `T1195.*`, `T1213.003`, `T1552.001`, `T1098`, protected-branch / CI-runner abuse |
| **Nutanix PC / Files, Zeek-ICSNPP (OT)** | mgmt-plane, file, ICS | Already packed; ATT&CK-for-ICS `T0836`/`T0855`/`T0858`/`T0889` extensible |

With today's telemetry we can meaningfully cover **~11 of 14 Enterprise tactics**
(Reconnaissance and Resource-Development are mostly external and only partially reachable).

## 3. MITRE ATLAS (adversarial AI) — a dependent track

ATLAS is unreachable today because **we ingest zero AI/ML telemetry**. It therefore begins with a new
parser for **LLM / AI-gateway logs** (Azure OpenAI / AWS Bedrock model-invocation logs, or an LLM
proxy such as LiteLLM). Once that telemetry exists, the detection-relevant ATLAS subset becomes
reachable — the coverage scoreboard already renders this matrix at **0 %** so the gap is visible:

| ATLAS tactic | Detection-relevant techniques |
|---|---|
| Initial Access | `AML.T0051` LLM Prompt Injection (`.000` direct / `.001` indirect), `AML.T0012` Valid Accounts, `AML.T0049` Exploit Public-Facing App, `AML.T0052` Phishing |
| ML Model Access | `AML.T0040` AI Inference API Access, `AML.T0044` Full Model Access, `AML.T0047` ML-Enabled Product/Service |
| Execution | `AML.T0050` Command & Scripting Interpreter, `AML.T0053` LLM Plugin Compromise, `AML.T0011` User Execution |
| Defense Evasion | `AML.T0054` LLM Jailbreak, `AML.T0015` Evade ML Model |
| Credential Access | `AML.T0055` Unsecured Credentials |
| Exfiltration | `AML.T0024` Exfil via ML Inference API (`.002` Extract Model), `AML.T0057` LLM Data Leakage, `AML.T0056` Meta-Prompt Extraction, `AML.T0025` Exfil via Cyber Means |
| Impact | `AML.T0029` Denial of ML Service, `AML.T0034` Cost Harvesting, `AML.T0031` Erode Model Integrity, `AML.T0046` Chaff Spamming |

This dovetails with the **AI-Security-Posture-Management** project — LogOcean becomes its
runtime-detection half. Built last (Phase 7) because it needs the parser foundation.

## 4. Rule taxonomy + engine capabilities needed

Three rule shapes:

1. **Per-event** (Sigma-subset) — exists. Fires inline at ingest.
2. **Threshold correlation** (count over window / entity) — exists (`app/detection/correlation.py`).
3. **Temporal sequence** (ordered A→B within a window per entity) — **not yet**; needed for
   spray→success, recon→exploit, encoded-command→outbound-C2.

Engine capabilities to add in the behavioural phase (Phase 5):

- **Temporal-sequence** correlation (ordered multi-stage).
- **Distinct-count / cardinality** aggregation (1 src → N distinct ports = scan; 1 src → N distinct
  users = spray) — today's `correlate` counts events, not distinct values of a second column.
- **GeoIP / ASN enrichment on ingest** → impossible-travel / new-country sign-in (`T1078`).
- **Reference / allowlist sets** for baselining known-good admin tooling and service accounts.

## 5. Rule metadata + quality gates

Every rule carries (schema enforced by the rule-linter, `tests/test_rule_quality.py`):

```yaml
id: lo-...                       # unique, kebab-case, lo- prefix
title: ...
level: informational|low|medium|high|critical
fidelity: high|medium|hunt       # optional; defaults to medium
data_source: [process_creation, windows_security]   # optional; ATT&CK-style data-source keys
description: ...                  # non-empty
tags: [attack.t1059.001, attack.execution]   # >=1 attack.tNNNN or atlas.aml.tNNNN
references: [https://...]         # optional
```

- **Fidelity tiers.** `high` = specific behaviour/IOC, auto-alert. `medium` = heuristic, review.
  `hunt` = broad, analyst-driven (kept out of the noisy auto-alert stream by policy).
- **ATLAS tags** use the `atlas.aml.tNNNN` convention (parsed into a rule's `atlas_techniques`).
- **Test gate (new rules).** Each new rule ships a positive + benign-negative test. (Existing rules
  are structurally validated now; behavioural back-fill is opportunistic.)

## 6. Measurement — the coverage scoreboard

`app/coverage.py` (pure) computes, from the loaded rule registry, technique-level coverage for
**ATT&CK Enterprise + ICS** and the **ATLAS** matrix, rolled up by tactic, fidelity and data source.
Surfaces:

- **`GET /coverage`** — the scoreboard page (coverage %, per-tactic table, fidelity/data-source
  breakdown, ATLAS matrix).
- **`GET /coverage.json`** — the full machine-readable report.
- **`GET /coverage/attack-navigator.json`** (`?domain=enterprise|ics`) — a MITRE ATT&CK Navigator
  layer scored by rule coverage (open in <https://mitre-attack.github.io/attack-navigator/>).
- **`scripts/coverage_report.py`** — CLI that prints the summary and writes the layer JSONs
  (CI-publishable coverage artifact).

## 7. Roadmap (phased)

| Phase | Deliverable | Status |
|---|---|---|
| **0 — Framework & measurement** | Rule-metadata schema (`fidelity`/`data_source`/`references`/`atlas.*`), CI rule-linter, `app/coverage.py`, `/coverage` scoreboard + Navigator layers + CLI, baseline coverage | ✅ **DONE** |
| **1 — Sigma importer (breadth)** | Map SigmaHQ logsource/fields → our schema; import + loaded-vs-skipped coverage report | ✅ **DONE** |
| **2 — Endpoint high-fidelity pack** | Windows / Sysmon curated, tuned, tested (15 rules; adversarially IOC-verified) | ✅ **DONE** |
| **3 — Cloud + Identity pack** | CloudTrail / GCP / Azure / Entra / Okta / M365 / GitHub / GitLab (16 rules; API-names adversarially verified) | ✅ **DONE** |
| **4 — Linux + Network pack** | auditd / web / Zeek / Suricata (incl. web-exploitation `T1190`) — 16 rules, patterns adversarially verified | ✅ **DONE** |
| **5 — Behavioural upgrade** | **distinct-count / cardinality ✅** (spray / distributed-brute-force / port-scan / host-sweep); temporal-sequence + GeoIP → impossible-travel next | ◐ **in progress** |
| **6 — OT/ICS + SaaS/VCS** | extend ATT&CK-for-ICS; GitHub/GitLab supply-chain pack | ▫ planned |
| **7 — ATLAS track** | LLM/AI-gateway parser + adversarial-AI rule pack | ▫ planned |

Each phase ships tested rules + a measured coverage delta (tracked on the `/coverage` scoreboard).

## 8. Content strategy

Breadth from **importing** (SigmaHQ is already ATT&CK-tagged — Phase 1 gives the fastest jump);
depth and low-noise from **authoring** high-fidelity packs for the telemetry Sigma barely covers
(cloud, identity, Nutanix, OT, ATLAS). Hybrid, importer-first.

### Phase 1 — using the Sigma importer

`app/sigma_import.py` translates a Sigma rule into our native rule dict:
Sigma `logsource` becomes a **gate selection** over our normalized fields (a
`process_creation` rule only fires on `action=process-create`, etc.), Sigma field names
(`Image` / `CommandLine` / `TargetObject` …) pass through (our parsers lift them onto
`raw`), and anything we can't faithfully run is **skipped with a reason** (unmapped
logsource, unsupported modifier like `utf16`/`wide`/`expand`, Sigma aggregation/correlation,
deprecated rule). Imports keep the original Sigma `id` / `author` + a source reference (DRL).

```bash
git clone https://github.com/SigmaHQ/sigma
python scripts/import_sigma.py --src sigma/rules            # dry-run: loaded-vs-skipped report
python scripts/import_sigma.py --src sigma/rules --write    # emit rules/imported/*.yml
# restart LogOcean → /coverage reflects the jump
```

`rules/imported/` is loaded alongside `rules/` but is **not vendored** (generated
per-deployment, gitignored) so the pack never drifts from upstream. Imported rules default
to `fidelity: medium`; promote the high-signal ones as you tune. Sigma **correlation** rules
are deferred to Phase 5 (temporal engine).

### Phase 2 — endpoint high-fidelity pack

Where Phase 1 gives breadth by import, Phase 2 gives **depth and low noise** by hand-authoring
15 curated Windows / Sysmon rules for the endpoint techniques that matter most and that generic
imports cover poorly — each tagged `fidelity: high|medium` + `data_source`, and each shipped with a
positive **and** a benign-negative test (`tests/test_detection.py`):

- **Credential access** — LSASS handle-open by mask (Sysmon EID 10 `GrantedAccess`), known
  credential-dumper tools (Mimikatz/nanodump/pypykatz/… by image, original-filename **and**
  argument syntax), NTDS.dit / SAM-hive extraction, WDigest `UseLogonCredential` plaintext-caching.
- **Defense evasion** — BYOVD known-vulnerable driver load (EID 6), Microsoft Defender disabled /
  excluded (registry **and** `Set-/Add-MpPreference`), AMSI / ETW in-memory tampering.
- **Privilege escalation / persistence** — UAC registry command-hijack (fodhelper / eventvwr /
  sdclt), LSA / AppInit / Winlogon-Notify autostart, remote-thread injection into system processes.
- **Execution / lateral movement** — PsExec / remote-service exec, `msiexec` remote-package
  proxy-exec, BITS-job download, Cobalt Strike default named pipes, local-account creation (4720).

To ground the pack honestly, the Sysmon parser's `_LIFT` set was extended to surface the
EID 6/7/8/10 fields (`SourceImage` / `TargetImage` / `GrantedAccess` / `ImageLoaded` / …) so the
rules match the rendered-`Message` `Get-WinEvent` export analysts actually produce (proven by a
parser round-trip test), not only shipper-emitted `EventData`. Every hardcoded indicator (driver
names, CS pipe patterns, registry keys, API masks, dumper syntax) was **adversarially verified
against public sources** (SigmaHQ / MITRE / loldrivers / vendor research) before ship — the pass
caught and fixed a dead sdclt `runas`-vs-`open` verb, a mislabeled ETW-injection token, and two
technique-tag errors. Delta on the `/coverage` scoreboard: **ATT&CK Enterprise 46 → 64 techniques;
high-fidelity coverage 7 → 23**.

### Phase 3 — cloud + identity pack

Phase 3 adds 16 curated rules across **every** cloud / identity source, closing the biggest
provider gaps: **GCP, Azure and GitLab went from zero rules to covered**. Each rule keys only on
fields the cloud parsers surface (`action` = eventName / methodName / operationName / Operation /
eventType, plus keyword search over the flattened `raw` record for values buried in
`requestParameters` / IAM policy bindings), and ships a positive + benign-negative test:

- **AWS** — threat-detection / Config disabled (GuardDuty·Security Hub·Config), AdministratorAccess
  policy attached, S3 bucket exposed publicly.
- **GCP** — SetIamPolicy granting a privileged role, service-account key created, logging sink deleted.
- **Azure** — RBAC role assignment, diagnostic settings deleted, Key Vault delete / access-policy change.
- **GitLab** — 2FA disabled, project/group made public.
- **Okta / M365 / GitHub** — admin impersonation; org transport rule + mailbox delegate; org 2FA
  disabled + branch-protection removed.

Because a cloud rule lives or dies by the exact API identifier, **every event / operation / method /
eventType name was adversarially verified against provider docs** (AWS / GCP / Azure / Microsoft /
Okta / GitHub / GitLab) in a 16-agent pass. It paid off: it caught **two dead GitLab rules** (they
assumed human-readable prose — `to public`, `2fa` — but GitLab emits discrete `change`/`to` fields and
an underscore `event_name` `user_disable_two_factor`, so the originals matched *zero* real events) and
**four mis-mapped ATT&CK sub-techniques** (S3 → T1530, transport-rule → T1114.003, Key Vault →
T1555.006, branch-protection → T1562.001). Fidelity labels were tuned down where a rule keys on an
operation name without inspecting the payload (Terraform-style full-policy re-applies fire the GCP IAM
rule; transport-rule body isn't inspected). Delta: **ATT&CK Enterprise 64 → 68 techniques** (cloud
techniques overlap heavily, so the win is provider breadth, not raw technique count); rules **64 → 80**
(74 event + 6 correlation).

### Phase 4 — Linux + network + web-exploitation pack

Phase 4 fills the previously near-empty Linux / network / web ground with 16 rules, led by
**web-exploitation (`T1190`)**. The web rules key on the normalized request line (`message`) and gate
on `log_type: [access, http]`, so a single rule fires across **Apache/Nginx access logs, Zeek HTTP,
and Suricata HTTP** at once:

- **Web (`T1190`)** — SQL injection, path traversal / LFI, OS command injection, XSS, web-shell access
  (`T1505.003`), and scanner user-agents (`T1595.002`).
- **Suricata IDS passthrough** — surface what the IDS already classified, mapped to ATT&CK by
  `alert.category`: web-application-attack (`T1190`), trojan / C2 (`T1071`), crypto-mining (`T1496`).
- **Linux auditd** — reverse shells (`T1059.004`), setuid backdoors (`T1548.001`), sudoers
  (`T1548.003`), SSH `authorized_keys` (`T1098.004`) and cron (`T1053.003`) persistence, `/etc/shadow`
  access (`T1003.008`), and security-control disabling (`T1562.001`/`.004`). These key on the auditd
  EXECVE command line the parser reassembles (mirroring the Sysmon command-line idiom).

Every payload token, IDS category string, and Linux command pattern was **adversarially verified**
against OWASP / PayloadsAllTheThings, the Suricata/ET classtype list, and GTFOBins / Atomic Red Team,
with an explicit ReDoS check on each `|re`. The pass was clean (13/16 CONFIRMED first time) and its two
tag corrections became coverage: a mis-tagged "Crypto Currency Mining" category was **split into its own
`T1496` rule**, and `T1548.003`'s tactic was fixed to Defense Evasion. Delta: **ATT&CK Enterprise
68 → 79 techniques** (the biggest single-phase jump — Linux/web/IDS were genuinely uncovered);
high-fidelity 26 → 35; rules **80 → 96** (90 event + 6 correlation).

### Phase 5 — behavioural upgrade (in progress)

Phase 5 is the first phase that grows the **engine**, not just content. Its first increment is
**distinct-count / cardinality correlation**: `db.correlate` gained an optional whitelisted
`distinct_col`, so a correlation rule can count *distinct values* of a second column
(`count(distinct …)`) instead of raw events. That expresses detections the event-counting engine
could not — behaviours defined by *breadth*:

- **Password spray** — one `src_ip` → 10+ distinct `user_name` failed logons (`T1110.003`); immune to a
  single user's repeated mistypes, and invisible to a per-user failed-count rule.
- **Distributed brute force / credential stuffing** — one `user_name` ← 10+ distinct `src_ip`
  (`T1110.004`); defeats per-source throttling.
- **Port scan** — one `(src_ip, dst_ip)` → 20+ distinct `dst_port` (`T1046`), the vertical-scan shape.
- **Host sweep** — one `src_ip` *denied* to 25+ distinct `dst_ip` (`T1018`/`T1046`); gating on blocked
  connections separates a real sweep from ordinary CDN/tracker browsing fan-out.

The SQL change is whitelist-gated (the `distinct_col` identifier must be in `_CORR_COLS` and not already
a group column) and fully parameterized; a load-time warning fires if a rule names an unaggregatable
column. It was **adversarially reviewed for SQL injection and `count(distinct)`/`HAVING` correctness
(both CONFIRMED clean)**, unit-tested (rule/loader/alert wording) and integration-tested against real
Postgres in CI (distinct vs event count, threshold, per-group isolation, fallback). Delta:
ATT&CK Enterprise 79 → **82 techniques**; rules 96 → **100** (90 event + 10 correlation).

**Remaining Phase 5 work:** **temporal-sequence** correlation (ordered A→B per entity — spray→success,
recon→exploit; needs a self-join or a two-step Python orchestration) and **GeoIP / ASN enrichment on
ingest → impossible-travel** (needs an offline geo dataset — an optional-MaxMind, degrade-gracefully
design is the likely approach).
