# CLAUDE.md — SIEM-Lite / LogVault

Guidance for Claude Code (and other agents) working in this repository.

## What this is

**LogVault** — a self-hosted log parser, indexer, and long-term store for
**Palo Alto NGFW** and **CrowdStrike Falcon EDR** logs. The operator manually
exports logs from each vendor console and uploads them through a web UI; the app
parses, normalizes, full-text indexes, and stores them in PostgreSQL with a
**≥ 3-year retention** policy.

- **Stack:** Python 3.12, FastAPI + Uvicorn, Jinja2 (server-rendered UI),
  PostgreSQL 16 via `psycopg` 3 (+ `psycopg_pool`), `python-dateutil`.
- **Repo:** https://github.com/Krishcalin/SIEM-Lite · **License:** see `LICENSE`.
- **Run:** `docker compose up --build` → http://localhost:8000 (Postgres + app).

## Architecture / data flow

```
upload (web) ─► detect.py (format) ─► parsers/<vendor>_<fmt>.py ─► NormalizedEvent
            ─► normalize.py (dedup hash + FTS blob) ─► db.insert_events
            ─► events (month-partitioned) + search_tsv (GIN) ─► search / export
```

One normalized schema for both vendors; the **full original record is always kept**
in `events.raw` (jsonb) so nothing is lost and any field stays searchable.

## Repository layout

```
app/
  main.py        FastAPI routes + UI (dashboard, upload, search, event, admin)
  config.py      env-driven settings (DB_DSN, RETENTION_YEARS, PAGE_SIZE, ...)
  models.py      NormalizedEvent dataclass (the common schema)
  util.py        tolerant parse_ts / clean_ip / to_int / first
  detect.py      best-effort vendor+format auto-detection
  normalize.py   dedup_hash() + tsv_text()
  db.py          pool, schema/partition mgmt, insert, search, stats, purge
  ingest.py      orchestration: detect -> parse -> normalize -> bulk insert -> batch stats
  parsers/       paloalto_csv, paloalto_syslog, fortinet_fortigate, cisco_asa, zeek_tsv,
                 crowdstrike_csv, crowdstrike_json, windows_security, suricata_eve, cef,
                 generic_syslog, aws_cloudtrail, m365_audit, entra_signin, okta_system_log
  templates/     base, dashboard, upload, search, event, admin
  static/style.css
schema.sql       partitioned events table, FTS + indexes, ingest_batches
samples/         one example file per format (used by tests)
tests/           test_parsers.py (parsers + detection; NO database needed)
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
- **Detection ordering (`detect.py`)** is specific-before-generic. JSON is routed by
  record keys: `event_type`+net → Suricata; `ProviderName`+`Id` → Windows;
  `eventSource`+`eventName` → CloudTrail; `Workload`+`Operation` → M365; `eventType`+
  `actor` → Okta; `userPrincipalName`/`appDisplayName` → Entra; else CrowdStrike. Text
  formats match `CEF:n|`, then `%ASA-…` (Cisco), then Zeek `#fields`, then PAN syslog,
  then Fortinet KV, then CSV headers, and finally **generic syslog** (`<PRI>` / RFC 3164).

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

Tests parse the bundled samples and assert normalized fields + auto-detection;
**no database is required**. Run them after any parser/detector change.

## Security / ops notes

- No built-in auth — run behind SSO / a reverse proxy or on a trusted host.
- The Postgres volume IS the 3-year archive — back it up.
- Don't commit `.env`, uploads, or `pgdata/` (already in `.gitignore`).
