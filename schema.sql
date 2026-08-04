-- ============================================================================
--  LogOcean schema — partitioned event store, full-text index, ingest batches.
--  Idempotent: safe to run on every startup.
-- ============================================================================

-- One row per uploaded file.
CREATE TABLE IF NOT EXISTS ingest_batches (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    filename       text        NOT NULL,
    file_sha256    text        NOT NULL,
    vendor         text,
    fmt            text,
    uploaded_at    timestamptz NOT NULL DEFAULT now(),
    total_rows     integer     DEFAULT 0,
    inserted_rows  integer     DEFAULT 0,
    duplicate_rows integer     DEFAULT 0,
    error_rows     integer     DEFAULT 0,
    status         text        DEFAULT 'pending',
    notes          text
);

-- Normalized event store, RANGE-partitioned by month on event_time so that
-- 3-year retention is a cheap DROP of whole partitions, and time-range queries
-- only touch the relevant months.
CREATE TABLE IF NOT EXISTS events (
    id          bigint GENERATED ALWAYS AS IDENTITY,
    event_time  timestamptz NOT NULL,
    ingested_at timestamptz NOT NULL DEFAULT now(),
    vendor      text        NOT NULL,        -- paloalto | crowdstrike
    product     text,                        -- ngfw | falcon
    log_type    text,                        -- traffic, threat, url, system, config, detection, ...
    severity    text,
    action      text,
    src_ip      inet,
    dst_ip      inet,
    src_port    integer,
    dst_port    integer,
    protocol    text,
    app         text,
    user_name   text,
    host_name   text,
    rule_name   text,
    bytes_total bigint,
    message     text,
    raw         jsonb       NOT NULL,         -- full original parsed record
    search_tsv  tsvector,                     -- full-text vector over key fields + raw
    batch_id    bigint      NOT NULL,
    dedup_hash  text        NOT NULL,         -- sha256 over canonical raw (+vendor+time)
    -- NOTE: `cim_models text[]` also belongs to this table. It is added by the CIM
    -- section below as a post-hoc ALTER (see the comment there for why).
    PRIMARY KEY (id, event_time)
) PARTITION BY RANGE (event_time);

-- Catch-all so an out-of-range timestamp never fails an insert.
CREATE TABLE IF NOT EXISTS events_default PARTITION OF events DEFAULT;

-- Indexes declared on the parent propagate to every (current + future) partition.
CREATE INDEX IF NOT EXISTS events_tsv_idx     ON events USING GIN (search_tsv);
CREATE INDEX IF NOT EXISTS events_raw_idx     ON events USING GIN (raw jsonb_path_ops);
CREATE INDEX IF NOT EXISTS events_time_idx     ON events (event_time DESC);
CREATE INDEX IF NOT EXISTS events_vendor_idx   ON events (vendor, event_time DESC);
CREATE INDEX IF NOT EXISTS events_logtype_idx  ON events (log_type);
CREATE INDEX IF NOT EXISTS events_src_idx      ON events (src_ip);
CREATE INDEX IF NOT EXISTS events_dst_idx      ON events (dst_ip);
CREATE INDEX IF NOT EXISTS events_user_idx     ON events (user_name);
CREATE INDEX IF NOT EXISTS events_host_idx     ON events (host_name);
CREATE INDEX IF NOT EXISTS events_batch_idx    ON events (batch_id);
-- search() filters severity/action case-insensitively — expression indexes make the
-- lower(col) predicates index-usable instead of scanning every partition.
CREATE INDEX IF NOT EXISTS events_severity_idx ON events (lower(severity));
CREATE INDEX IF NOT EXISTS events_action_idx   ON events (lower(action));

-- Dedup within partitions (must include the partition key on a partitioned table).
CREATE UNIQUE INDEX IF NOT EXISTS events_dedup_idx ON events (dedup_hash, event_time);

-- ============================================================================
--  CIM data models (Backbone 2): membership materialized on `events`.
-- ============================================================================
-- `cim_models` carries the tags of the CIM data models an event belongs to
-- ('authentication', 'network', 'endpoint', …). It is a PLAIN text[] filled per row
-- in Python at ingest from app.cim.match.tags_for(), exactly the way `search_tsv` is
-- filled from normalize.tsv_text() — deliberately NOT `GENERATED … STORED`:
--   * PostgreSQL 16 freezes a generation expression at ADD COLUMN. Rewriting one
--     needs ALTER COLUMN … SET EXPRESSION, which is PG17+, and docker-compose pins
--     postgres:16 — so an edit to models.yaml could never reach an existing database.
--   * Detection needs membership BEFORE the INSERT: the engine evaluates each event
--     as it streams through the pipeline, while rows are flushed only in chunks.
-- Declared as a post-hoc ALTER rather than as a column of CREATE TABLE above so that
-- a fresh database and an upgraded one converge on the SAME schema — identical
-- ordinal position included — which is the pattern this file already uses for every
-- column added after the fact (ingest_batches.source_type, alerts.assignee, …).
-- With no DEFAULT the ADD COLUMN is catalog-only (no heap rewrite) and it recurses to
-- every existing partition. Partitions created LATER inherit it because
-- `CREATE TABLE … PARTITION OF events` takes its whole column list from the parent.
ALTER TABLE events ADD COLUMN IF NOT EXISTS cim_models text[];

-- The performance premise of the model views and of LOQL `datamodel:`: the
-- containment predicate `cim_models @> ARRAY['authentication']::text[]` must be
-- index-served, never a scan across three years of partitions. Declared on the parent
-- like the indexes above, so every partition db.ensure_partitions creates later gets a
-- matching child index automatically. Rows in no model store NULL, not '{}', so they
-- contribute no index entries at all.
CREATE INDEX IF NOT EXISTS events_cim_models_idx ON events USING GIN (cim_models);

-- Exactly one row: which registry the `cim_<tag>` views were built from, and which one
-- the stored `cim_models` values were last derived under. The two halves have different
-- writers and must not be confused:
--   * registry_version / model_tags / membership_hash / applied_at — written by
--     db.init_cim (the `_CIM_STAMP_UPSERT`, an ON CONFLICT DO UPDATE on the boolean key)
--     every time the views are rebuilt, i.e. on every startup. A RECORD of which registry
--     the view surface came from, surfaced on /admin and /datamodels.
--   * backfilled_at / backfill_hash — written ONLY by db.backfill_cim, and only by a run
--     that was unbounded and completed. The rule the rows in `events` were last derived
--     under. init_cim never touches them: the views can move ahead of history, and saying
--     otherwise would report a membership edit as applied to rows it has not reached.
--
-- `backfill_due` IS NOT `backfill_hash <> membership_hash`. This comment used to say it
-- was, and db.cim_status() has never computed it that way. It compares `backfill_hash`
-- against the fingerprint of the registry ON DISK, re-read by db.registry_drift() (and it
-- falls back to the in-process registry only when models.yaml cannot be read at all).
-- The difference is the whole window that matters: `membership_hash` is refreshed only by
-- a startup, so between an operator's edit to models.yaml and the restart it still holds
-- the OLD fingerprint — equal to `backfill_hash` — and a stored-vs-stored comparison
-- would answer "history is current" for precisely as long as the edit has been ignored.
-- Against the file it stays true until restart-then-backfill has actually happened.
-- `membership_hash` is therefore a durable record for an operator reading the row, not an
-- input to the staleness check.
CREATE TABLE IF NOT EXISTS cim_meta (
    id               boolean     PRIMARY KEY DEFAULT true CHECK (id),  -- one row only
    registry_version integer     NOT NULL,
    model_tags       text[]      NOT NULL DEFAULT '{}',
    membership_hash  text        NOT NULL,
    applied_at       timestamptz NOT NULL DEFAULT now(),
    backfilled_at    timestamptz,
    backfill_hash    text
);

-- ============================================================================
--  Live ingestion (Phase 1): API keys + source tracking on batches.
-- ============================================================================

-- API keys for the HTTP ingest endpoint. Only the sha256 of the key is stored;
-- the plaintext is shown once at creation. `key_prefix` is a short, non-secret
-- label for the UI to identify a key.
CREATE TABLE IF NOT EXISTS api_keys (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name         text        NOT NULL,
    key_sha256   text        NOT NULL UNIQUE,
    key_prefix   text        NOT NULL,
    source_label text,
    enabled      boolean     NOT NULL DEFAULT true,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz
);

-- A batch can now come from an upload, the syslog receiver, or the HTTP API.
-- Live sources have no file, so filename/sha become nullable.
ALTER TABLE ingest_batches ADD COLUMN IF NOT EXISTS source_type text NOT NULL DEFAULT 'upload';
ALTER TABLE ingest_batches ADD COLUMN IF NOT EXISTS source_addr text;
ALTER TABLE ingest_batches ALTER COLUMN filename    DROP NOT NULL;
ALTER TABLE ingest_batches ALTER COLUMN file_sha256 DROP NOT NULL;

-- Events REMOVED by an ingest action (app/ingest_actions.py `drop` / a rejected
-- `sample`), which never reached the INSERT. Without its own column those events
-- would have to be absorbed into duplicate_rows, telling the operator "we already had
-- this data" when the truth is "a rule deleted it" — so this column is what keeps the
-- invariant total_rows = inserted_rows + duplicate_rows + dropped_rows honest.
ALTER TABLE ingest_batches ADD COLUMN IF NOT EXISTS dropped_rows integer DEFAULT 0;

-- ============================================================================
--  Detection & alerting (Phase 2).
-- ============================================================================

-- Rule registry: metadata + enable flag per detection rule. The rule logic lives
-- in the YAML files under rules/ — this table tracks enablement and is synced from
-- those files on startup (enabled flags are preserved across restarts).
CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id    text PRIMARY KEY,
    title      text   NOT NULL,
    level      text,
    source     text,
    tactics    text[] NOT NULL DEFAULT '{}',
    techniques text[] NOT NULL DEFAULT '{}',
    enabled    boolean NOT NULL DEFAULT true
);

-- Alerts raised when an event matches a rule. Low-volume relative to events, so
-- not partitioned. One alert per (rule, originating event) via the unique index;
-- re-ingesting the same event does not duplicate alerts.
CREATE TABLE IF NOT EXISTS alerts (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at  timestamptz NOT NULL DEFAULT now(),   -- when the alert was raised
    event_time  timestamptz,                          -- originating event time
    rule_id     text        NOT NULL,
    rule_title  text        NOT NULL,
    level       text        NOT NULL,
    tactics     text[]      NOT NULL DEFAULT '{}',
    techniques  text[]      NOT NULL DEFAULT '{}',
    vendor      text,
    src_ip      inet,
    dst_ip      inet,
    user_name   text,
    host_name   text,
    message     text,
    dedup_hash  text        NOT NULL,                 -- links to the originating event
    batch_id    bigint,
    status      text        NOT NULL DEFAULT 'open'   -- open | ack | closed
);

-- Triage: who owns an alert (assignment). status gains a 'suppressed' value for
-- alerts an allowlist matched (kept for audit, hidden from the default view).
-- case_id groups many alerts under one investigation (cases table below).
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS assignee text;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS case_id bigint;
CREATE INDEX IF NOT EXISTS alerts_case_idx ON alerts (case_id);

CREATE UNIQUE INDEX IF NOT EXISTS alerts_dedup_idx   ON alerts (rule_id, dedup_hash);
CREATE INDEX IF NOT EXISTS alerts_created_idx ON alerts (created_at DESC);
CREATE INDEX IF NOT EXISTS alerts_status_idx  ON alerts (status);
CREATE INDEX IF NOT EXISTS alerts_level_idx   ON alerts (lower(level));
CREATE INDEX IF NOT EXISTS alerts_assignee_idx ON alerts (assignee);

-- Free-form investigation notes threaded under an alert.
CREATE TABLE IF NOT EXISTS alert_notes (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    alert_id   bigint      NOT NULL,
    author     text,
    note       text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS alert_notes_alert_idx ON alert_notes (alert_id);

-- Suppression / allowlist rules: an alert that matches an enabled, unexpired rule
-- is stored as status='suppressed' and not notified. Each non-null column is an
-- AND condition, and src_ip accepts an exact IP or a CIDR.
CREATE TABLE IF NOT EXISTS suppressions (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name       text        NOT NULL,
    rule_id    text,
    src_ip     text,
    user_name  text,
    host_name  text,
    vendor     text,
    reason     text,
    enabled    boolean     NOT NULL DEFAULT true,
    created_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    hit_count  bigint      NOT NULL DEFAULT 0,
    last_hit   timestamptz
);
CREATE INDEX IF NOT EXISTS suppressions_enabled_idx ON suppressions (enabled);

-- Incidents / cases: one investigation grouping many related alerts. An alert
-- points at its case via alerts.case_id, and a case's severity rolls up to the
-- highest of its members.
CREATE TABLE IF NOT EXISTS cases (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    title      text        NOT NULL,
    summary    text,
    status     text        NOT NULL DEFAULT 'open',     -- open | investigating | closed
    severity   text        NOT NULL DEFAULT 'medium',
    assignee   text,
    created_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    closed_at  timestamptz
);
CREATE INDEX IF NOT EXISTS cases_status_idx   ON cases (status);
CREATE INDEX IF NOT EXISTS cases_assignee_idx ON cases (assignee);

-- Provenance: 'manual' (analyst-created) or 'killchain' (reconstructed attack
-- story). kc_signature is the stable hash of a story's alert set, used to avoid
-- auto-creating the same story twice.
ALTER TABLE cases ADD COLUMN IF NOT EXISTS source       text NOT NULL DEFAULT 'manual';
ALTER TABLE cases ADD COLUMN IF NOT EXISTS kc_signature text;
CREATE INDEX IF NOT EXISTS cases_kc_sig_idx ON cases (kc_signature);

-- Investigation notes threaded under a case.
CREATE TABLE IF NOT EXISTS case_notes (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    case_id    bigint      NOT NULL,
    author     text,
    note       text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS case_notes_case_idx ON case_notes (case_id);

-- ============================================================================
--  UEBA: entity baselines for behavioural analytics / risk scoring.
-- ============================================================================
-- One row per actor (user / host / ip), maintained incrementally at ingest. The
-- first_seen baseline drives "new entity" and (via entity_links) "new
-- association" anomalies, and risk is scored from the alerts attributed to it.
CREATE TABLE IF NOT EXISTS entities (
    entity_type  text        NOT NULL,          -- user | host | ip
    entity_value text        NOT NULL,
    first_seen   timestamptz NOT NULL,
    last_seen    timestamptz NOT NULL,
    event_count  bigint      NOT NULL DEFAULT 0,
    PRIMARY KEY (entity_type, entity_value)
);
CREATE INDEX IF NOT EXISTS entities_first_idx ON entities (first_seen DESC);
CREATE INDEX IF NOT EXISTS entities_type_idx  ON entities (entity_type);

-- Observed associations between entities (user↔ip, user↔host, host↔ip). A link
-- first seen recently whose subject entity is older is a "new association".
CREATE TABLE IF NOT EXISTS entity_links (
    entity_type  text        NOT NULL,
    entity_value text        NOT NULL,
    peer_type    text        NOT NULL,
    peer_value   text        NOT NULL,
    first_seen   timestamptz NOT NULL,
    last_seen    timestamptz NOT NULL,
    count        bigint      NOT NULL DEFAULT 0,
    PRIMARY KEY (entity_type, entity_value, peer_type, peer_value)
);
CREATE INDEX IF NOT EXISTS entity_links_first_idx   ON entity_links (first_seen DESC);
CREATE INDEX IF NOT EXISTS entity_links_subject_idx ON entity_links (entity_type, entity_value);
CREATE INDEX IF NOT EXISTS alerts_level_idx   ON alerts (level);
CREATE INDEX IF NOT EXISTS alerts_rule_idx    ON alerts (rule_id);
CREATE INDEX IF NOT EXISTS alerts_user_idx    ON alerts (user_name);
CREATE INDEX IF NOT EXISTS alerts_srcip_idx   ON alerts (src_ip);

-- Audit trail of agentless response actions taken when an alert matched a
-- playbook. A time-boxed action (playbook `revert_after`) stores when it is due
-- to be undone in revert_at — the revert scheduler fires the inverse action then
-- and stamps reverted_at so it is undone exactly once.
CREATE TABLE IF NOT EXISTS response_actions (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at  timestamptz NOT NULL DEFAULT now(),
    alert_id    bigint,
    playbook_id text        NOT NULL,
    action_type text        NOT NULL,   -- block_ip | disable_user | log | ...
    target      text,                   -- the IP / user / host acted on
    status      text        NOT NULL,   -- success | failed | skipped
    detail      text,
    revert_at   timestamptz
);
ALTER TABLE response_actions ADD COLUMN IF NOT EXISTS reverted_at timestamptz;
CREATE INDEX IF NOT EXISTS response_created_idx ON response_actions (created_at DESC);
CREATE INDEX IF NOT EXISTS response_alert_idx   ON response_actions (alert_id);
-- Successful, time-boxed actions still awaiting auto-revert.
CREATE INDEX IF NOT EXISTS response_revert_idx  ON response_actions (revert_at)
    WHERE reverted_at IS NULL AND revert_at IS NOT NULL;

-- Named, re-runnable event/alert queries. `path` is the page the query targets
-- (/search or /alerts) and `query` is its URL query string. `owner` is the
-- username who saved it ('' when auth is disabled) so searches stay per-user.
CREATE TABLE IF NOT EXISTS saved_searches (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now(),
    owner      text        NOT NULL DEFAULT '',
    name       text        NOT NULL,
    path       text        NOT NULL DEFAULT '/search',
    query      text        NOT NULL DEFAULT '',
    UNIQUE (owner, name, path)
);
CREATE INDEX IF NOT EXISTS saved_owner_idx ON saved_searches (owner, path, name);

-- ============================================================================
--  Agentless collectors (Phase 4): per-source pull state / checkpoint.
-- ============================================================================
-- One row per collector. `cursor` is the incremental checkpoint (e.g. the last
-- event timestamp pulled) so each run only fetches new records.
CREATE TABLE IF NOT EXISTS collectors (
    name        text PRIMARY KEY,
    enabled     boolean     NOT NULL DEFAULT true,
    cursor      text,
    last_run    timestamptz,
    last_status text,
    last_count  integer     NOT NULL DEFAULT 0,
    last_error  text
);

-- ============================================================================
--  Authentication & RBAC (Phase 5).
-- ============================================================================
-- Operators of the LogOcean UI. Only the password hash is stored (pbkdf2).
CREATE TABLE IF NOT EXISTS users (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username      text        NOT NULL UNIQUE,
    password_hash text        NOT NULL,
    role          text        NOT NULL DEFAULT 'viewer',   -- admin | analyst | viewer
    enabled       boolean     NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_login    timestamptz
);

-- Server-side sessions: a random token in an HttpOnly cookie maps to a user.
CREATE TABLE IF NOT EXISTS sessions (
    token      text PRIMARY KEY,
    user_id    bigint      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions (user_id);

-- Audit trail of security-relevant actions (login, purge, config changes, triage).
CREATE TABLE IF NOT EXISTS audit_log (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now(),
    username   text,                    -- actor (NULL pre-auth, e.g. a failed login)
    action     text        NOT NULL,    -- login | logout | purge | rule.toggle | ...
    detail     text,
    ip         text
);
CREATE INDEX IF NOT EXISTS audit_created_idx ON audit_log (created_at DESC);

-- ============================================================================
--  Threat intelligence: indicators of compromise (IOCs).
-- ============================================================================
-- Indicators loaded from feeds (by `source`) or added manually. The ingest
-- pipeline matches events against the enabled, unexpired rows, and a hit raises a
-- threat-intel alert. Re-syncing a feed replaces only that source's rows.
CREATE TABLE IF NOT EXISTS iocs (
    indicator   text        NOT NULL,
    ioc_type    text        NOT NULL,          -- ip | cidr | domain | hash | url
    source      text        NOT NULL DEFAULT 'manual',
    severity    text        NOT NULL DEFAULT 'high',
    description text,
    enabled     boolean     NOT NULL DEFAULT true,
    added_at    timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz,
    PRIMARY KEY (indicator, ioc_type)
);
CREATE INDEX IF NOT EXISTS iocs_type_idx   ON iocs (ioc_type);
CREATE INDEX IF NOT EXISTS iocs_source_idx ON iocs (source);

-- Custom field-mapper parsers authored from the console. Definitions are DATA,
-- never code: a signature (which raw key/value identifies the source) plus a
-- field map (raw key -> normalized column). Applied after the built-in parser
-- to fill columns the generic parsers could not map.
CREATE TABLE IF NOT EXISTS custom_parsers (
    parser_id   text PRIMARY KEY,
    title       text NOT NULL,
    match_key   text NOT NULL,
    match_value text NOT NULL,
    field_map   jsonb NOT NULL DEFAULT '{}',
    vendor      text,
    product     text,
    enabled     boolean NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS custom_parsers_enabled_idx ON custom_parsers (enabled);
ALTER TABLE custom_parsers ADD COLUMN IF NOT EXISTS kv_source text;
ALTER TABLE custom_parsers ADD COLUMN IF NOT EXISTS kv_sep    text;

-- Console-authored detection rules. Stored as Sigma-style YAML text so they load
-- through the same rule_from_dict path as file rules, and kept in the DB so they
-- survive image rebuilds (the rules directory is baked into the image).
CREATE TABLE IF NOT EXISTS custom_rules (
    rule_id    text PRIMARY KEY,
    title      text NOT NULL,
    yaml_text  text NOT NULL,
    enabled    boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Installed content packs (Phase 2). One row per pack; `document` is the VERBATIM
-- pack YAML (app/contentpack.py). Ownership ("which pack installed this rule?"),
-- upgrade ("what did the new version drop?") and uninstall ("remove exactly what I
-- added") are all derived from that document, so there is no second bookkeeping table
-- that can fall out of step with it. `digest` is the SHA-256 of the canonical parse —
-- it covers content, not formatting, so re-indenting a pack does not invalidate it.
CREATE TABLE IF NOT EXISTS content_packs (
    name         text PRIMARY KEY,
    version      text NOT NULL,
    format       integer NOT NULL DEFAULT 1,
    digest       text NOT NULL,
    document     text NOT NULL,
    signed_by    text,
    installed_at timestamptz NOT NULL DEFAULT now(),
    installed_by text
);
CREATE INDEX IF NOT EXISTS content_packs_installed_idx ON content_packs (installed_at DESC);

-- Encrypted credential store (the "secrets vault", Phase 2). One row per
-- (integration, name) slot — e.g. ('okta', 'token'), ('aws', 'secret_access_key').
--
-- `ciphertext` is AES-256-GCM (app/vault/crypto.py) over the master key in VAULT_KEY;
-- the GCM tag is appended by the AEAD, so no separate tag column. `nonce` is the 96-bit
-- IV drawn fresh on every write. `key_id` is a NON-SECRET fingerprint of the key that
-- sealed the row, so rotation can select exactly the stale rows instead of trying to
-- decrypt everything.
--
-- Nothing here is readable without VAULT_KEY, which deliberately does NOT live in this
-- database — that separation is the whole point: a dump, a backup or a read replica
-- carries ciphertext only.
CREATE TABLE IF NOT EXISTS secrets (
    integration text NOT NULL,
    name        text NOT NULL,
    ciphertext  bytea NOT NULL,
    nonce       bytea NOT NULL,
    key_id      text  NOT NULL,
    updated_by  text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (integration, name)
);
-- Rotation scans by key_id: "which rows are still under the previous key?"
CREATE INDEX IF NOT EXISTS secrets_key_id_idx ON secrets (key_id);
