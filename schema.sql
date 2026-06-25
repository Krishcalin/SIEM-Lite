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

-- Dedup within partitions (must include the partition key on a partitioned table).
CREATE UNIQUE INDEX IF NOT EXISTS events_dedup_idx ON events (dedup_hash, event_time);

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

-- ============================================================================
--  Detection & alerting (Phase 2).
-- ============================================================================

-- Rule registry: metadata + enable flag per detection rule. The rule logic lives
-- in the YAML files under rules/; this table tracks enablement and is synced from
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

CREATE UNIQUE INDEX IF NOT EXISTS alerts_dedup_idx   ON alerts (rule_id, dedup_hash);
CREATE INDEX IF NOT EXISTS alerts_created_idx ON alerts (created_at DESC);
CREATE INDEX IF NOT EXISTS alerts_status_idx  ON alerts (status);
CREATE INDEX IF NOT EXISTS alerts_level_idx   ON alerts (level);
CREATE INDEX IF NOT EXISTS alerts_rule_idx    ON alerts (rule_id);
CREATE INDEX IF NOT EXISTS alerts_user_idx    ON alerts (user_name);
CREATE INDEX IF NOT EXISTS alerts_srcip_idx   ON alerts (src_ip);

-- Audit trail of agentless response actions taken when an alert matched a
-- playbook. revert_at is reserved for future stateful auto-revert.
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
CREATE INDEX IF NOT EXISTS response_created_idx ON response_actions (created_at DESC);
CREATE INDEX IF NOT EXISTS response_alert_idx   ON response_actions (alert_id);

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
