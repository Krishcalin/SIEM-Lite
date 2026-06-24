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
