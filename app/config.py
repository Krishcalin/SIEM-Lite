# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Runtime configuration, read from environment variables (see .env.example)."""
from __future__ import annotations

import os
from dataclasses import dataclass


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    db_dsn: str = os.getenv("DB_DSN", "postgresql://logocean:logocean@localhost:5432/logocean")
    retention_years: int = int(os.getenv("RETENTION_YEARS", "3"))
    page_size: int = int(os.getenv("PAGE_SIZE", "100"))
    max_upload_mb: int = int(os.getenv("MAX_UPLOAD_MB", "512"))
    auto_purge: bool = _bool("AUTO_PURGE", False)

    # Detection engine: evaluate enabled rules inline as events are ingested.
    detection_enabled: bool = _bool("DETECTION_ENABLED", True)
    # How often (seconds) the scheduler evaluates correlation (threshold) rules.
    correlation_interval: int = int(os.getenv("CORRELATION_INTERVAL", "60"))

    # Notifications: send newly-raised alerts (>= min level) to channels.
    notify_enabled: bool = _bool("NOTIFY_ENABLED", False)
    notify_min_level: str = os.getenv("NOTIFY_MIN_LEVEL", "high").lower()
    notify_queue_max: int = int(os.getenv("NOTIFY_QUEUE_MAX", "1000"))
    # Webhook channel (Slack / Teams / Discord / generic incoming webhook or SOAR).
    webhook_url: str = os.getenv("WEBHOOK_URL", "")
    webhook_style: str = os.getenv("WEBHOOK_STYLE", "slack").lower()   # slack | json
    # Email channel (SMTP). Needs host + from + to (comma-separated) to activate.
    smtp_host: str = os.getenv("SMTP_HOST", "")
    smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
    smtp_user: str = os.getenv("SMTP_USER", "")
    smtp_password: str = os.getenv("SMTP_PASSWORD", "")
    smtp_from: str = os.getenv("SMTP_FROM", "")
    smtp_to: str = os.getenv("SMTP_TO", "")
    smtp_tls: bool = _bool("SMTP_TLS", True)

    # Agentless response: run playbooks on matching alerts; webhook actions POST
    # to your automation/SOAR endpoint. `log` actions need no endpoint.
    response_enabled: bool = _bool("RESPONSE_ENABLED", False)
    response_webhook_url: str = os.getenv("RESPONSE_WEBHOOK_URL", "")
    response_queue_max: int = int(os.getenv("RESPONSE_QUEUE_MAX", "1000"))
    # Stateful auto-revert: undo time-boxed actions (playbook `revert_after`) by
    # firing the inverse intent once their revert_at passes. Poll period seconds.
    response_auto_revert: bool = _bool("RESPONSE_AUTO_REVERT", True)
    response_revert_interval: int = int(os.getenv("RESPONSE_REVERT_INTERVAL", "60"))

    # Agentless collectors: scheduled pull of logs from vendor APIs into the
    # ingest pipeline. A collector activates only when its credentials are set.
    collectors_enabled: bool = _bool("COLLECTORS_ENABLED", False)
    collector_interval: int = int(os.getenv("COLLECTOR_INTERVAL", "300"))      # seconds
    collector_lookback_hours: int = int(os.getenv("COLLECTOR_LOOKBACK_HOURS", "24"))
    okta_domain: str = os.getenv("OKTA_DOMAIN", "")        # https://acme.okta.com
    okta_token: str = os.getenv("OKTA_TOKEN", "")
    github_org: str = os.getenv("GITHUB_ORG", "")
    github_token: str = os.getenv("GITHUB_TOKEN", "")
    gitlab_url: str = os.getenv("GITLAB_URL", "")          # https://gitlab.com
    gitlab_token: str = os.getenv("GITLAB_TOKEN", "")
    # AWS CloudTrail (SigV4-signed LookupEvents). Active when region + keys set.
    aws_region: str = os.getenv("AWS_REGION", "")          # e.g. us-east-1
    aws_access_key_id: str = os.getenv("AWS_ACCESS_KEY_ID", "")
    aws_secret_access_key: str = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    aws_session_token: str = os.getenv("AWS_SESSION_TOKEN", "")   # optional (STS)
    # Microsoft Entra ID / 365 (OAuth2 client credentials, one app registration).
    # Entra sign-ins activate when tenant+client+secret are set; the M365 unified
    # audit log additionally needs M365_ENABLED (separate API permission + a
    # started Management Activity subscription).
    azure_tenant_id: str = os.getenv("AZURE_TENANT_ID", "")
    azure_client_id: str = os.getenv("AZURE_CLIENT_ID", "")
    azure_client_secret: str = os.getenv("AZURE_CLIENT_SECRET", "")
    m365_enabled: bool = _bool("M365_ENABLED", False)
    m365_content_type: str = os.getenv("M365_CONTENT_TYPE", "Audit.General")
    # GCP Cloud Audit Logs (service-account signed-JWT OAuth2). Active when the
    # project + service-account email + private key are set. Copy client_email
    # and private_key straight out of the downloaded service-account JSON key
    # (escaped "\n" in the PEM is handled).
    gcp_project_id: str = os.getenv("GCP_PROJECT_ID", "")
    gcp_client_email: str = os.getenv("GCP_CLIENT_EMAIL", "")
    gcp_private_key: str = os.getenv("GCP_PRIVATE_KEY", "")
    gcp_token_uri: str = os.getenv("GCP_TOKEN_URI", "https://oauth2.googleapis.com/token")

    # Threat-intelligence enrichment: match ingested events against IOC feeds
    # (IPs/CIDRs/domains/hashes/URLs) and raise an alert on a hit. THREATINTEL_FEEDS
    # is a comma/space-separated list of local file paths or http(s) URLs; manual
    # indicators added in the UI also apply. Off by default.
    threatintel_enabled: bool = _bool("THREATINTEL_ENABLED", False)
    threatintel_feeds: str = os.getenv("THREATINTEL_FEEDS", "")
    threatintel_refresh_minutes: int = int(os.getenv("THREATINTEL_REFRESH_MINUTES", "60"))
    threatintel_default_severity: str = os.getenv("THREATINTEL_DEFAULT_SEVERITY", "high")

    # UEBA / entity risk: maintain per-entity (user/host/ip) baselines at ingest
    # and score risk from attributed alerts (severity-weighted, recency-decayed).
    # On by default (cheap upserts); the Risk page surfaces it. Tune the decay
    # half-life and scoring window in days.
    ueba_enabled: bool = _bool("UEBA_ENABLED", True)
    risk_half_life_days: float = float(os.getenv("RISK_HALF_LIFE_DAYS", "7"))
    risk_window_days: int = int(os.getenv("RISK_WINDOW_DAYS", "30"))

    # Kill-chain reconstruction: stitch related alerts (shared entity + time
    # proximity) that span multiple ATT&CK tactics into attack stories on the
    # /killchain page. Auto-create is opt-in and only fires for stories at or
    # above KILLCHAIN_MIN_SEVERITY.
    killchain_enabled: bool = _bool("KILLCHAIN_ENABLED", True)
    killchain_window_hours: int = int(os.getenv("KILLCHAIN_WINDOW_HOURS", "24"))
    killchain_max_gap_minutes: int = int(os.getenv("KILLCHAIN_MAX_GAP_MINUTES", "60"))
    killchain_min_tactics: int = int(os.getenv("KILLCHAIN_MIN_TACTICS", "2"))
    killchain_autocreate: bool = _bool("KILLCHAIN_AUTOCREATE", False)
    killchain_interval: int = int(os.getenv("KILLCHAIN_INTERVAL", "300"))       # seconds
    killchain_min_severity: str = os.getenv("KILLCHAIN_MIN_SEVERITY", "high").lower()

    # Detection-engineering workbench: ATT&CK coverage map, rule-health analytics
    # (never-fired / noisy / stale), and an in-app rule tester on /workbench.
    workbench_window_days: int = int(os.getenv("WORKBENCH_WINDOW_DAYS", "30"))
    workbench_noisy_threshold: int = int(os.getenv("WORKBENCH_NOISY_THRESHOLD", "50"))

    # Log-source health: alert when a source (vendor/log_type) that was sending
    # regularly goes SILENT — a collector/forwarder outage, a broken device, or an
    # attacker disabling logging (MITRE T1562). A source counts as "expected" once
    # it has >= MIN_EVENTS in the learning window; it is "silent" when its newest
    # event is older than SILENCE_MINUTES; an ongoing outage re-alerts at most once
    # per REPEAT_HOURS. Stateless (derived from events); on by default. /sources.
    source_health_enabled: bool = _bool("SOURCE_HEALTH_ENABLED", True)
    source_health_interval: int = int(os.getenv("SOURCE_HEALTH_INTERVAL", "300"))      # seconds
    source_health_silence_minutes: int = int(os.getenv("SOURCE_HEALTH_SILENCE_MINUTES", "60"))
    source_health_learn_days: int = int(os.getenv("SOURCE_HEALTH_LEARN_DAYS", "7"))
    source_health_min_events: int = int(os.getenv("SOURCE_HEALTH_MIN_EVENTS", "5"))
    source_health_level: str = os.getenv("SOURCE_HEALTH_LEVEL", "medium").lower()
    source_health_repeat_hours: int = int(os.getenv("SOURCE_HEALTH_REPEAT_HOURS", "24"))

    # AI SOC copilot (Claude): alert/case explainers + Sigma-rule-from-NL. Off by
    # default; needs the `anthropic` package and an API key (COPILOT_API_KEY, or
    # ANTHROPIC_API_KEY in the environment). Model is configurable so operators can
    # trade cost for capability (e.g. claude-sonnet-4-6 / claude-haiku-4-5).
    copilot_enabled: bool = _bool("COPILOT_ENABLED", False)
    copilot_api_key: str = os.getenv("COPILOT_API_KEY", "")
    copilot_model: str = os.getenv("COPILOT_MODEL", "claude-opus-4-8")
    copilot_max_tokens: int = int(os.getenv("COPILOT_MAX_TOKENS", "1024"))

    # Authentication (Phase 5). Off by default (front with SSO/proxy); set
    # AUTH_ENABLED=true for built-in login + RBAC. On first run an admin is
    # bootstrapped from ADMIN_USER/ADMIN_PASSWORD (a random password is logged
    # if ADMIN_PASSWORD is unset).
    auth_enabled: bool = _bool("AUTH_ENABLED", False)
    session_ttl_hours: int = int(os.getenv("SESSION_TTL_HOURS", "12"))
    session_cookie_secure: bool = _bool("SESSION_COOKIE_SECURE", False)  # True behind HTTPS
    admin_user: str = os.getenv("ADMIN_USER", "admin")
    admin_password: str = os.getenv("ADMIN_PASSWORD", "")

    # LOQL — the piped analytics query language (POST /api/v1/query). Guardrails keep
    # one heavy analyst query from starving ingest on the shared Postgres: a per-query
    # statement timeout, a hard row cap, and a default result LIMIT.
    loql_default_limit: int = int(os.getenv("LOQL_DEFAULT_LIMIT", "1000"))
    loql_max_rows: int = int(os.getenv("LOQL_MAX_ROWS", "100000"))
    loql_timeout_ms: int = int(os.getenv("LOQL_TIMEOUT_MS", "30000"))
    # cap the element count of values()/list() aggregates so a single grouped row cannot
    # array_agg an unbounded amount of memory (the LIMIT/row-cap count rows, not cell size).
    loql_max_agg_elems: int = int(os.getenv("LOQL_MAX_AGG_ELEMS", "10000"))

    # CIM data models — the vendor-agnostic schemas in app/cim/models.yaml. Membership
    # itself is NOT gated here: `events.cim_models` is stamped in Python at ingest and
    # detections + `datamodel:` searches read that column, so switching it off would
    # silently break them. CIM_ENABLED gates the database-side half only — the per-model
    # `cim_<tag>` views rebuilt from the registry at startup.
    cim_enabled: bool = _bool("CIM_ENABLED", True)
    # /datamodels can show a live member count per model. Each one is an aggregate over
    # an indexed `cim_models @> ARRAY[tag]` predicate — cheap on a young store, a bitmap
    # heap scan of most of the table on a three-year one. So counting is opt-in per page
    # view and bounded twice: CIM_COUNT_DAYS windows it (0 disables counting, and a
    # window lets the planner prune whole partitions), and CIM_COUNT_TIMEOUT_MS is the
    # budget for the WHOLE sweep — each model gets a slice of what is left, so a starved
    # database costs one budget rather than one timeout per model.
    cim_count_days: int = int(os.getenv("CIM_COUNT_DAYS", "30"))
    cim_count_timeout_ms: int = int(os.getenv("CIM_COUNT_TIMEOUT_MS", "5000"))
    # Rows per committed chunk of the admin membership backfill (db.backfill_cim), the
    # maintenance pass that re-derives cim_models for events already stored after a
    # models.yaml membership edit. Smaller chunks hold shorter locks, at more round trips.
    cim_backfill_chunk: int = int(os.getenv("CIM_BACKFILL_CHUNK", "2000"))

    # Async ingest queue (live sources buffer here; writer workers batch-insert).
    ingest_queue_max: int = int(os.getenv("INGEST_QUEUE_MAX", "10000"))
    ingest_workers: int = int(os.getenv("INGEST_WORKERS", "2"))
    ingest_flush_max: int = int(os.getenv("INGEST_FLUSH_MAX", "2000"))   # events per flush
    ingest_flush_ms: int = int(os.getenv("INGEST_FLUSH_MS", "1000"))     # max buffer age

    # Syslog receiver (Phase 1 live ingestion). Default port 5514 so the
    # non-root container needn't bind the privileged 514; map 514->5514 if wanted.
    syslog_enabled: bool = _bool("SYSLOG_ENABLED", False)
    syslog_host: str = os.getenv("SYSLOG_HOST", "0.0.0.0")
    syslog_udp_port: int = int(os.getenv("SYSLOG_UDP_PORT", "5514"))     # 0 disables UDP
    syslog_tcp_port: int = int(os.getenv("SYSLOG_TCP_PORT", "5514"))     # 0 disables TCP
    syslog_format: str = os.getenv("SYSLOG_FORMAT", "auto")             # fixed fmt or "auto"
    syslog_tls_cert: str = os.getenv("SYSLOG_TLS_CERT", "")            # enables TLS on TCP
    syslog_tls_key: str = os.getenv("SYSLOG_TLS_KEY", "")


settings = Settings()
