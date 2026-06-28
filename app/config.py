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

    # Authentication (Phase 5). Off by default (front with SSO/proxy); set
    # AUTH_ENABLED=true for built-in login + RBAC. On first run an admin is
    # bootstrapped from ADMIN_USER/ADMIN_PASSWORD (a random password is logged
    # if ADMIN_PASSWORD is unset).
    auth_enabled: bool = _bool("AUTH_ENABLED", False)
    session_ttl_hours: int = int(os.getenv("SESSION_TTL_HOURS", "12"))
    session_cookie_secure: bool = _bool("SESSION_COOKIE_SECURE", False)  # True behind HTTPS
    admin_user: str = os.getenv("ADMIN_USER", "admin")
    admin_password: str = os.getenv("ADMIN_PASSWORD", "")

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
