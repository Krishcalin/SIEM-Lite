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
