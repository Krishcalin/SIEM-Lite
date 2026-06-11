"""Runtime configuration, read from environment variables (see .env.example)."""
from __future__ import annotations

import os
from dataclasses import dataclass


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    db_dsn: str = os.getenv("DB_DSN", "postgresql://logvault:logvault@localhost:5432/logvault")
    retention_years: int = int(os.getenv("RETENTION_YEARS", "3"))
    page_size: int = int(os.getenv("PAGE_SIZE", "100"))
    max_upload_mb: int = int(os.getenv("MAX_UPLOAD_MB", "512"))
    auto_purge: bool = _bool("AUTO_PURGE", False)


settings = Settings()
