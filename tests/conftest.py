"""Shared pytest fixtures.

The integration fixtures here connect to a real PostgreSQL so the partitioning,
full-text search, dedup, retention purge, correlation SQL and HTTP stack — none
of which the DB-free unit tests can exercise — are tested against the actual
database engine. They self-skip when no database is reachable, so the default
`pytest` run stays green on a machine without Postgres; CI provides the service.

Point them at a database with `DB_DSN` (or `TEST_DB_DSN`):
    DB_DSN=postgresql://logocean:logocean@localhost:5432/logocean pytest -m integration
"""
from __future__ import annotations

import os

import pytest

# Tables truncated between integration tests (children of `events` are dropped
# separately so partition-creation assertions start from a clean slate).
_TABLES = ("events", "alerts", "ingest_batches", "detection_rules", "api_keys",
           "response_actions", "collectors", "sessions", "users", "audit_log", "iocs")


@pytest.fixture(scope="session")
def pg():
    """Session-wide real-DB handle: align settings + pool to DB_DSN and run the
    schema. Skips the whole integration suite if no database is reachable."""
    dsn = os.getenv("DB_DSN") or os.getenv("TEST_DB_DSN")
    if not dsn:
        pytest.skip("integration tests need a database — set DB_DSN")

    from app import db
    from app.config import settings

    # settings is a frozen dataclass built at import; force the test DSN and drop
    # any pool that may have been opened against a different one.
    object.__setattr__(settings, "db_dsn", dsn)
    if db._pool is not None:
        try:
            db._pool.close()
        except Exception:  # noqa: BLE001
            pass
        db._pool = None

    try:
        db.init_schema()
    except Exception as exc:  # noqa: BLE001 — DB unreachable / wrong creds
        pytest.skip(f"cannot reach PostgreSQL at DB_DSN: {exc}")
    return db


@pytest.fixture
def clean_db(pg):
    """Empty every table (and drop month partitions) before a test, for isolation."""
    with pg.pool().connection() as conn:
        parts = conn.execute(
            "SELECT c.relname AS name FROM pg_inherits i "
            "JOIN pg_class c ON c.oid = i.inhrelid "
            "WHERE i.inhparent = 'events'::regclass AND c.relname ~ '^events_[0-9]{6}$'"
        ).fetchall()
        for r in parts:
            conn.execute(f"DROP TABLE IF EXISTS {r['name']}")
        conn.execute(f"TRUNCATE {', '.join(_TABLES)} RESTART IDENTITY CASCADE")
        conn.commit()
    return pg
