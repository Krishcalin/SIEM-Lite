# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Shared pytest fixtures.

The integration fixtures here connect to a real PostgreSQL so the partitioning,
full-text search, dedup, retention purge, correlation SQL and HTTP stack — none
of which the DB-free unit tests can exercise — are tested against the actual
database engine. They self-skip when NO DATABASE IS CONFIGURED, so the default
`pytest` run stays green on a machine without Postgres; CI provides the service.

Point them at a database with `DB_DSN` (or `TEST_DB_DSN`):
    DB_DSN=postgresql://logocean:logocean@localhost:5432/logocean pytest -m integration

CONFIGURED-BUT-BROKEN IS A FAILURE, NOT A SKIP — read `pg` and
`pytest_sessionfinish` below together. A configured DSN that cannot be reached used to
skip exactly like an absent one, so the CI integration job (which always sets DB_DSN)
would report a green, zero-second, zero-test pass whenever its service container was
down or its tests failed to import. It did so for roughly seventy commits, which is how
a blocker shipped, was documented, and never once ran against a real database.
"""
from __future__ import annotations

import os
import re

import pytest

# Tables truncated between integration tests (children of `events` are dropped
# separately so partition-creation assertions start from a clean slate).
_TABLES = ("events", "alerts", "alert_notes", "suppressions", "cases", "case_notes",
           "entities", "entity_links", "ingest_batches", "detection_rules", "api_keys",
           "response_actions", "collectors", "sessions", "users", "audit_log", "iocs",
           "saved_searches")


def _dsn() -> str:
    return os.getenv("DB_DSN") or os.getenv("TEST_DB_DSN") or ""


def _redacted(dsn: str) -> str:
    """`postgresql://user:***@host/db` — safe to put in a failure message."""
    return re.sub(r"(?<=://)([^:/@]+):([^@]*)(?=@)", r"\1:***", dsn)


@pytest.fixture(scope="session")
def pg():
    """Session-wide real-DB handle: align settings + pool to DB_DSN and run the schema.

    SKIPS ON ONE CONDITION ONLY: no DSN is configured at all. That is the contract —
    "self-skip when DB_DSN is unset" — and it is decided above, before a socket is
    opened. Once a DSN IS configured, every failure from here on propagates: an
    unreachable server, a wrong password, a database that does not exist, a schema.sql
    that will not apply. Somebody deliberately pointed this suite at a database; the only
    honest outcomes are "the tests ran" and "the job failed".

    This used to turn `psycopg.OperationalError` into a skip as well, which reads as
    prudence and is the opposite. The CI integration job always sets DB_DSN, so a dead
    service container produced skips and exit 0 — a green job that tested nothing,
    indistinguishable from a green job that tested everything. `pytest_sessionfinish`
    below is the second half of the same guard.
    """
    dsn = _dsn()
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
    except Exception as exc:  # noqa: BLE001 — re-raised with the context pytest strips
        raise RuntimeError(
            f"DB_DSN is set to {_redacted(dsn)} but the integration database could not "
            "be prepared, so these tests are FAILING rather than skipping. Either the "
            "server is unreachable (check the service container / credentials / that the "
            "database exists) or schema.sql did not apply (a schema defect). Unset "
            "DB_DSN if you genuinely have no database; a DSN that is set and broken is "
            "never a skip. Original error above."
        ) from exc
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


# --------------------------------------------------------------------------- #
#  "It ran nothing and said it passed" guard                                   #
# --------------------------------------------------------------------------- #
# Counts integration tests that were COLLECTED versus integration tests that actually
# reached their call phase. The `pg` fixture above closes the door on the specific hole
# that was found (a configured DSN that skipped), but the class of defect is broader
# than one fixture: any skip, any conditional, any future `pytest.skip` in a helper can
# empty an integration run without emptying its exit code. So the run is checked as a
# whole rather than trusting each entry point.
_integration = {"collected": 0, "executed": 0}


def pytest_collection_finish(session):
    # `session.items` is the FINAL selection — counted here rather than in
    # `pytest_collection_modifyitems`, which a conftest runs before the `mark` plugin has
    # applied `-m`. Counting there saw the integration tests even under
    # `-m "not integration"`, so a plain unit run on a developer machine with DB_DSN
    # exported would have failed this guard for doing exactly the right thing.
    _integration["collected"] = sum(
        1 for item in session.items
        if item.get_closest_marker("integration") is not None)


def pytest_runtest_logreport(report):
    # A `call` phase happens only for a test whose setup succeeded, so a fixture-level
    # skip (the `pg` fixture) never reaches here at all. The outcome still has to be
    # checked: `pytest.skip()` raised inside a test BODY does produce a call report, and
    # it is the same nothing as any other skip. Passed and failed both count as executed
    # — a failing test is reported by pytest itself and is not this guard's business.
    if (report.when == "call" and report.outcome != "skipped"
            and "integration" in report.keywords):
        _integration["executed"] += 1


def pytest_sessionfinish(session, exitstatus):
    """Fail a run that collected integration tests, had a database configured, and then
    executed none of them.

    Deliberately narrow so it cannot fire on a legitimate run:

    * No DSN configured -> the suite is supposed to skip, and this returns immediately.
      `pytest -m "not integration"` is unaffected for the same reason it collects no
      integration items.
    * Nothing collected -> either the selection excluded them or collection ERRORED, and
      a collection error already fails the session with its own non-zero exit code.
    * Anything executed -> ordinary pytest reporting takes over.
    * A run that was never meant to execute anything (`--collect-only`, `--setup-only`,
      `--setup-plan`) -> not a test run at all. Without this the collection check that
      this whole change is verified with would itself fail whenever DB_DSN is exported.

    What is left is precisely the failure that hid a blocker for seventy commits: tests
    collected, all skipped, exit 0, nobody any the wiser.
    """
    opt = session.config.option
    if any(getattr(opt, name, False)
           for name in ("collectonly", "setuponly", "setupplan")):
        return
    if not _dsn() or not _integration["collected"] or _integration["executed"]:
        return
    msg = (f"INTEGRATION SUITE RAN NOTHING: {_integration['collected']} test(s) were "
           f"collected with DB_DSN={_redacted(_dsn())} configured and none of them "
           "executed. A run that tests nothing must not report success -- fix the "
           "database, the fixtures or the selection. (Unset DB_DSN to skip on purpose.)")
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        reporter.write_line("")
        reporter.write_line(msg, red=True, bold=True)
    session.exitstatus = 1
