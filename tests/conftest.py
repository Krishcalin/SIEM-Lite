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
# `cim_meta` is the one-row CIM registry stamp (schema.sql, Backbone 2): it must be
# emptied like everything else, or the `backfill_due` / `applied_at` state one test
# writes becomes the starting state of the next.
# `content_packs`, `custom_parsers` and `custom_rules` are swept for the same reason
# `cim_meta` is: a pack writes rows into all three, and an installed pack is precisely
# the state that decides OWNERSHIP — whether the next install is an update, a no-op or
# a conflict. HONEST SCOPE: no test currently depends on this. The Phase-2 pack tests
# happen to pass without it because the last one to run uninstalls, so the tables are
# empty by the time the conflict test asserts they are. That is an accident of
# ordering, not isolation, which is exactly why the sweep is here rather than left to
# be discovered by whoever adds the test that reorders them.
_TABLES = ("events", "alerts", "alert_notes", "suppressions", "cases", "case_notes",
           "entities", "entity_links", "ingest_batches", "detection_rules", "api_keys",
           "response_actions", "collectors", "sessions", "users", "audit_log", "iocs",
           "saved_searches", "cim_meta", "secrets", "content_packs", "custom_parsers",
           "custom_rules",
           # The Phase-3 registry. `asset_meta` carries the backfill stamp, so leaving
           # it behind would make one test's "history is current" the starting state of
           # the next. The alias tables are listed before their parents only for
           # readability — TRUNCATE ... CASCADE handles the FKs either way.
           "asset_aliases", "identity_aliases", "assets", "identities", "asset_meta")

# Exactly the shape `app.cim.sql.view_name` emits, matched independently of that module
# on purpose: this is the broom the CIM tests are swept up with, so it must not share a
# code path (or a bug) with the reconciler those tests are trying to prove correct.
_CIM_VIEW_RE = re.compile(r"^cim_[a-z][a-z0-9_]*$")


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
    service container produced 52 skips and exit 0 — a green job that tested nothing,
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
    """Empty every table (and drop month partitions) before a test, for isolation.

    Also reconciles the `cim_<tag>` views: any view matching the CIM naming shape that
    the *current* registry does not define is dropped. A test that deliberately plants a
    stale `cim_zzz` (to prove `db.init_cim` reconciles orphans) would otherwise leave it
    behind and change the orphan count another test asserts on. The views of real models
    are left alone — they are cheap, `init_cim` rebuilds them anyway, and dropping them
    here would make every test that reads one depend on fixture ordering.

    CASCADE is used *only here*, and the contrast is the point: `db._drop_orphan_cim_views`
    is deliberately RESTRICT so production never deletes an operator's dependent object
    silently. The orphan test plants such a dependent object to prove that; this broom has
    to be able to sweep it up afterwards, so it is the one place CASCADE is correct.
    """
    with pg.pool().connection() as conn:
        parts = conn.execute(
            "SELECT c.relname AS name FROM pg_inherits i "
            "JOIN pg_class c ON c.oid = i.inhrelid "
            "WHERE i.inhparent = 'events'::regclass AND c.relname ~ '^events_[0-9]{6}$'"
        ).fetchall()
        for r in parts:
            conn.execute(f"DROP TABLE IF EXISTS {r['name']}")

        from app.cim import get_registry, view_name
        keep = {view_name(m) for m in get_registry().models}
        views = conn.execute(
            "SELECT viewname FROM pg_views WHERE schemaname = current_schema() "
            "AND viewname LIKE %s", (r"cim\_%",)).fetchall()
        for v in views:
            name = v["viewname"]
            if name not in keep and _CIM_VIEW_RE.match(name):
                conn.execute(f"DROP VIEW IF EXISTS {name} CASCADE")

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

    What is left is precisely the failure that hid a blocker for seventy commits: 52
    tests collected, 52 skipped, exit 0, nobody any the wiser.
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
