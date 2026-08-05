# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Geo wiring: the store seams that join `app/enrich` to `events`.

`tests/test_geo.py` covers the resolver, `tests/test_enrich_sources.py` the range
sources and `tests/test_mmdb.py` the reader. This file covers what the WIRE layer owns
and nobody else can test:

* the merge into `events.context_tags`, which is ONE column with TWO producers;
* `db._row` binding all four geo columns on the default path;
* the two backfills, driven over a fake connection so the loop itself — not just the
  SQL text — is exercised without a database.

DB-FREE ON PURPOSE. The backfill tests below drive the real `backfill_geo` /
`backfill_assets` loops against a stub connection, so they prove the derivation and the
merge. They do NOT prove PostgreSQL accepts the statements or that the partition-keyed
UPDATE finds its row; that is the integration suite's job (`-m integration`) and it is
the gate on this slice, not this file.

THE ASSET AND GEO RESOLVERS HERE ARE BOTH REAL. `assets.build` assembles a genuine
index from literal rows and `geo.literal_source` a genuine geo one, so the labels being
merged are the labels production would produce, not fixtures shaped to agree.
"""
from __future__ import annotations

import datetime as dt
import re
from contextlib import contextmanager
from pathlib import Path

import pytest

from app import assets, db
from app.enrich import geo
from app.models import NormalizedEvent

REPO_ROOT = Path(__file__).resolve().parent.parent
_T = dt.datetime(2026, 8, 4, 12, 0, tzinfo=dt.timezone.utc)


def evt(**cols) -> NormalizedEvent:
    cols.setdefault("vendor", "acme")
    return NormalizedEvent(event_time=_T, **cols)


#: A real asset index: one declared host with a category and an environment, reachable
#: by hostname AND by address, so an event can resolve a `host:` label and a `dst:` one.
def asset_index():
    return assets.build(
        asset_rows=[dict(asset_id="srv-db-01", enabled=True, criticality="critical",
                         category=["server"], environment="prod")],
        identity_rows=[],
        asset_alias_rows=[{"alias_type": "hostname", "alias_value": "srv-db-01",
                           "asset_id": "srv-db-01"},
                          {"alias_type": "ip", "alias_value": "10.1.1.1",
                           "asset_id": "srv-db-01"}],
        identity_alias_rows=[])


#: A real geo index answering for one public address.
def geo_index():
    return geo.GeoIndex([geo.literal_source(
        {"8.8.8.8": {"country": "US", "asn": 15169}})])


@pytest.fixture
def wired():
    """Both indexes installed through the REAL module caches, and both write-state
    counters reset.

    `set_index` rather than monkeypatching `get_index`, and that distinction caught a
    bug: `geo.stats()` reads the module cache directly while `db.geo_status()` goes
    through `get_index()`, so a fixture that patched only the accessor left the two
    reporting different indexes — a disagreement that cannot happen in production and
    would have made the /health merge test assert against a fiction.

    The counters and the caches are module globals shared with every other test in the
    session, so both are restored on the way out. A test that leaves one dirty makes an
    unrelated assertion elsewhere fail, which only ever shows up as a reordering flake.
    """
    assets.set_index(asset_index())
    geo.set_index(geo_index())
    db.reset_geo_write_state()
    db.reset_asset_write_state()
    yield
    assets.set_index(None)
    geo.set_index(None)
    db.reset_geo_write_state()
    db.reset_asset_write_state()


# ══════════════════════════════════════════════════════════════════════════════
#  The merge — one array, two producers
# ══════════════════════════════════════════════════════════════════════════════
def test_both_label_sets_survive_the_merge(wired):
    """THE property this whole slice turns on.

    `events.context_tags` is written by `db._row`, `backfill_assets` and `backfill_geo`.
    The asset registry emits `host:server` / `host:prod`; geo emits `src:public` /
    `dst:private`. If either producer's labels can be lost, the loss is invisible in the
    data — a row with stripped context looks exactly like a row about an undeclared
    host on an unclassified address.
    """
    out = db._derived_context(
        evt(host_name="srv-db-01", src_ip="8.8.8.8", dst_ip="10.1.1.1"))
    # `10.1.1.1` is a declared alias of the same host, so the asset side contributes
    # `dst:` labels too — and `dst:private` from geo lands in among them without either
    # producer losing anything.
    assert out["context_tags"] == ["dst:private", "dst:prod", "dst:server",
                                   "host:prod", "host:server", "src:public"]


def test_the_geo_scalars_ride_alongside_the_labels(wired):
    out = db._derived_context(evt(src_ip="8.8.8.8", dst_ip="10.1.1.1"))
    assert (out["src_country"], out["src_asn"]) == ("US", 15169)
    assert (out["dst_country"], out["dst_asn"]) == (None, None)


def test_the_registry_columns_are_untouched_by_geo(wired):
    out = db._derived_context(evt(host_name="srv-db-01", src_ip="8.8.8.8"))
    assert out["asset_id"] == "srv-db-01"
    assert out["asset_criticality"] == "critical"


def test_the_merged_array_is_sorted_deduplicated_and_lower_cased(wired):
    """A backfilled row must be BYTE-IDENTICAL to a freshly ingested one or every
    backfill run rewrites every heap tuple it touches. `tuple(set(...))` orders by hash
    and Python randomizes string hashes per process, so ingest and a later backfill
    would disagree in production only."""
    out = db._derived_context(evt(src_ip="10.1.1.1", dst_ip="10.9.9.9"))
    tags = out["context_tags"]
    assert tags == sorted(tags)
    assert len(tags) == len(set(tags))
    assert all(t == t.lower() and t == t.strip() for t in tags)


def test_an_already_resolved_geo_result_is_honoured_rather_than_recomputed(wired):
    """`_geo_context` accepts a pre-resolved `GeoResult` on the same terms
    `_asset_context` accepts a `Resolution`. It is what keeps the resolver PURE and
    substitutable — and it is the seam a future caller that resolves once and writes
    twice would use. Untested, it would be plumbing nobody could rely on."""
    from app.enrich.models import GeoResult

    pinned = GeoResult(src_country="ZA", src_asn=327, context_tags=("src:public",))
    # `10.9.9.9` is UNDECLARED, so the asset side contributes nothing and the array is
    # the pinned geo result alone. (`10.1.1.1` is an alias of the fixture host, which
    # would fold `src:prod` / `src:server` in and blur what this test is asserting.)
    out = db._derived_context(evt(src_ip="10.9.9.9"), geo_res=pinned)
    assert out["src_country"] == "ZA" and out["src_asn"] == 327
    # The pinned result was USED, not recomputed: a fresh resolve of 10.9.9.9 would say
    # `src:private`, and the scope layer was never consulted.
    assert out["context_tags"] == ["src:public"]


def test_a_row_with_no_context_at_all_binds_null_not_an_empty_array(wired):
    """NULL keeps the GIN index proportional to rows that actually carry context — the
    rule `cim_models` follows one column over. `'{}'` would index every row in the
    store."""
    out = db._derived_context(evt(host_name="undeclared-host"))
    assert out["context_tags"] is None


def test_an_address_only_event_still_gets_scope_labels_with_no_geo_database():
    """User decision 3, at the store seam: scope classification is arithmetic and needs
    no data file, so an install that side-loads nothing still labels every row. The
    country columns stay NULL, which is configuration and not a fault."""
    out = db._derived_context(evt(src_ip="10.1.1.1", dst_ip="8.8.8.8"),
                              geo_index=geo.EMPTY_INDEX)
    assert out["context_tags"] == ["dst:public", "src:private"]
    assert out["src_country"] is None and out["dst_country"] is None


# ══════════════════════════════════════════════════════════════════════════════
#  Degradation — context is never worth an event
# ══════════════════════════════════════════════════════════════════════════════
class _Exploding:
    """An index whose lookup raises, standing in for a resolver defect."""

    sources = ("x",)
    fingerprint = "boom"

    def is_empty(self):
        return False

    def lookup(self, ip):
        raise RuntimeError("resolver defect")


def test_a_geo_failure_costs_the_geo_columns_and_nothing_else(wired, monkeypatch):
    def explode(*a, **kw):
        raise RuntimeError("resolver defect")

    monkeypatch.setattr(geo, "resolve", explode)
    out = db._derived_context(evt(host_name="srv-db-01", src_ip="8.8.8.8"))
    # The event is still storable, its registry context intact...
    assert out["asset_id"] == "srv-db-01"
    assert out["context_tags"] == ["host:prod", "host:server"]
    # ...and the four geo columns degrade together, from the one named constant.
    assert {k: out[k] for k in db._NO_GEO} == db._NO_GEO
    assert db.geo_write_state()["failures"] == 1


def test_the_geo_failure_counter_is_separate_from_the_asset_one(wired, monkeypatch):
    """/health has to be able to say WHICH subsystem is degrading rows. One shared
    counter would report a broken geo file as missing business context, sending the
    operator to `backfill_assets` for a problem it cannot fix."""
    monkeypatch.setattr(geo, "resolve",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    db._derived_context(evt(src_ip="8.8.8.8"))
    assert db.geo_write_state()["failures"] == 1
    assert db.asset_write_state()["failures"] == 0


def test_no_geo_and_no_context_never_share_a_key(wired):
    """`backfill_assets` compares `_asset_context`'s dict against a hand-built five-key
    `current` dict. Widening `_NO_CONTEXT` with geo keys would make those two different
    SHAPES, so `new != current` would hold for every row forever — a full-table rewrite
    on every run with `unchanged` permanently zero."""
    assert set(db._NO_GEO) & set(db._NO_CONTEXT) == set()
    assert set(db._NO_GEO) == set(db._GEO_COLUMNS)
    assert set(db._NO_CONTEXT) == set(db._ASSET_COLUMNS) | {"context_tags"}


# ══════════════════════════════════════════════════════════════════════════════
#  `db._row` — the ingest bind parameters
# ══════════════════════════════════════════════════════════════════════════════
def test_row_binds_every_geo_column_on_the_default_path(wired):
    """No `geo=` argument exists, deliberately: a column derived only when an optional
    argument is passed would bind NULL for every real ingest and nothing would say so."""
    # `10.9.9.9` is undeclared, so the array here is geo's contribution alone.
    row = db._row(evt(src_ip="8.8.8.8", dst_ip="10.9.9.9"), 1)
    assert row["src_country"] == "US"
    assert row["src_asn"] == 15169
    assert row["dst_country"] is None and row["dst_asn"] is None
    assert row["context_tags"] == ["dst:private", "src:public"]


def test_row_merges_registry_and_geo_labels_into_the_one_array(wired):
    row = db._row(evt(host_name="srv-db-01", src_ip="8.8.8.8"), 1)
    assert "host:server" in row["context_tags"]      # from the registry
    assert "src:public" in row["context_tags"]       # from geo


def test_insert_events_takes_no_new_keyword(wired):
    """`pipeline.write_stream` probes this signature with `inspect.signature` and falls
    back to a three-argument call, and a test double monkeypatches it with a
    three-argument lambda. Geo resolves inside `_row` precisely so that neither breaks."""
    import inspect

    assert list(inspect.signature(db.insert_events).parameters) == [
        "conn", "events", "batch_id", "cim_tags"]


# ══════════════════════════════════════════════════════════════════════════════
#  The two UPDATE statements cannot clobber each other's scalar columns
# ══════════════════════════════════════════════════════════════════════════════
def _set_columns(sql: str) -> set[str]:
    body = sql.split(" SET ", 1)[1].split(" WHERE ", 1)[0]
    return set(re.findall(r"(\w+)\s*=\s*%\(", body))


def test_each_backfill_writes_only_its_own_columns_plus_the_shared_array():
    """Ownership of a LABEL is not recoverable from its text — geo's `src:public` is
    spelled exactly like the label an operator gets by naming a DMZ environment
    `public`. Ownership of a COLUMN is, and it is what keeps the two backfills from
    undoing each other."""
    asset_cols = _set_columns(db._ASSET_UPDATE)
    geo_cols = _set_columns(db._GEO_UPDATE)
    assert asset_cols == set(db._ASSET_COLUMNS) | {"context_tags"}
    assert geo_cols == set(db._GEO_COLUMNS) | {"context_tags"}
    assert asset_cols & geo_cols == {"context_tags"}


def test_the_geo_backfill_selects_both_resolvers_input_fields():
    """It rewrites the SHARED array, so it must re-derive the asset labels too — which
    needs `host_name` and `user_name`, not just the addresses it resolves itself."""
    for field in ("host_name", "user_name", "src_ip", "dst_ip"):
        assert field in db._GEO_BACKFILL_COLS, field
    for col in db._GEO_COLUMNS + ("context_tags", "id", "event_time"):
        assert col in db._GEO_BACKFILL_COLS, col


def test_the_geo_backfill_query_is_keyset_paginated_and_partition_aware():
    sql, params = db._geo_backfill_query()
    assert "id > %(_after)s" in sql and "ORDER BY id" in sql and params == {}
    sql, params = db._geo_backfill_query(since=_T, until=_T)
    assert "event_time >= %(_since)s" in sql and "event_time < %(_until)s" in sql
    assert set(params) == {"_since", "_until"}
    # The partition key must be in the UPDATE predicate or the row is not addressable.
    assert "event_time = %(event_time)s" in db._GEO_UPDATE


# ══════════════════════════════════════════════════════════════════════════════
#  The backfill loops, over a fake connection
# ══════════════════════════════════════════════════════════════════════════════
class _Result:
    def __init__(self, rows, rowcount=1):
        self._rows, self.rowcount = rows, rowcount

    def fetchall(self):
        return self._rows

    def fetchone(self):
        return self._rows[0] if self._rows else None


class _Cursor:
    def __init__(self, sink):
        self.sink = sink

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def executemany(self, sql, rows):
        self.sink.append((sql, list(rows)))


class _Conn:
    """Enough of a psycopg connection to drive a backfill loop: successive SELECTs
    return successive pages, everything else reports one affected row."""

    def __init__(self, pages):
        self.pages, self.writes, self.executed, self.commits = list(pages), [], [], 0

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        if sql.lstrip().upper().startswith("SELECT"):
            return _Result(self.pages.pop(0) if self.pages else [])
        return _Result([], rowcount=1)

    def cursor(self):
        return _Cursor(self.writes)

    def commit(self):
        self.commits += 1


def fake_pool(monkeypatch, conn):
    @contextmanager
    def connection():
        yield conn

    monkeypatch.setattr(db, "pool", lambda: type("P", (), {"connection": staticmethod(
        connection)})())
    return conn


def stored_row(**over):
    """A stored `events` row as the backfill SELECTs it: no context derived yet."""
    row = {"id": 1, "event_time": _T, "host_name": "srv-db-01", "user_name": None,
           "src_ip": "8.8.8.8", "dst_ip": "10.1.1.1",
           "asset_id": None, "asset_criticality": None,
           "identity_id": None, "identity_priority": None,
           "src_country": None, "dst_country": None,
           "src_asn": None, "dst_asn": None, "context_tags": None}
    row.update(over)
    return row


def test_the_geo_backfill_writes_the_geo_columns_and_keeps_the_asset_labels(
        wired, monkeypatch):
    """The mirror of the clobber below: `backfill_geo` rewrites `context_tags`, so it
    must re-derive the ASSET labels or it would strip business context from every row
    it corrected."""
    conn = fake_pool(monkeypatch, _Conn([[stored_row()], []]))
    out = db.backfill_geo()

    assert out["scanned"] == 1 and out["updated"] == 1
    sql, rows = conn.writes[0]
    assert sql == db._GEO_UPDATE
    assert rows[0]["src_country"] == "US" and rows[0]["src_asn"] == 15169
    assert "host:server" in rows[0]["context_tags"]     # the asset side survived
    assert "src:public" in rows[0]["context_tags"]      # ...and geo's own labels landed


def test_the_asset_backfill_does_not_strip_the_geo_scope_labels(wired, monkeypatch):
    """THE hazard this slice was warned about. `_ASSET_UPDATE` sets `context_tags`
    unconditionally, so deriving that array from asset labels alone would delete every
    `src:public` / `dst:private` from every row the asset backfill touched — and would
    then see a difference on all of them, turning a no-op run into a full-table
    rewrite."""
    conn = fake_pool(monkeypatch, _Conn([[stored_row()], []]))
    db.backfill_assets()

    sql, rows = conn.writes[0]
    assert sql == db._ASSET_UPDATE
    assert "src:public" in rows[0]["context_tags"]
    assert "dst:private" in rows[0]["context_tags"]
    assert "host:server" in rows[0]["context_tags"]
    # It writes no geo scalar: those belong to `backfill_geo`.
    assert not set(db._GEO_COLUMNS) & set(rows[0])


def test_the_two_backfills_agree_on_the_array_they_both_write(wired, monkeypatch):
    """Run in either order they must converge, because both derive the array through
    `_derived_context`. If they disagreed, each run would undo the other and neither
    would ever report `unchanged`."""
    c1 = fake_pool(monkeypatch, _Conn([[stored_row()], []]))
    db.backfill_geo()
    geo_tags = c1.writes[0][1][0]["context_tags"]

    c2 = fake_pool(monkeypatch, _Conn([[stored_row()], []]))
    db.backfill_assets()
    asset_tags = c2.writes[0][1][0]["context_tags"]

    assert geo_tags == asset_tags


def test_an_already_correct_row_is_not_written_at_all(wired, monkeypatch):
    """A re-run after a no-op change must be nearly free rather than rewriting every
    heap tuple it touches."""
    correct = stored_row(src_country="US", src_asn=15169,
                         context_tags=db._derived_context(
                             stored_row())["context_tags"])
    conn = fake_pool(monkeypatch, _Conn([[correct], []]))
    out = db.backfill_geo()
    assert (out["scanned"], out["updated"], out["unchanged"]) == (1, 0, 1)
    assert conn.writes == []


def test_a_freshly_ingested_row_is_rewritten_by_neither_backfill(wired, monkeypatch):
    """The DB-free form of `test_integration_assets.py::test_a_second_backfill_writes_
    nothing`, and the property most at risk from this slice.

    A row written by `db._row` and then re-derived by either backfill must come out
    BYTE-IDENTICAL. If it did not, every backfill run would rewrite every heap tuple it
    touched and `unchanged` would be permanently zero — and the existing asset
    integration test would start failing for a reason that has nothing to do with
    assets. The row below is built from `_row`'s ACTUAL output rather than from
    hand-written expectations, so it cannot drift away from what ingest stores.
    """
    ingested = db._row(evt(host_name="srv-db-01", src_ip="8.8.8.8",
                           dst_ip="10.1.1.1"), 1)
    row = stored_row(**{k: ingested[k] for k in
                        (*db._ASSET_COLUMNS, *db._GEO_COLUMNS, "context_tags")})

    conn = fake_pool(monkeypatch, _Conn([[row], []]))
    out = db.backfill_geo()
    assert (out["updated"], out["unchanged"]) == (0, 1), conn.writes

    conn = fake_pool(monkeypatch, _Conn([[row], []]))
    out = db.backfill_assets()
    assert (out["updated"], out["unchanged"]) == (0, 1), conn.writes


def test_only_an_unbounded_completed_run_advances_the_stamp(wired, monkeypatch):
    """A bounded run has left rows underived; stamping it would answer "history is
    current" over a store that is half migrated."""
    conn = fake_pool(monkeypatch, _Conn([[stored_row()]]))
    out = db.backfill_geo(max_rows=1)
    assert out["done"] is False and out["full_pass"] is False
    assert not any(db._GEO_BACKFILL_STAMP == s for s, _ in conn.executed)

    conn = fake_pool(monkeypatch, _Conn([[stored_row()], []]))
    out = db.backfill_geo()
    assert out["done"] is True and out["full_pass"] is True
    stamps = [p for s, p in conn.executed if s == db._GEO_BACKFILL_STAMP]
    assert stamps == [{"hash": geo_index().fingerprint}]


def test_a_windowed_run_completes_but_still_must_not_stamp(wired, monkeypatch):
    """`done` and `full_pass` are two different facts and the stamp needs BOTH. A
    time-windowed run runs to completion — `done` is True — while leaving every row
    outside the window underived, so gating on `done` alone would claim history was
    current over a store that is mostly untouched."""
    conn = fake_pool(monkeypatch, _Conn([[stored_row()], []]))
    out = db.backfill_geo(since=_T)
    assert out["done"] is True and out["full_pass"] is False
    assert not [s for s, _ in conn.executed if s == db._GEO_BACKFILL_STAMP]

    conn = fake_pool(monkeypatch, _Conn([[], []]))
    assert db.backfill_geo(start_id=5)["full_pass"] is False
    assert not [s for s, _ in conn.executed if s == db._GEO_BACKFILL_STAMP]


# ══════════════════════════════════════════════════════════════════════════════
#  The stamp and the staleness answer
# ══════════════════════════════════════════════════════════════════════════════
def test_a_fresh_install_seeds_the_stamp_so_it_is_not_born_degraded(wired, monkeypatch):
    """Geo has no "nothing declared, nothing owed" state — scope labels derive with no
    data file — so without this seed `backfill_due` would read TRUE on every fresh
    install forever. A permanently degraded /health that means nothing is the fastest
    way to teach an operator to ignore the field."""
    conn = fake_pool(monkeypatch, _Conn([[{"present": False}]]))   # `events` is empty
    db.stamp_geo_sources()
    params = [p for s, p in conn.executed if s == db._GEO_STAMP_UPSERT][0]
    assert params["seed"] is True
    assert params["hash"] == geo_index().fingerprint


def test_an_upgraded_store_is_not_seeded_because_its_history_predates_the_columns(
        wired, monkeypatch):
    conn = fake_pool(monkeypatch, _Conn([[{"present": True}]]))    # rows already stored
    db.stamp_geo_sources()
    params = [p for s, p in conn.executed if s == db._GEO_STAMP_UPSERT][0]
    assert params["seed"] is False


def test_the_stamp_probe_degrades_towards_reporting_a_backfill_as_owed(
        wired, monkeypatch):
    """The safe direction: a spurious "backfill owed" costs one cheap no-op run, while
    the other way round would mark unmigrated history as current with nothing left to
    notice it by."""
    class _Broken(_Conn):
        def execute(self, sql, params=None):
            if sql.lstrip().upper().startswith("SELECT"):
                raise RuntimeError("no such table")
            return super().execute(sql, params)

    conn = fake_pool(monkeypatch, _Broken([]))
    db.stamp_geo_sources()
    params = [p for s, p in conn.executed if s == db._GEO_STAMP_UPSERT][0]
    assert params["seed"] is False


def test_the_record_half_of_the_stamp_never_touches_the_backfill_half():
    """The configured sources may legitimately move ahead of the rows derived under
    them. `ON CONFLICT DO UPDATE` claiming otherwise would report a side-loaded database
    as applied to history it has not reached."""
    on_conflict = db._GEO_STAMP_UPSERT.split("DO UPDATE SET", 1)[1]
    assert "backfill_hash" not in on_conflict
    assert "backfilled_at" not in on_conflict


def test_staleness_is_measured_against_the_live_fingerprint_not_the_stored_one(
        wired, monkeypatch):
    """`geo_hash` is refreshed only on load, so a stored-vs-stored comparison would
    answer "history is current" for exactly as long as a side-loaded file had been
    ignored. `asset_status` and `cim_status` document the identical trap."""
    live = geo_index().fingerprint
    # The stored record half still names the OLD sources; only `backfill_hash` matters.
    row = {"geo_hash": "stale-record", "backfill_hash": "derived-under-something-else",
           "applied_at": _T, "backfilled_at": _T}
    fake_pool(monkeypatch, _Conn([[row]]))
    out = db.geo_status()
    assert out["geo_hash"] == live          # recomputed now, not read from the row
    assert out["backfill_due"] is True

    row = {**row, "backfill_hash": live}
    fake_pool(monkeypatch, _Conn([[row]]))
    assert db.geo_status()["backfill_due"] is False


def test_a_never_stamped_store_reports_a_backfill_as_owed(wired, monkeypatch):
    """NULL `backfill_hash` with no seed means rows exist that predate these columns."""
    fake_pool(monkeypatch, _Conn([[{"geo_hash": None, "backfill_hash": None,
                                    "applied_at": None, "backfilled_at": None}]]))
    assert db.geo_status()["backfill_due"] is True


def test_geo_status_has_no_nothing_declared_guard(wired, monkeypatch):
    """`asset_status` suppresses `backfill_due` when nothing is declared, because an
    empty registry really does derive nothing. An empty GEO index still derives scope
    labels, so copying that guard would silence the notice on exactly the install whose
    stored rows have no labels at all."""
    geo.set_index(geo.EMPTY_INDEX)             # the fixture restores it
    fake_pool(monkeypatch, _Conn([[{"geo_hash": None, "backfill_hash": None,
                                    "applied_at": None, "backfilled_at": None}]]))
    out = db.geo_status()
    assert out["source_count"] == 0 and out["mode"] == "scope-only"
    assert out["backfill_due"] is True


def test_the_status_block_does_not_clobber_the_per_source_diagnostics(wired,
                                                                     monkeypatch):
    """FOUND BY MEASURING THE ENDPOINT, not by review.

    /health and /api/v1/geo/status both publish `{**geo.stats(), **db.geo_status()}`.
    `geo.stats()['sources']` is the LIST of per-source descriptions — the configured
    string and the absolute path each one resolved to — which is the entire diagnosis
    for a relative path that resolved against the wrong working directory. `geo_status`
    originally returned an INT under that same key, so the merge replaced the list with
    a count and took the diagnosis with it. Nothing failed; the field was simply gone.
    """
    fake_pool(monkeypatch, _Conn([[{"geo_hash": None, "backfill_hash": None,
                                    "applied_at": None, "backfilled_at": None}]]))
    merged = {**geo.stats(), **db.geo_status()}
    assert isinstance(merged["sources"], list)
    assert merged["source_count"] == 1
    # Any other key present in both must carry the SAME value, or the merge is lossy.
    for key in set(geo.stats()) & set(db.geo_status()):
        assert geo.stats()[key] == db.geo_status()[key], key


def test_the_backfill_pins_one_index_for_the_whole_run(wired, monkeypatch):
    """A reload halfway through would make the first half of a run disagree with the
    second, and the stamp written at the end would name a fingerprint describing
    neither. Measured by counting how often the cached index is consulted."""
    calls = []

    def counted():
        calls.append(1)
        return geo_index()

    monkeypatch.setattr(geo, "get_index", counted)
    fake_pool(monkeypatch, _Conn([[stored_row(id=1)], [stored_row(id=2)], []]))
    db.backfill_geo(chunk=1)
    assert calls == [1], f"the geo index was resolved {len(calls)} times, not pinned"


# ══════════════════════════════════════════════════════════════════════════════
#  The API surface
# ══════════════════════════════════════════════════════════════════════════════
def test_the_geo_api_surface_is_read_only():
    """An `api_keys` row carries no role and `require_api_key` accepts any enabled key,
    so a write endpoint here would let a key issued to a log forwarder repoint the geo
    database the whole store is enriched from — and /api/ is exempt from the console
    session auth, so RBAC could not reach it."""
    import app.main as main

    routes = {p: set(m) for p, m in main.app.openapi()["paths"].items()
              if p.startswith("/api/v1/geo")}
    assert routes, "no /api/v1/geo routes are mounted"
    for path, methods in routes.items():
        assert methods == {"get"}, (path, methods)


def test_the_lookup_endpoint_runs_the_real_resolver(wired):
    """Not a re-implementation: an endpoint that computed the answer its own way could
    drift from what ingest stores, and finding out what was stored is the entire reason
    for asking."""
    import asyncio

    from app import api

    out = asyncio.run(api.api_geo_lookup(ip="8.8.8.8", dst_ip="10.9.9.9", key={}))
    assert out["src_country"] == "US" and out["src_asn"] == 15169
    assert out["context_tags"] == ["dst:private", "src:public"]
    # It is the SAME answer `db._row` would bind for the same event.
    row = db._row(evt(src_ip="8.8.8.8", dst_ip="10.9.9.9"), 1)
    assert (out["src_country"], out["src_asn"]) == (row["src_country"], row["src_asn"])
    assert out["context_tags"] == row["context_tags"]


def test_the_lookup_endpoint_reports_the_address_it_actually_used(wired):
    """`normalized` is usually the answer when a result looks wrong: psycopg hands the
    backfill an `IPv4Interface` for an `inet` column carrying a prefix, and dual-stack
    servers log IPv4-mapped IPv6 constantly. Both are folded before the lookup."""
    import asyncio

    from app import api

    out = asyncio.run(api.api_geo_lookup(ip="::ffff:8.8.8.8", key={}))
    assert out["normalized"]["src_ip"] == "8.8.8.8"
    assert out["src_country"] == "US"          # ...and it therefore still resolves
    assert out["normalized"]["dst_ip"] is None


# ══════════════════════════════════════════════════════════════════════════════
#  schema.sql
# ══════════════════════════════════════════════════════════════════════════════
SCHEMA_RAW = (REPO_ROOT / "schema.sql").read_text(encoding="utf-8")

#: schema.sql with every `--` comment stripped.
#:
#: MUTATION TESTING FORCED THIS. The first version of these tests matched against the
#: raw file, and commenting a whole `ALTER TABLE ... dst_country` line OUT left every
#: one of them passing: `re.search` does not care that its match sits behind a `--`, and
#: `split_statements` folds a commented-out statement into the following chunk (the `;`
#: inside a comment is correctly not a terminator), so even the per-statement check
#: found the text. A test that passes with the column absent from the schema is worse
#: than no test at all.
SCHEMA = re.sub(r"--[^\n]*", "", SCHEMA_RAW)


def test_the_four_geo_columns_are_post_hoc_alters_with_no_default():
    """No DEFAULT keeps each ADD catalog-only, so it recurses into every existing
    partition without rewriting three years of them, and a fresh database converges on
    the same column list as an upgraded one."""
    for col in db._GEO_COLUMNS:
        m = re.search(rf"ALTER TABLE events ADD COLUMN IF NOT EXISTS {col}\s+(\w+);",
                      SCHEMA)
        assert m, f"{col} is not a post-hoc ALTER on events"
        assert "DEFAULT" not in m.group(0)


def test_the_asn_columns_are_bigint_because_an_as_number_is_unsigned_32_bit():
    """MEASURED, not stylistic: RFC 6996 reserves 4200000000-4294967294 for private use
    and `geo.norm_asn` accepts those values, while int4 stops at 2147483647. An
    `integer` column would raise numeric_value_out_of_range from inside `executemany`,
    costing the whole insert chunk rather than the one row."""
    assert geo.norm_asn(4200000000) == 4200000000 > 2 ** 31 - 1
    for col in ("src_asn", "dst_asn"):
        assert re.search(rf"ADD COLUMN IF NOT EXISTS {col}\s+bigint;", SCHEMA), col


def test_geo_meta_is_a_one_row_stamp_table_with_both_writers_columns():
    ddl = re.search(r"CREATE TABLE IF NOT EXISTS geo_meta \((.*?)\);", SCHEMA, re.S)
    assert ddl, "geo_meta is missing from schema.sql"
    body = ddl.group(1)
    assert "boolean" in body and "CHECK (id)" in body          # exactly one row
    for col in ("geo_hash", "source_count", "applied_at", "backfilled_at",
                "backfill_hash"):
        assert col in body, col


def test_geo_meta_is_swept_between_integration_tests():
    """`stamp_geo_sources` SEEDS the backfill stamp on the first stamp of a database
    whose `events` table is empty. A stale row left behind would skip that seed for the
    next test and hand it a `backfill_due` it never asked for — order-dependent
    flakiness rather than a loud failure."""
    conftest = (REPO_ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    tables = re.search(r"_TABLES = \((.*?)\)\n", conftest, re.S).group(1)
    assert '"geo_meta"' in tables


def test_the_geo_schema_survives_the_hand_rolled_statement_splitter():
    """`db.split_statements` is hand-rolled with documented gaps — no `$$` quoting, no
    `/* */` blocks, no `E'…'` strings — and it runs in the integration job only,
    historically the least trustworthy job in this repo. This asserts the geo section
    stays inside the subset it handles.

    MEASURED while mutation-testing, and it corrects the brief I was given: a `;` placed
    MID-LINE inside a `--` comment is handled correctly by this splitter (it tracks
    comment state and does not terminate on it). It is the naive `script.split(";")`
    that this function replaced which cuts such a comment in half. The real hazard here
    is different — a commented-out statement is folded into the FOLLOWING chunk, so a
    text search over the split output finds it as though it were live. Hence the
    comment-stripped `SCHEMA` above.
    """
    stmts = db.split_statements(SCHEMA_RAW)
    for col in db._GEO_COLUMNS:
        bodies = [re.sub(r"--[^\n]*", "", s) for s in stmts]
        hits = [b for b in bodies
                if re.search(rf"ADD COLUMN IF NOT EXISTS {col}\b", b)]
        assert len(hits) == 1, f"{col} did not split into exactly one statement"
    assert len([s for s in stmts if "CREATE TABLE IF NOT EXISTS geo_meta" in s]) == 1
    keyword = re.compile(r"^\s*(--|CREATE|ALTER|INSERT|DROP|COMMENT|SET|GRANT|UPDATE)",
                         re.I)
    assert [s for s in stmts if not keyword.match(s)] == []


# ══════════════════════════════════════════════════════════════════════════════
#  No new dependency
# ══════════════════════════════════════════════════════════════════════════════
def test_the_geo_slice_added_no_third_party_import():
    """The charter's hard line. `maxminddb` is not installed and never will be — the
    reader is written from the published format spec against the stdlib."""
    import ast
    import sys

    stdlib = set(sys.stdlib_module_names)
    allowed = stdlib | {"app", "psycopg", "psycopg_pool", "fastapi", "starlette",
                        "jinja2", "yaml", "dateutil", "multipart"}
    for path in (REPO_ROOT / "app" / "enrich").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                roots = [(node.module or "").split(".")[0]] if node.level == 0 else []
            else:
                continue
            for root in roots:
                assert not root or root in allowed, f"{path.name} imports {root!r}"
