# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Geo & network enrichment against a real PostgreSQL (Phase 3, slice 2).

EVERY ASSERTION RE-QUERIES THE DATABASE. Not one of them compares a function's own
return value to what that function said it did — that defect class has already bitten
this repo, because such a test passes with the write removed entirely. Where a return
value IS checked it is checked *in addition to* a read-back, never instead of one.

WHAT THIS FILE PROVES THAT `tests/test_geo_wiring.py` CANNOT. That file drives the real
backfill loops over a stub connection, so it proves the derivation, the merge and the
gating. It cannot prove any of the following, and all of them were unverified until this
file existed:

* the four `ALTER TABLE` columns actually apply, and recurse into every month partition;
* `src_asn`/`dst_asn` are wide enough for a real AS number — `bigint`, measured, not
  assumed (an RFC 6996 private-use ASN overflows int4 and would take a whole
  `executemany` chunk down, not one row);
* `_GEO_STAMP_UPSERT`'s ``CASE WHEN %(seed)s::boolean`` binds as intended. That cast was
  reasoned but never executed, and an untyped parameter in a CASE THEN position is where
  PostgreSQL type inference is weakest;
* `_GEO_UPDATE`'s partition-keyed `WHERE id = ... AND event_time = ...` finds its row
  when the store spans more than one partition;
* `geo_meta` creates at all;
* psycopg loads `inet` as an ipaddress OBJECT, so the backfill re-derives from a
  different Python type than ingest did — the failure that would report
  `scanned=N updated=0` and be indistinguishable from success.

THE MERGE IS THE HIGHEST-RISK THING IN THE SLICE and has its own section. `context_tags`
is one column with two producers; a lost label looks exactly like a row about an
undeclared host on an unclassified address, so nothing in the data would ever show it.
"""
from __future__ import annotations

import datetime as dt
import json
import re
from contextlib import contextmanager

import pytest

from app import assets, db
from app.enrich import geo
from app.models import NormalizedEvent

pytestmark = pytest.mark.integration

_T = dt.datetime(2026, 8, 4, 12, 0, tzinfo=dt.timezone.utc)
#: A second month, so the partition-keyed UPDATE has more than one partition to find a
#: row in. `events` is partitioned by `event_time`, so this is the only way to get one.
_T2 = dt.datetime(2026, 9, 4, 12, 0, tzinfo=dt.timezone.utc)

#: A real geo layer, built from literals. `10.1.2.50` is deliberately a PRIVATE address
#: with an answer: the resolver does not skip RFC 1918 space, precisely so an operator's
#: CSV mapping internal ranges to site countries works. It also carries an RFC 6996
#: private-use ASN, which is what proves the column is `bigint`.
_LITERALS = {"8.8.8.8": {"country": "US", "asn": 15169},
             "1.1.1.1": {"country": "AU", "asn": 13335},
             "10.1.2.50": {"country": "DE", "asn": 4200000000}}

#: Larger than int4's 2147483647. RFC 6996 reserves 4200000000-4294967294 for private
#: use, which is exactly what an enterprise's internal BGP uses and exactly what an
#: operator's side-loaded CSV maps.
_PRIVATE_USE_ASN = 4200000000


def _geo_index() -> geo.GeoIndex:
    return geo.GeoIndex([geo.literal_source(dict(_LITERALS))])


def _evt(n: int, when: dt.datetime = _T, **kw) -> NormalizedEvent:
    """An event with a DISTINCT dedup identity.

    `dedup_hash` is sha256(vendor + event_time + raw), so events differing only in
    `message` collapse into one row — the trap that has caught test authors in this
    repo before. `raw={"n": n}` is what actually makes them distinct.
    """
    return NormalizedEvent(event_time=when, vendor="geotest", raw={"n": n}, **kw)


def _store(events: list[NormalizedEvent]) -> int:
    batch = db.create_batch(None, None, "geotest", "generic_json", "test", None)
    with db.pool().connection() as conn:
        db.insert_events(conn, events, batch)
        conn.commit()
    return batch


def _rows() -> list[dict]:
    """Every stored test row, straight from Postgres. The only source of truth here."""
    with db.pool().connection() as conn:
        return conn.execute(
            "SELECT raw->>'n' AS n, src_ip, dst_ip, src_country, dst_country, "
            "src_asn, dst_asn, context_tags, asset_id, asset_criticality "
            "FROM events WHERE vendor = 'geotest' "
            "ORDER BY (raw->>'n')::int").fetchall()


def _geo_meta() -> dict | None:
    with db.pool().connection() as conn:
        return conn.execute("SELECT * FROM geo_meta WHERE id = true").fetchone()


@contextmanager
def _configured(**fields):
    """Force geo paths onto the FROZEN `Settings` singleton, then put them back.

    `settings` is a frozen dataclass built at import, so `monkeypatch.setattr` raises
    `FrozenInstanceError` — measured, not guessed. `object.__setattr__` is the same
    escape hatch `conftest.pg` already uses to force `db_dsn`, so this follows the
    established precedent rather than inventing a second mechanism.

    Restoration is in a `finally` because `settings` is a process-wide singleton: a test
    that left a path behind would silently reconfigure every later test in the session.
    """
    from app.config import settings
    previous = {k: getattr(settings, k) for k in fields}
    for k, v in fields.items():
        object.__setattr__(settings, k, v)
    try:
        yield settings
    finally:
        for k, v in previous.items():
            object.__setattr__(settings, k, v)
        geo.set_index(None)


def _xmin() -> list[int]:
    """The inserting transaction id of every test row.

    THE ONLY HONEST WAY TO PROVE "this backfill wrote nothing". Asserting on the
    `unchanged` counter the backfill itself returns is the defect class this repo has
    been bitten by — it passes with the skip logic removed and the UPDATE issued anyway,
    because the counter is computed from the same comparison that decides the write.
    `xmin` is Postgres's own record: an UPDATE writes a new heap tuple with a new xmin,
    so an unchanged value means no row version was written. There is nothing the test
    code can do to fake it.
    """
    with db.pool().connection() as conn:
        return [r["x"] for r in conn.execute(
            "SELECT xmin::text::bigint AS x FROM events WHERE vendor = 'geotest' "
            "ORDER BY (raw->>'n')::int").fetchall()]


@pytest.fixture
def loaded(clean_db):
    """A geo index installed through the REAL module cache, and the write counter reset.

    `geo.set_index` rather than monkeypatching `get_index`: `db._row` resolves from the
    cache on every call and `geo.stats()` reads that same cache directly, so patching
    only the accessor would leave the two reporting different indexes — a disagreement
    that cannot happen in production.

    Both module caches are globals shared with the rest of the session, so both are
    restored on the way out. A test that leaves one dirty makes an unrelated assertion
    elsewhere fail, which only ever shows up as a reordering flake.
    """
    geo.set_index(_geo_index())
    db.reset_geo_write_state()
    yield geo.get_index()
    geo.set_index(None)
    assets.set_index(None)
    db.reset_geo_write_state()


@pytest.fixture
def declared(loaded):
    """...plus a declared asset reachable by hostname AND by address.

    The address alias is `10.1.2.50`, which the geo layer above also answers for. That
    overlap is the point: the asset side contributes `dst:` labels for the same address
    the geo side labels `dst:private`, so the two producers' labels genuinely interleave
    in one array rather than occupying separate halves of it.
    """
    db.upsert_asset("srv-db-01", criticality="critical", category=["Server", "PCI"],
                    environment="prod", watchlist=["Crown-Jewel"],
                    aliases=[("hostname", "SRV-DB-01"), ("ip", "10.1.2.50")])
    index = assets.reload()
    db.stamp_asset_registry(index)
    return index


# ══════════════════════════════════════════════════════════════════════════════
#  The schema — the ALTERs, the partition recursion, and the column WIDTH
# ══════════════════════════════════════════════════════════════════════════════
def test_the_four_geo_columns_exist_and_the_asn_columns_are_bigint(clean_db):
    """`integer` was what the interface brief specified and it is WRONG — measured, not
    argued: a valid AS number does not fit. See `test_a_private_use_asn_round_trips`,
    which is the same fact from the other end.
    """
    with db.pool().connection() as conn:
        cols = conn.execute(
            "SELECT column_name, data_type FROM information_schema.columns "
            "WHERE table_name = 'events' AND column_name IN "
            "('src_country','dst_country','src_asn','dst_asn') "
            "ORDER BY column_name").fetchall()
    got = {c["column_name"]: c["data_type"] for c in cols}
    assert got == {"src_country": "text", "dst_country": "text",
                   "src_asn": "bigint", "dst_asn": "bigint"}


def test_the_columns_recurse_into_every_month_partition(loaded):
    """`ADD COLUMN` with no DEFAULT is catalog-only and recurses into existing children;
    a partition created afterwards inherits from the parent. Both paths matter on an
    upgrade, so both are exercised — the store below spans two months.
    """
    _store([_evt(1, src_ip="8.8.8.8"), _evt(2, _T2, src_ip="1.1.1.1")])
    with db.pool().connection() as conn:
        parts = conn.execute(
            "SELECT c.relname AS name FROM pg_inherits i "
            "JOIN pg_class c ON c.oid = i.inhrelid "
            "WHERE i.inhparent = 'events'::regclass ORDER BY c.relname").fetchall()
        names = [p["name"] for p in parts]
        missing = conn.execute(
            "SELECT c.relname AS name FROM pg_inherits i "
            "JOIN pg_class c ON c.oid = i.inhrelid "
            "WHERE i.inhparent = 'events'::regclass AND NOT EXISTS ("
            "  SELECT 1 FROM information_schema.columns col "
            "  WHERE col.table_name = c.relname AND col.column_name = 'src_country')"
        ).fetchall()
    assert len(names) >= 2, names          # two months really did produce two children
    assert [m["name"] for m in missing] == []


def test_a_private_use_asn_round_trips_through_the_column(loaded):
    """4200000000 > int4's 2147483647. On an `integer` column this raises
    numeric_value_out_of_range from inside `executemany`, taking the WHOLE insert chunk
    down rather than the one offending row — the same failure class the `to_port` /
    `to_int` clamps in `db._row` exist to prevent.

    Read back out of the database rather than off the resolver, because the resolver
    returning the right int is not the fact in question here; the COLUMN accepting it is.
    """
    _store([_evt(1, dst_ip="10.1.2.50")])
    (row,) = _rows()
    assert row["dst_asn"] == _PRIVATE_USE_ASN
    assert row["dst_country"] == "DE"


# ══════════════════════════════════════════════════════════════════════════════
#  Ingest-time stamping
# ══════════════════════════════════════════════════════════════════════════════
def test_a_stored_event_carries_country_asn_and_scope_labels(loaded):
    _store([_evt(1, src_ip="8.8.8.8", dst_ip="10.1.2.50")])
    (row,) = _rows()
    assert (row["src_country"], row["src_asn"]) == ("US", 15169)
    assert (row["dst_country"], row["dst_asn"]) == ("DE", _PRIVATE_USE_ASN)
    assert row["context_tags"] == ["dst:private", "src:public"]


def test_scope_labels_are_stamped_with_no_database_loaded_at_all(clean_db):
    """The feature, not an edge case. Scope classification is arithmetic over the
    address, so the layer every install gets must work with an EMPTY index — and
    `resolve` must not short-circuit on `index.is_empty()` the way the asset resolver
    legitimately does. An install that never side-loads a database is almost all of
    them.
    """
    geo.set_index(geo.EMPTY_INDEX)
    try:
        _store([_evt(1, src_ip="8.8.8.8", dst_ip="10.1.2.50")])
        (row,) = _rows()
        assert row["context_tags"] == ["dst:private", "src:public"]
        assert row["src_country"] is None and row["src_asn"] is None
    finally:
        geo.set_index(None)


def test_an_event_with_no_addresses_stores_NULL_not_an_empty_array(loaded):
    """NULL keeps the GIN index proportional to rows that actually carry context — the
    rule `cim_models` follows."""
    _store([_evt(1, host_name="no-addresses-here")])
    (row,) = _rows()
    assert row["context_tags"] is None
    assert row["src_country"] is None and row["dst_country"] is None
    assert row["src_asn"] is None and row["dst_asn"] is None


def test_an_unresolvable_address_still_gets_its_scope_label(loaded):
    """The two layers are independent: an address no loaded database answers for still
    carries the label that says what KIND of address it is."""
    _store([_evt(1, src_ip="203.0.113.7")])       # RFC 5737 documentation space
    (row,) = _rows()
    assert row["src_country"] is None and row["src_asn"] is None
    assert row["context_tags"] == ["src:documentation"]


def test_scope_labels_are_answered_by_the_existing_gin_index(loaded):
    """The scope half of this slice is queryable the day it ships, at zero index cost,
    because the labels land in the already-indexed `context_tags`. That is the stated
    reason schema.sql adds NO new index for the four columns, so it is worth pinning
    that the containment predicate actually resolves.
    """
    _store([_evt(1, src_ip="8.8.8.8"), _evt(2, src_ip="10.1.2.50")])
    with db.pool().connection() as conn:
        hit = conn.execute(
            "SELECT raw->>'n' AS n FROM events WHERE vendor = 'geotest' "
            "AND context_tags @> ARRAY['src:public']::text[]").fetchall()
    assert [h["n"] for h in hit] == ["1"]


# ══════════════════════════════════════════════════════════════════════════════
#  THE MERGE — one column, two producers. The highest-risk thing in the slice.
# ══════════════════════════════════════════════════════════════════════════════
#: Measured from a real derivation, not hand-reasoned. `dst:private` (geo) sits IN AMONG
#: the `dst:` labels the asset registry contributes for the same address, which is the
#: concrete demonstration that label ownership is not recoverable from the text — and
#: therefore why both backfills re-derive both sides instead of stripping their own.
_MERGED = ["dst:crown-jewel", "dst:pci", "dst:private", "dst:prod", "dst:server",
           "host:crown-jewel", "host:pci", "host:prod", "host:server", "src:public"]

_ASSET_LABELS = [t for t in _MERGED if t not in ("dst:private", "src:public")]
_GEO_LABELS = ["dst:private", "src:public"]


def _merge_fields() -> dict:
    return dict(host_name="SRV-DB-01", src_ip="8.8.8.8", dst_ip="10.1.2.50")


def test_a_freshly_ingested_row_carries_BOTH_label_sets(declared):
    """Ingest-time merge, read back out of the column."""
    _store([_evt(1, **_merge_fields())])
    (row,) = _rows()
    assert row["context_tags"] == _MERGED
    assert set(_ASSET_LABELS) <= set(row["context_tags"])
    assert set(_GEO_LABELS) <= set(row["context_tags"])
    # ...and neither subsystem's SCALAR columns were lost to the other's write.
    assert row["asset_id"] == "srv-db-01" and row["asset_criticality"] == "critical"
    assert (row["src_country"], row["dst_asn"]) == ("US", _PRIVATE_USE_ASN)


def test_the_geo_backfill_does_not_strip_the_asset_labels(declared):
    """`_GEO_UPDATE` sets `context_tags` unconditionally, so `backfill_geo` must
    re-derive the ASSET side and merge, or it would delete every business-context label
    from every row it corrected — invisibly."""
    geo.set_index(geo.EMPTY_INDEX)              # stored with scope labels but no country
    _store([_evt(1, **_merge_fields())])
    before = _rows()[0]
    assert before["src_country"] is None
    assert set(_ASSET_LABELS) <= set(before["context_tags"])

    geo.set_index(_geo_index())                 # ...now a database is side-loaded
    db.backfill_geo()

    (row,) = _rows()                            # READ BACK, not the return value
    assert row["context_tags"] == _MERGED
    assert set(_ASSET_LABELS) <= set(row["context_tags"])
    assert row["src_country"] == "US"
    assert row["asset_id"] == "srv-db-01"       # the registry scalars were not touched


def test_the_asset_backfill_does_not_strip_the_geo_labels(loaded):
    """The mirror image, and THE hazard this slice was warned about. `_ASSET_UPDATE`
    also sets `context_tags` unconditionally; deriving that array from asset labels
    alone would delete every `src:public` / `dst:private` from every row the asset
    backfill touched — and would then see a difference on all of them, turning a no-op
    run into a full-table rewrite."""
    assets.set_index(assets.EMPTY_INDEX)        # nothing declared at ingest time
    _store([_evt(1, **_merge_fields())])
    before = _rows()[0]
    assert before["asset_id"] is None
    assert set(_GEO_LABELS) <= set(before["context_tags"])

    db.upsert_asset("srv-db-01", criticality="critical",
                    category=["Server", "PCI"], environment="prod",
                    watchlist=["Crown-Jewel"],
                    aliases=[("hostname", "SRV-DB-01"), ("ip", "10.1.2.50")])
    index = assets.reload()
    db.backfill_assets(index=index)

    (row,) = _rows()
    assert row["context_tags"] == _MERGED
    assert set(_GEO_LABELS) <= set(row["context_tags"])
    assert row["asset_id"] == "srv-db-01"
    # It writes no geo SCALAR — those belong to `backfill_geo`, and they were already
    # stamped at ingest, so they must survive untouched.
    assert (row["src_country"], row["src_asn"]) == ("US", 15169)


def test_the_two_backfills_converge_in_either_order(declared):
    """Both derive the array through `_derived_context`, so running them in either order
    must reach the same stored array. If they disagreed each run would undo the other
    and neither would ever report `unchanged`."""
    geo.set_index(geo.EMPTY_INDEX)
    assets.set_index(assets.EMPTY_INDEX)
    _store([_evt(1, **_merge_fields()), _evt(2, _T2, **_merge_fields())])

    geo.set_index(_geo_index())
    assets.set_index(declared)

    db.backfill_geo()
    db.backfill_assets()
    geo_then_assets = [r["context_tags"] for r in _rows()]

    db.backfill_assets()
    db.backfill_geo()
    assets_then_geo = [r["context_tags"] for r in _rows()]

    assert geo_then_assets == assets_then_geo == [_MERGED, _MERGED]


def test_neither_backfill_rewrites_a_freshly_ingested_row(declared):
    """The property the whole design rests on, and the one the existing asset
    integration suite would have started failing on if this slice got it wrong: a row
    written by `db._row` must be re-derived BYTE-IDENTICALLY by both backfills, or every
    run rewrites every heap tuple it touches and `unchanged` is permanently zero."""
    _store([_evt(1, **_merge_fields()), _evt(2, src_ip="1.1.1.1")])
    before = _xmin()

    db.backfill_geo()
    db.backfill_assets()

    # Postgres's own record that no heap tuple was written — not the counter the
    # backfill computed for itself. See `_xmin`.
    assert _xmin() == before
    assert [r["context_tags"] for r in _rows()] == [_MERGED, ["src:public"]]


# ══════════════════════════════════════════════════════════════════════════════
#  backfill_geo — the history correction
# ══════════════════════════════════════════════════════════════════════════════
def test_backfill_corrects_rows_ingested_before_a_database_was_side_loaded(loaded):
    geo.set_index(geo.EMPTY_INDEX)
    _store([_evt(1, src_ip="8.8.8.8"), _evt(2, dst_ip="10.1.2.50")])
    assert all(r["src_country"] is None and r["dst_country"] is None for r in _rows())

    geo.set_index(_geo_index())
    db.backfill_geo()

    rows = _rows()                              # read back, not from the return value
    assert (rows[0]["src_country"], rows[0]["src_asn"]) == ("US", 15169)
    assert (rows[1]["dst_country"], rows[1]["dst_asn"]) == ("DE", _PRIVATE_USE_ASN)


def test_the_backfill_re_derives_from_a_psycopg_inet_object(loaded):
    """psycopg loads an `inet` column as an ipaddress OBJECT, not a string, so the
    backfill feeds `geo.resolve` a different Python type than ingest did. Without the
    `str()` in `geo._ip_text` this resolves NOTHING while reporting
    `scanned=N updated=0` — indistinguishable from "already correct".

    The IPv4-MAPPED form is in here for the same reason from the other side: Postgres
    stores `::ffff:8.8.8.8` in an `inet` and hands it back as an IPv6Address, which only
    resolves if `_ip_text` unwraps it. Both rows are stored with an EMPTY index so
    `updated` cannot be satisfied by the ingest stamp.
    """
    geo.set_index(geo.EMPTY_INDEX)
    _store([_evt(1, src_ip="8.8.8.8"), _evt(2, src_ip="::ffff:8.8.8.8")])
    with db.pool().connection() as conn:
        raw = conn.execute("SELECT src_ip FROM events WHERE vendor='geotest' "
                           "ORDER BY (raw->>'n')::int").fetchall()
    # The premise, measured rather than assumed: these are objects, not strings.
    assert not any(isinstance(r["src_ip"], str) for r in raw)

    geo.set_index(_geo_index())
    db.backfill_geo()

    rows = _rows()
    assert [r["src_country"] for r in rows] == ["US", "US"]
    assert [r["src_asn"] for r in rows] == [15169, 15169]


def test_the_update_reaches_rows_in_every_partition(loaded):
    """A store spanning two months is the only way to prove the UPDATE lands in both.

    NOTE WHAT THIS DOES *NOT* PROVE, because the first version of this test claimed it
    and was wrong. Removing `event_time` from `_GEO_UPDATE`'s predicate leaves this test
    GREEN — measured with the mutant, not assumed. `id` comes from one identity sequence
    on the partitioned parent, so it is globally unique and `WHERE id = ...` alone still
    finds exactly the right row. The partition key buys PRUNING, not correctness, and
    that is a separate fact with its own test below.
    """
    geo.set_index(geo.EMPTY_INDEX)
    _store([_evt(1, _T, src_ip="8.8.8.8"), _evt(2, _T2, src_ip="1.1.1.1"),
            _evt(3, _T2, src_ip="10.1.2.50")])
    geo.set_index(_geo_index())

    db.backfill_geo()

    rows = _rows()
    assert [r["src_country"] for r in rows] == ["US", "AU", "DE"]
    # ...and the rows really are in different partitions, or the test proved nothing.
    with db.pool().connection() as conn:
        spread = conn.execute(
            "SELECT count(DISTINCT tableoid) AS n FROM events "
            "WHERE vendor = 'geotest'").fetchone()
    assert spread["n"] == 2


def test_the_partition_key_in_the_predicate_actually_prunes(loaded):
    """WHY `_GEO_UPDATE` carries `AND event_time = ...` at all.

    Correctness does not need it (see the test above). Pruning does: without the
    partition key the planner has no way to know which child holds the row, so the
    UPDATE is planned against EVERY partition — on a three-year store that is 36 of
    them per row, and the backfill issues one such statement per changed row through
    `executemany`.

    MEASURED, on the real statement text rather than a copy of it, so a future edit to
    `_GEO_UPDATE` is what this reads. EXPLAIN without ANALYZE does not execute the
    statement, so nothing is written here.

    The assertion is deliberately RELATIVE as well as absolute — "the key names strictly
    fewer partitions than its absence does" holds across planner versions, where an
    exact plan-shape assertion is the kind of thing that passes on one machine and fails
    on CI.
    """
    _store([_evt(n, dt.datetime(2026, m, 4, 12, 0, tzinfo=dt.timezone.utc),
                 src_ip="8.8.8.8")
            for n, m in enumerate((1, 2, 3, 4, 5, 6), start=1)])

    # `events_default` is matched as well as the month children. It is created by
    # schema.sql and is NOT swept by `clean_db` (whose regex is `^events_[0-9]{6}$`), so
    # a pattern that missed it would count six children while the planner saw seven —
    # the test would then compare two differently-defined sets and still look green.
    # This expectation was wrong on the first run; the code was right.
    part_re = re.compile(r"events_(?:\d{6}|default)")

    def _partitions(sql: str, params: dict) -> set[str]:
        with db.pool().connection() as conn:
            plan = conn.execute(f"EXPLAIN (FORMAT JSON) {sql}", params).fetchone()
            conn.rollback()                 # EXPLAIN takes locks; hold none of them
        return set(part_re.findall(json.dumps(list(plan.values())[0])))

    with db.pool().connection() as conn:
        target = conn.execute("SELECT id, event_time FROM events "
                              "WHERE vendor = 'geotest' ORDER BY id LIMIT 1").fetchone()
        children = conn.execute(
            "SELECT c.relname AS name FROM pg_inherits i "
            "JOIN pg_class c ON c.oid = i.inhrelid "
            "WHERE i.inhparent = 'events'::regclass").fetchall()
    total = len({c["name"] for c in children if part_re.fullmatch(c["name"])})
    assert total == 7, [c["name"] for c in children]   # six months + events_default

    params = {"id": target["id"], "event_time": target["event_time"],
              "src_country": None, "dst_country": None, "src_asn": None,
              "dst_asn": None, "context_tags": None}
    pruned = _partitions(db._GEO_UPDATE, params)
    unpruned = _partitions(db._GEO_UPDATE.replace(
        " AND event_time = %(event_time)s", ""), params)

    assert len(pruned) == 1, pruned          # exactly the child that holds the row
    assert len(pruned) < len(unpruned), (pruned, unpruned)
    assert len(unpruned) == total            # ...and the alternative is all of them


def test_a_backfilled_row_is_identical_to_one_ingested_live(loaded):
    """The backfill re-derives through the SAME `geo.resolve` as ingest precisely so a
    corrected row cannot differ from an identically-shaped fresh one."""
    fields = dict(src_ip="8.8.8.8", dst_ip="10.1.2.50")

    geo.set_index(geo.EMPTY_INDEX)
    _store([_evt(1, **fields)])                 # row 1: stored with no country
    geo.set_index(_geo_index())
    _store([_evt(2, **fields)])                 # row 2: stored WITH country

    db.backfill_geo()                           # row 1 corrected

    stale, live = _rows()
    compared = ("src_country", "dst_country", "src_asn", "dst_asn", "context_tags")
    assert {k: stale[k] for k in compared} == {k: live[k] for k in compared}
    assert stale["src_country"] == "US"         # ...and not both empty


def test_a_second_backfill_writes_nothing(loaded):
    """A re-run after a no-op edit must be nearly free rather than rewriting every heap
    tuple it touches. Proven with `xmin` as well as the counter, because the counter is
    derived from the same comparison that decides the write and would agree with itself
    even if the UPDATE were issued unconditionally."""
    geo.set_index(geo.EMPTY_INDEX)
    _store([_evt(1, src_ip="8.8.8.8"), _evt(2, dst_ip="10.1.2.50")])
    geo.set_index(_geo_index())

    first = db.backfill_geo()
    corrected = _xmin()
    assert first["updated"] == 2
    assert [r["src_country"] for r in _rows()] == ["US", None]

    again = db.backfill_geo()
    assert (again["scanned"], again["updated"], again["unchanged"]) == (2, 0, 2)
    assert _xmin() == corrected             # no new row version, per Postgres itself


def test_backfill_is_resumable_from_its_reported_cursor(loaded):
    geo.set_index(geo.EMPTY_INDEX)
    _store([_evt(n, src_ip="8.8.8.8") for n in range(1, 6)])
    geo.set_index(_geo_index())

    first = db.backfill_geo(max_rows=2)
    assert first["done"] is False               # stopped on the bound, not on the data
    assert [r["src_country"] for r in _rows()] == ["US", "US", None, None, None]

    rest = db.backfill_geo(start_id=first["last_id"])
    assert rest["scanned"] == 3
    assert [r["src_country"] for r in _rows()] == ["US"] * 5


def test_a_time_windowed_backfill_touches_only_its_window(loaded):
    geo.set_index(geo.EMPTY_INDEX)
    _store([_evt(1, _T, src_ip="8.8.8.8"), _evt(2, _T2, src_ip="8.8.8.8")])
    geo.set_index(_geo_index())

    db.backfill_geo(since=_T2)

    assert [r["src_country"] for r in _rows()] == [None, "US"]


# ══════════════════════════════════════════════════════════════════════════════
#  The stamp, the seed, and the staleness answer
# ══════════════════════════════════════════════════════════════════════════════
def test_the_stamp_upsert_executes_and_seeds_on_an_empty_store(loaded):
    """THE statement that had never been executed anywhere. `_GEO_STAMP_UPSERT` puts a
    bind parameter in a `CASE WHEN ... THEN` position, which is where PostgreSQL type
    inference is weakest — the explicit `::boolean` / `::text` casts were reasoned, not
    measured, and a type error there would have taken startup's geo stamp down on every
    deployment.

    The SEED is the behaviour: geo has no "nothing declared, nothing owed" state, so
    without it `backfill_due` reads TRUE on every fresh install forever, and a
    permanently degraded /health is the fastest way to teach an operator to ignore the
    field.
    """
    idx = geo.get_index()
    returned = db.stamp_geo_sources(idx)

    row = _geo_meta()                           # read back, not the return value
    assert row is not None, "geo_meta was not written at all"
    assert row["geo_hash"] == idx.fingerprint == returned
    assert row["source_count"] == 1
    assert row["applied_at"] is not None
    # the seed: an empty `events` has no history to correct
    assert row["backfill_hash"] == idx.fingerprint
    assert row["backfilled_at"] is not None
    assert db.geo_status()["backfill_due"] is False


def test_an_upgraded_store_is_not_seeded_because_its_history_predates_the_columns(
        loaded):
    """The other arm of the same CASE, and the reason the seed is safe: rows already in
    the store genuinely predate these columns, so /health must tell the operator a
    backfill is owed."""
    _store([_evt(1, src_ip="8.8.8.8")])         # history exists
    db.stamp_geo_sources()

    row = _geo_meta()
    assert row["geo_hash"] == geo.get_index().fingerprint
    assert row["backfill_hash"] is None         # NOT seeded
    assert row["backfilled_at"] is None
    assert db.geo_status()["backfill_due"] is True


def test_a_re_stamp_never_touches_the_backfill_half(loaded):
    """The configured sources may legitimately move ahead of the rows derived under
    them. An `ON CONFLICT` branch that also refreshed `backfill_hash` would report a
    newly side-loaded database as already applied to history it has not reached."""
    db.stamp_geo_sources()                      # seeds on the empty store
    seeded = _geo_meta()["backfill_hash"]
    assert seeded is not None

    _store([_evt(1, src_ip="8.8.8.8")])
    other = geo.GeoIndex([geo.literal_source({"9.9.9.9": {"country": "CH"}})])
    assert other.fingerprint != seeded
    db.stamp_geo_sources(other)                 # the UPDATE branch

    row = _geo_meta()
    assert row["geo_hash"] == other.fingerprint   # the record half moved...
    assert row["backfill_hash"] == seeded         # ...the backfill half did not


def test_a_side_load_makes_a_backfill_owed_and_the_backfill_clears_it(loaded):
    """`backfill_due` is measured against the sources AS THEY ARE NOW, not against the
    stored `geo_hash` — which is refreshed only on load and would answer "history is
    current" for exactly as long as a side-loaded file had been ignored."""
    db.stamp_geo_sources()                      # fresh install, seeded
    _store([_evt(1, src_ip="8.8.8.8")])
    assert db.geo_status()["backfill_due"] is False

    other = geo.GeoIndex([geo.literal_source({"8.8.8.8": {"country": "US", "asn": 1}},
                                             name="edited")])
    geo.set_index(other)
    db.stamp_geo_sources(other)
    assert db.geo_status()["backfill_due"] is True

    db.backfill_geo(index=other)
    assert db.geo_status()["backfill_due"] is False
    (row,) = _rows()
    assert row["src_asn"] == 1                  # the new answer really did land


def test_a_bounded_run_does_not_claim_history_is_current(loaded):
    """Only an unbounded, completed pass may advance the stamp — otherwise a partial run
    reports the sources as fully applied to rows it never reached."""
    _store([_evt(1, src_ip="8.8.8.8")])
    db.stamp_geo_sources()                      # not seeded: history exists
    assert _geo_meta()["backfill_hash"] is None

    db.backfill_geo(max_rows=1)
    assert _geo_meta()["backfill_hash"] is None
    db.backfill_geo(since=_T)                   # completes, but is windowed
    assert _geo_meta()["backfill_hash"] is None

    db.backfill_geo()                           # unbounded and complete
    assert _geo_meta()["backfill_hash"] == geo.get_index().fingerprint


def test_a_backfill_with_no_stamp_row_warns_rather_than_failing(loaded):
    """`_GEO_BACKFILL_STAMP` is an UPDATE, so on an unstamped database it matches zero
    rows. That must be a logged warning and not an exception: an operator who ran the
    backfill before the app ever started would otherwise see the whole (successful) run
    report as failed."""
    _store([_evt(1, src_ip="8.8.8.8")])
    assert _geo_meta() is None                  # clean_db truncated geo_meta

    out = db.backfill_geo()                     # must not raise

    assert out["done"] is True and out["full_pass"] is True
    assert _geo_meta() is None                  # ...and nothing was invented
    (row,) = _rows()
    assert row["src_country"] == "US"           # the row work still happened


def test_geo_status_reports_the_live_sources_and_the_stored_stamp(loaded):
    """The /health answer, read against a real `geo_meta`. `source_count` — NOT
    `sources` — because /health and /api/v1/geo/status both publish
    `{**geo.stats(), **db.geo_status()}`, and `stats()['sources']` is the LIST of
    per-source descriptions that is the entire diagnosis for a path resolved against the
    wrong working directory. A key collision would replace it with an integer.
    """
    db.stamp_geo_sources()
    status = db.geo_status()
    row = _geo_meta()

    assert status["source_count"] == 1
    assert status["mode"] == "scope+country/asn"
    assert status["geo_hash"] == row["geo_hash"]
    assert status["backfill_hash"] == row["backfill_hash"]
    assert status["applied_at"] == row["applied_at"]

    merged = {**geo.stats(), **status}
    assert isinstance(merged["sources"], list)  # not clobbered by an int
    assert merged["source_count"] == 1


def test_health_reports_the_geo_block_against_a_real_database(loaded):
    """`_geo_health` opens a connection, so this is the only place its real shape can be
    checked. It must never raise — /health has to answer even when the database will
    not — and it must resolve the status BEFORE `stats()`, or a process that has not
    ingested yet reports mode `unloaded` for an index that is about to load."""
    from app.main import _geo_health

    db.stamp_geo_sources()
    block, reasons = _geo_health()

    assert block["mode"] == "scope+country/asn"
    assert block["loaded"] is True
    assert block["scope_available"] is True
    assert block["backfill_due"] is False
    assert block["write_state"]["failures"] == 0
    assert reasons == []


def test_health_names_the_backfill_when_history_is_stale(loaded):
    from app.main import _geo_health

    _store([_evt(1, src_ip="8.8.8.8")])
    db.stamp_geo_sources()                      # upgrade shape: not seeded
    block, reasons = _geo_health()

    assert block["backfill_due"] is True
    assert any("backfill_geo" in r for r in reasons), reasons


# ══════════════════════════════════════════════════════════════════════════════
#  The real side-load path: a FILE on disk -> settings -> a stored column
# ══════════════════════════════════════════════════════════════════════════════
def test_a_side_loaded_csv_reaches_a_stored_events_row(clean_db, tmp_path):
    """THE OPERATOR'S ACTUAL PATH, and the only test that walks all of it.

    Every other test in this file installs an index with `geo.set_index`, which skips
    `geo.load()` entirely — so `_open_csv`, `RangeTable.load`, the precedence order and
    the `Settings` field lookup are all bypassed. The failure that hides in exactly that
    gap is the one this repo already has scars from: a path that resolved against the
    wrong working directory, loaded nothing, and left every prescribed check saying ok
    while the columns stayed NULL forever.

    `settings` is a frozen dataclass built at import, so the field is forced through
    `_configured` rather than `monkeypatch.setattr`, which raises `FrozenInstanceError`.
    An ABSOLUTE path is used deliberately — that is what the documentation tells
    operators to configure, and a relative one here would pass on a runner whose cwd
    happens to be the repo root, which is the exact failure being guarded against.
    """
    csv_path = tmp_path / "ranges.csv"
    csv_path.write_text("start_ip,end_ip,country,asn\n"
                        "8.8.8.0,8.8.8.255,US,15169\n"
                        "203.0.113.0,203.0.113.255,NL,64500\n", encoding="utf-8")

    with _configured(geo_ranges_csv=str(csv_path.resolve())):
        index = geo.reload()                    # the real loader, off a real file
        # a TUPLE, not a list — `GeoIndex.__init__` freezes it. The test asserted a list
        # on the first run and was wrong; the code was right.
        assert index.errors == (), index.errors
        assert [s.kind for s in index.sources] == ["csv"]
        # the resolved absolute path is published for diagnosis, per `describe()`
        assert index.sources[0].path == str(csv_path.resolve())

        _store([_evt(1, src_ip="8.8.8.8", dst_ip="203.0.113.9")])

        (row,) = _rows()                        # read back out of Postgres
        assert (row["src_country"], row["src_asn"]) == ("US", 15169)
        assert (row["dst_country"], row["dst_asn"]) == ("NL", 64500)
        # An address the file answers for does NOT lose the scope layer: the
        # documentation range is still labelled for what it is.
        assert row["context_tags"] == ["dst:documentation", "src:public"]


def test_a_configured_file_that_is_missing_is_reported_not_swallowed(
        clean_db, tmp_path):
    """A path that does not exist must land in `errors` — and the events must still be
    stored, with their scope labels intact. Both halves matter: a loud error with lost
    events would be worse than the silence it replaces."""
    with _configured(geo_ranges_csv=str(tmp_path / "nope.csv")):
        index = geo.reload()
        assert len(index.errors) == 1
        assert "FileNotFoundError" in index.errors[0]
        assert index.is_empty()

        _store([_evt(1, src_ip="8.8.8.8")])

        (row,) = _rows()
        assert row["src_country"] is None       # no country, as expected
        assert row["context_tags"] == ["src:public"]   # ...but the event kept its label
        assert db.geo_write_state()["failures"] == 0   # a bad FILE is not a write fault

        from app.main import _geo_health
        _block, reasons = _geo_health()
        assert any("did not load" in r for r in reasons), reasons


# ── the shared-array erasure guard ────────────────────────────────────────────
@pytest.mark.integration
def test_backfill_geo_refuses_to_run_when_the_asset_registry_failed_to_load(clean_db):
    """THE BLOCKER THIS GUARD EXISTS FOR, proven by reading the store back.

    `assets.get_index()` degrades to EMPTY_INDEX silently on any load failure — the
    right contract at ingest, where context is never worth an event. But `backfill_geo`
    re-derives the SHARED `context_tags` array, so an empty asset index means every row
    is rewritten with the geo half alone: `host:prod`, `src:pci` and `identity:vip`
    deleted across the whole store, no error, nothing left to show what was lost.
    """
    db.upsert_asset("srv-db-01", criticality="critical", environment="prod",
                    watchlist=["crown-jewel"], aliases=[("hostname", "SRV-DB-01")])
    real = assets.reload()
    db.stamp_asset_registry(real)

    batch = db.create_batch(None, None, "geoguard", "generic_json", "test", None)
    evt = NormalizedEvent(event_time=dt.datetime(2026, 8, 5, tzinfo=dt.timezone.utc),
                          vendor="geoguard", host_name="SRV-DB-01",
                          src_ip="10.1.2.3", dst_ip="8.8.8.8", raw={"n": 1})
    with db.pool().connection() as conn:
        db.insert_events(conn, [evt], batch)
        conn.commit()

    def stored_tags():
        with db.pool().connection() as conn:
            return conn.execute("SELECT context_tags FROM events "
                                "WHERE vendor = 'geoguard'").fetchone()["context_tags"]

    before = stored_tags()
    assert any(t.startswith("host:") for t in before), before      # asset labels present
    assert any(t.endswith(":private") or t.endswith(":public") for t in before), before

    # the registry index degrades exactly as a failed load leaves it
    assets.set_index(assets.EMPTY_INDEX)
    with pytest.raises(RuntimeError, match="refusing to run backfill_geo"):
        db.backfill_geo()

    assert stored_tags() == before, "the refusal must leave the store untouched"

    # ...and with the registry loaded it runs and preserves BOTH halves
    assets.set_index(real)
    db.backfill_geo()
    after = stored_tags()
    assert any(t.startswith("host:") for t in after), after
    assert any(t.endswith(":private") or t.endswith(":public") for t in after), after
    assets.set_index(None)


@pytest.mark.integration
def test_backfill_geo_still_runs_when_nothing_is_declared(clean_db):
    """An empty index and an empty registry are not the same thing. A fresh install
    has declared nothing, and the backfill must work there — otherwise the guard would
    make geo unusable until somebody created an asset."""
    assets.set_index(assets.EMPTY_INDEX)
    batch = db.create_batch(None, None, "geoguard", "generic_json", "test", None)
    evt = NormalizedEvent(event_time=dt.datetime(2026, 8, 5, tzinfo=dt.timezone.utc),
                          vendor="geoguard", src_ip="10.1.2.3", raw={"n": 2})
    with db.pool().connection() as conn:
        db.insert_events(conn, [evt], batch)
        conn.commit()
    result = db.backfill_geo()                      # must NOT raise
    assert result["scanned"] >= 1
    assets.set_index(None)
