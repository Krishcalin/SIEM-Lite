# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Asset & identity registry against a real PostgreSQL.

Every assertion re-queries the database rather than trusting a function's own return
value. That is the defect class this repo has already been bitten by — a test that
compares `f()` to what `f()` said it did passes with the write removed entirely — so
the registry writes, the ingest stamp and the backfill are all read back out.

The DB-free half (canonicalization, the index, the resolver) is in test_assets.py.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app import assets, db
from app.models import NormalizedEvent

pytestmark = pytest.mark.integration

_T = datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc)


def _evt(n: int, **kw) -> NormalizedEvent:
    """An event with a DISTINCT dedup identity.

    `dedup_hash` is sha256(vendor + event_time + raw), so events differing only in
    `message` collapse to one row — the trap that has caught test authors here
    before. `raw={"n": n}` is what actually makes them distinct.
    """
    return NormalizedEvent(event_time=_T, vendor="assettest", raw={"n": n}, **kw)


def _store(events: list[NormalizedEvent]) -> int:
    batch = db.create_batch(None, None, "assettest", "generic_json", "test", None)
    with db.pool().connection() as conn:
        db.insert_events(conn, events, batch)
        conn.commit()
    return batch


def _rows() -> list[dict]:
    with db.pool().connection() as conn:
        return conn.execute(
            "SELECT raw->>'n' AS n, asset_id, asset_criticality, identity_id, "
            "identity_priority, context_tags FROM events WHERE vendor = 'assettest' "
            "ORDER BY (raw->>'n')::int").fetchall()


@pytest.fixture
def registry(clean_db):
    """A declared registry, loaded and stamped. `clean_db` truncates the tables, so
    each test starts from an empty one."""
    db.upsert_asset("srv-db-01", criticality="critical",
                    category=["Server", "PCI"], environment="prod",
                    watchlist=["Crown-Jewel"], owner="dbteam",
                    aliases=[("hostname", "SRV-DB-01"), ("ip", "10.1.2.50")])
    db.upsert_asset("dmz-net", criticality="high", category=["dmz"],
                    aliases=[("cidr", "10.9.0.0/16")])
    db.upsert_identity("u-jdoe", priority="high", watchlist=["VIP"],
                       display_name="John Doe",
                       aliases=[("sam", "jdoe"), ("email", "John.Doe@corp.example")])
    index = assets.reload()
    db.stamp_asset_registry(index)
    yield index
    assets.set_index(None)          # so the next test reloads from its own tables


# ══════════════════════════════════════════════════════════════════════════════
#  Registry writes
# ══════════════════════════════════════════════════════════════════════════════
def test_an_asset_and_its_aliases_are_stored_normalized(registry):
    with db.pool().connection() as conn:
        row = conn.execute("SELECT * FROM assets WHERE asset_id = 'srv-db-01'").fetchone()
        aliases = conn.execute(
            "SELECT alias_type, alias_value FROM asset_aliases "
            "WHERE asset_id = 'srv-db-01' ORDER BY alias_type").fetchall()
    assert row["criticality"] == "critical" and row["owner"] == "dbteam"
    # labels lower-cased on write, so `context_tags` can never hold two spellings
    assert row["category"] == ["pci", "server"] and row["watchlist"] == ["crown-jewel"]
    assert [(a["alias_type"], a["alias_value"]) for a in aliases] == [
        ("hostname", "srv-db-01"), ("ip", "10.1.2.50")]


def test_an_alias_already_claimed_by_another_asset_is_refused(registry):
    """Not last-write-wins: a silent steal would move every future event's context
    from one asset to another with nothing in the UI to show for it.

    And the refusal is ATOMIC — the asset row is written before the aliases are, but
    the raise leaves the transaction uncommitted, so it rolls back with them. A
    half-created asset with no aliases would be worse than either outcome: it
    resolves nothing, yet occupies the id the operator wanted to retry with.
    """
    with pytest.raises(ValueError, match="already declared"):
        db.upsert_asset("other-box", aliases=[("ip", "10.1.2.50")])
    with db.pool().connection() as conn:
        owner = conn.execute("SELECT asset_id FROM asset_aliases WHERE "
                             "alias_type='ip' AND alias_value='10.1.2.50'").fetchone()
        made = conn.execute("SELECT count(*) AS n FROM assets "
                            "WHERE asset_id='other-box'").fetchone()
    assert owner["asset_id"] == "srv-db-01"     # the alias did NOT move
    assert made["n"] == 0                       # ...and nothing was left half-written


def test_re_declaring_aliases_replaces_rather_than_merges(registry):
    """An edit that removes an alias must actually remove it, or a decommissioned
    hostname resolves to the asset forever with no way to retract it."""
    db.upsert_asset("srv-db-01", criticality="critical",
                    aliases=[("hostname", "SRV-DB-01")])       # the ip is dropped
    with db.pool().connection() as conn:
        got = conn.execute("SELECT alias_type FROM asset_aliases "
                           "WHERE asset_id='srv-db-01'").fetchall()
    assert [g["alias_type"] for g in got] == ["hostname"]


def test_omitting_aliases_leaves_the_existing_set_alone(registry):
    db.upsert_asset("srv-db-01", criticality="low")            # a field-only edit
    with db.pool().connection() as conn:
        n = conn.execute("SELECT count(*) AS n FROM asset_aliases "
                         "WHERE asset_id='srv-db-01'").fetchone()["n"]
        crit = conn.execute("SELECT criticality FROM assets "
                            "WHERE asset_id='srv-db-01'").fetchone()["criticality"]
    assert n == 2 and crit == "low"


def test_an_invalid_alias_is_refused_before_anything_is_written(registry):
    with pytest.raises(ValueError, match="not a valid"):
        db.upsert_asset("bad-box", aliases=[("ip", "not-an-address")])
    with pytest.raises(ValueError, match="unknown alias type"):
        db.upsert_asset("bad-box2", aliases=[("serial", "abc")])


def test_deleting_an_asset_takes_its_aliases_with_it(registry):
    assert db.delete_asset("srv-db-01") == 1
    with db.pool().connection() as conn:
        n = conn.execute("SELECT count(*) AS n FROM asset_aliases "
                         "WHERE asset_id='srv-db-01'").fetchone()["n"]
    assert n == 0                               # ON DELETE CASCADE


def test_listing_folds_the_aliases_in_and_orders_by_criticality(registry):
    rows = db.list_assets()
    assert [r["asset_id"] for r in rows] == ["srv-db-01", "dmz-net"]   # critical first
    assert set(rows[0]["aliases"]) == {"hostname:srv-db-01", "ip:10.1.2.50"}


# ══════════════════════════════════════════════════════════════════════════════
#  Ingest-time stamping
# ══════════════════════════════════════════════════════════════════════════════
def test_a_stored_event_carries_the_resolved_context(registry):
    _store([_evt(1, host_name="SRV-DB-01", user_name="CORP\\jdoe",
                 src_ip="10.9.5.7", dst_ip="10.1.2.50")])
    (row,) = _rows()
    assert row["asset_id"] == "srv-db-01"
    assert row["asset_criticality"] == "critical"
    assert row["identity_id"] == "u-jdoe" and row["identity_priority"] == "high"
    # both sides of the flow are represented, plus the identity
    assert "host:crown-jewel" in row["context_tags"]
    assert "src:dmz" in row["context_tags"]
    assert "identity:vip" in row["context_tags"]


def test_an_event_matching_nothing_stores_NULL_not_an_empty_array(registry):
    """NULL keeps the GIN index proportional to rows that actually carry context —
    the same rule `cim_models` follows."""
    _store([_evt(1, host_name="undeclared-box", user_name="nobody")])
    (row,) = _rows()
    assert row["asset_id"] is None and row["context_tags"] is None


def test_context_survives_a_round_trip_through_the_gin_index(registry):
    _store([_evt(1, dst_ip="10.1.2.50"), _evt(2, host_name="undeclared")])
    with db.pool().connection() as conn:
        hit = conn.execute(
            "SELECT raw->>'n' AS n FROM events WHERE vendor='assettest' "
            "AND context_tags @> ARRAY['dst:crown-jewel']::text[]").fetchall()
    assert [h["n"] for h in hit] == ["1"]       # the containment predicate resolves


# ══════════════════════════════════════════════════════════════════════════════
#  The backfill
# ══════════════════════════════════════════════════════════════════════════════
def test_backfill_corrects_rows_ingested_before_the_registry_existed(clean_db):
    assets.set_index(assets.EMPTY_INDEX)        # nothing declared at ingest time
    _store([_evt(1, host_name="SRV-DB-01", user_name="jdoe"),
            _evt(2, src_ip="10.9.9.9")])
    assert all(r["asset_id"] is None for r in _rows())

    db.upsert_asset("srv-db-01", criticality="critical", watchlist=["crown-jewel"],
                    aliases=[("hostname", "SRV-DB-01")])
    db.upsert_asset("dmz-net", criticality="high", aliases=[("cidr", "10.9.0.0/16")])
    db.upsert_identity("u-jdoe", priority="high", aliases=[("sam", "jdoe")])
    index = assets.reload()
    db.stamp_asset_registry(index)

    result = db.backfill_assets(index=index)
    assert result["updated"] == 2 and result["done"] is True

    rows = _rows()                              # read back, not from the return value
    assert rows[0]["asset_id"] == "srv-db-01" and rows[0]["identity_id"] == "u-jdoe"
    assert rows[1]["asset_id"] == "dmz-net"
    assets.set_index(None)


def test_a_backfilled_row_is_identical_to_one_ingested_live(registry):
    """The property the whole design rests on. The backfill re-derives through the
    SAME `assets.resolve` as ingest precisely so a corrected row cannot differ from
    an identically-shaped fresh one."""
    fields = dict(host_name="SRV-DB-01", user_name="CORP\\jdoe",
                  src_ip="10.9.5.7", dst_ip="10.1.2.50")

    assets.set_index(assets.EMPTY_INDEX)        # row 1 stored with no context
    _store([_evt(1, **fields)])
    assets.set_index(registry)                  # row 2 stored WITH context
    _store([_evt(2, **fields)])

    db.backfill_assets(index=registry)          # row 1 corrected
    stale, live = _rows()
    assert {k: v for k, v in stale.items() if k != "n"} == \
           {k: v for k, v in live.items() if k != "n"}
    assert stale["asset_id"] == "srv-db-01"     # ...and not both empty


def test_a_second_backfill_writes_nothing(registry):
    """Rows whose context is unchanged are not written at all, so a re-run after a
    no-op edit is nearly free rather than rewriting every heap tuple it touches."""
    _store([_evt(1, host_name="SRV-DB-01"), _evt(2, dst_ip="10.1.2.50")])
    db.backfill_assets(index=registry)
    again = db.backfill_assets(index=registry)
    assert again["scanned"] == 2 and again["updated"] == 0 and again["unchanged"] == 2


def test_backfill_is_resumable_from_its_reported_cursor(registry):
    assets.set_index(assets.EMPTY_INDEX)
    _store([_evt(n, host_name="SRV-DB-01") for n in range(1, 6)])
    assets.set_index(registry)

    first = db.backfill_assets(index=registry, max_rows=2)
    assert first["done"] is False and first["scanned"] == 2   # stopped on the bound
    rest = db.backfill_assets(index=registry, start_id=first["last_id"])
    assert rest["scanned"] == 3
    assert all(r["asset_id"] == "srv-db-01" for r in _rows())


def test_a_bounded_run_does_not_claim_history_is_current(registry):
    """Only an unbounded, completed pass may advance the stamp — otherwise a partial
    run would report the registry as fully applied to rows it never reached."""
    _store([_evt(n, host_name="SRV-DB-01") for n in range(1, 4)])
    db.backfill_assets(index=registry, max_rows=1)
    with db.pool().connection() as conn:
        row = conn.execute("SELECT backfill_hash FROM asset_meta").fetchone()
    assert row["backfill_hash"] is None


# ══════════════════════════════════════════════════════════════════════════════
#  Staleness
# ══════════════════════════════════════════════════════════════════════════════
def test_a_fresh_install_with_no_registry_owes_no_backfill(clean_db):
    assets.set_index(None)
    status = db.asset_status()
    assert status["assets"] == 0 and status["backfill_due"] is False
    assets.set_index(None)


def test_an_edit_makes_a_backfill_owed_and_the_backfill_clears_it(registry):
    _store([_evt(1, host_name="SRV-DB-01")])
    db.backfill_assets(index=registry)
    assert db.asset_status()["backfill_due"] is False

    db.upsert_asset("srv-db-01", criticality="low",
                    aliases=[("hostname", "SRV-DB-01")])
    updated = assets.reload()
    assert updated.fingerprint != registry.fingerprint
    # measured against the registry AS IT IS NOW, not against the stored
    # `registry_hash` — which is only refreshed on load and would answer "current"
    # for exactly as long as the edit had been ignored
    assert db.asset_status()["backfill_due"] is True

    db.backfill_assets(index=updated)
    assert db.asset_status()["backfill_due"] is False
    (row,) = _rows()
    assert row["asset_criticality"] == "low"


def test_a_display_only_edit_does_not_demand_a_backfill(registry):
    _store([_evt(1, host_name="SRV-DB-01")])
    db.backfill_assets(index=registry)
    db.upsert_asset("srv-db-01", criticality="critical", category=["Server", "PCI"],
                    environment="prod", watchlist=["Crown-Jewel"],
                    owner="a-different-team",          # cannot change a resolution
                    aliases=[("hostname", "SRV-DB-01"), ("ip", "10.1.2.50")])
    assets.reload()
    assert db.asset_status()["backfill_due"] is False
