# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""The registry's operator surface: console routes, CSV import/export, API reads.

Every assertion reads back from the database or from a second request, never from
the response text of the request that did the writing.

The RBAC boundary is the point of several of these. Registry writes decide which
hosts are crown jewels, and an `api_keys` row carries no role — so a write endpoint
on /api/v1 would let a key issued to a log forwarder re-declare the estate. Writes
are console routes under `require_role("admin")`; /api/v1 is read-only. Tests below
pin both halves.
"""
from __future__ import annotations

import pytest

from app import assets, db

pytestmark = pytest.mark.integration


def _client(clean_db):
    from starlette.testclient import TestClient

    from app.main import app
    return TestClient(app)


ASSETS_CSV = "\n".join([
    "asset_id,criticality,category,watchlist,environment,hostname,ip",
    "srv-db-01,critical,server;pci,crown-jewel,prod,SRV-DB-01,10.1.2.50",
    "wks-014,low,workstation,,prod,WKS-014,",
])

IDENTITIES_CSV = "\n".join([
    "identity_id,priority,watchlist,email,sam",
    "u-jdoe,high,vip,john.doe@corp.example,CORP\\jdoe",
])


@pytest.fixture
def client(clean_db):
    c = _client(clean_db)
    yield c
    assets.set_index(None)


# ══════════════════════════════════════════════════════════════════════════════
#  Plan / apply
# ══════════════════════════════════════════════════════════════════════════════
def test_planning_writes_nothing(client):
    r = client.post("/registry/plan", data={"document": ASSETS_CSV, "kind": "assets"})
    assert r.status_code == 200 and "srv-db-01" in r.text
    with db.pool().connection() as conn:
        n = conn.execute("SELECT count(*) AS n FROM assets").fetchone()["n"]
    assert n == 0, "a dry run must not write"


def test_applying_writes_the_rows_and_reloads_the_index(client):
    r = client.post("/registry/apply", data={"document": ASSETS_CSV, "kind": "assets"})
    assert r.status_code == 200

    with db.pool().connection() as conn:
        rows = conn.execute("SELECT asset_id, criticality, category, watchlist, source "
                            "FROM assets ORDER BY asset_id").fetchall()
        aliases = conn.execute("SELECT alias_type, alias_value, asset_id "
                               "FROM asset_aliases ORDER BY alias_value").fetchall()
    assert [x["asset_id"] for x in rows] == ["srv-db-01", "wks-014"]
    assert rows[0]["criticality"] == "critical"
    assert rows[0]["category"] == ["pci", "server"]      # lower-cased + sorted on write
    assert rows[0]["source"] == "csv"
    assert ("ip", "10.1.2.50") in [(a["alias_type"], a["alias_value"]) for a in aliases]

    # the LIVE index was reloaded, not just the tables written
    assert assets.get_index().asset_for_alias("hostname", "srv-db-01") == "srv-db-01"


def test_a_bad_file_is_refused_whole_and_writes_nothing(client):
    bad = ASSETS_CSV + "\nsrv-db-01,low,,,,DUPLICATE,"      # duplicate asset_id
    r = client.post("/registry/apply", data={"document": bad, "kind": "assets"})
    assert r.status_code == 200 and "twice" in r.text
    with db.pool().connection() as conn:
        n = conn.execute("SELECT count(*) AS n FROM assets").fetchone()["n"]
    assert n == 0, "all-or-nothing: not even the valid rows land"


def test_an_alias_collision_rolls_the_whole_import_back(client):
    client.post("/registry/apply", data={"document": ASSETS_CSV, "kind": "assets"})
    stealing = "\n".join(["asset_id,criticality,ip",
                          "new-a,low,10.9.9.9",
                          "new-b,low,10.1.2.50"])          # already srv-db-01's
    r = client.post("/registry/apply", data={"document": stealing, "kind": "assets"})
    assert "already declared" in r.text
    with db.pool().connection() as conn:
        ids = [x["asset_id"] for x in conn.execute(
            "SELECT asset_id FROM assets ORDER BY asset_id").fetchall()]
        owner = conn.execute("SELECT asset_id FROM asset_aliases WHERE "
                             "alias_value = '10.1.2.50'").fetchone()["asset_id"]
    assert ids == ["srv-db-01", "wks-014"]      # new-a did NOT land either
    assert owner == "srv-db-01"                 # and the alias did not move


def test_replace_deletes_entries_absent_from_the_file(client):
    client.post("/registry/apply", data={"document": ASSETS_CSV, "kind": "assets"})
    shorter = "\n".join(["asset_id,criticality,hostname",
                         "srv-db-01,critical,SRV-DB-01"])
    client.post("/registry/apply",
                data={"document": shorter, "kind": "assets", "replace": "1"})
    with db.pool().connection() as conn:
        ids = [x["asset_id"] for x in conn.execute(
            "SELECT asset_id FROM assets").fetchall()]
    assert ids == ["srv-db-01"]


def test_replace_is_off_by_default(client):
    client.post("/registry/apply", data={"document": ASSETS_CSV, "kind": "assets"})
    shorter = "asset_id,criticality,hostname\nsrv-db-01,critical,SRV-DB-01"
    client.post("/registry/apply", data={"document": shorter, "kind": "assets"})
    with db.pool().connection() as conn:
        n = conn.execute("SELECT count(*) AS n FROM assets").fetchone()["n"]
    assert n == 2, "a partial import must not silently retire everything absent from it"


def test_identities_import_through_the_same_surface(client):
    client.post("/registry/apply",
                data={"document": IDENTITIES_CSV, "kind": "identities"})
    with db.pool().connection() as conn:
        row = conn.execute("SELECT * FROM identities").fetchone()
        aliases = conn.execute("SELECT alias_type, alias_value FROM identity_aliases "
                               "ORDER BY alias_type").fetchall()
    assert row["identity_id"] == "u-jdoe" and row["priority"] == "high"
    assert [(a["alias_type"], a["alias_value"]) for a in aliases] == [
        ("email", "john.doe@corp.example"), ("sam", "corp\\jdoe")]


def test_deleting_an_entry_reloads_the_index(client):
    client.post("/registry/apply", data={"document": ASSETS_CSV, "kind": "assets"})
    client.post("/registry/delete", data={"kind": "assets", "entry_id": "wks-014"})
    with db.pool().connection() as conn:
        ids = [x["asset_id"] for x in conn.execute(
            "SELECT asset_id FROM assets").fetchall()]
    assert ids == ["srv-db-01"]
    assert assets.get_index().asset_for_alias("hostname", "wks-014") is None


def test_every_write_is_audited(client):
    client.post("/registry/apply", data={"document": ASSETS_CSV, "kind": "assets"})
    client.post("/registry/delete", data={"kind": "assets", "entry_id": "wks-014"})
    with db.pool().connection() as conn:
        actions = [a["action"] for a in conn.execute(
            "SELECT action FROM audit_log ORDER BY id").fetchall()]
    assert "registry.import" in actions and "registry.delete" in actions


# ══════════════════════════════════════════════════════════════════════════════
#  Export + template
# ══════════════════════════════════════════════════════════════════════════════
def test_export_round_trips_through_the_console(client):
    client.post("/registry/apply", data={"document": ASSETS_CSV, "kind": "assets"})
    exported = client.get("/registry/export?kind=assets")
    assert exported.status_code == 200
    assert exported.headers["content-type"].startswith("text/csv")

    # re-importing the export must reproduce the registry exactly
    client.post("/registry/apply",
                data={"document": exported.text, "kind": "assets", "replace": "1"})
    again = client.get("/registry/export?kind=assets")
    assert again.text == exported.text


def test_the_templates_download_and_are_importable(client):
    for kind in ("assets", "identities"):
        t = client.get(f"/registry/template?kind={kind}")
        assert t.status_code == 200 and "attachment" in t.headers["content-disposition"]
        r = client.post("/registry/apply", data={"document": t.text, "kind": kind})
        assert r.status_code == 200
    with db.pool().connection() as conn:
        assert conn.execute("SELECT count(*) AS n FROM assets").fetchone()["n"] == 1
        assert conn.execute("SELECT count(*) AS n FROM identities").fetchone()["n"] == 1


# ══════════════════════════════════════════════════════════════════════════════
#  Backfill from the console
# ══════════════════════════════════════════════════════════════════════════════
def test_the_console_backfill_clears_backfill_due(client):
    from datetime import datetime, timezone

    from app.models import NormalizedEvent

    batch = db.create_batch(None, None, "uitest", "generic_json", "test", None)
    evt = NormalizedEvent(event_time=datetime(2026, 8, 4, tzinfo=timezone.utc),
                          vendor="uitest", host_name="SRV-DB-01", raw={"n": 1})
    with db.pool().connection() as conn:
        db.insert_events(conn, [evt], batch)
        conn.commit()

    client.post("/registry/apply", data={"document": ASSETS_CSV, "kind": "assets"})
    assert db.asset_status()["backfill_due"] is True

    r = client.post("/registry/backfill")
    assert r.status_code == 200
    assert db.asset_status()["backfill_due"] is False
    with db.pool().connection() as conn:
        row = conn.execute("SELECT asset_id, asset_criticality FROM events "
                           "WHERE vendor='uitest'").fetchone()
    assert row["asset_id"] == "srv-db-01" and row["asset_criticality"] == "critical"


# ══════════════════════════════════════════════════════════════════════════════
#  The API surface — READS ONLY
# ══════════════════════════════════════════════════════════════════════════════
def test_the_api_exposes_reads_and_the_resolver(client):
    client.post("/registry/apply", data={"document": ASSETS_CSV, "kind": "assets"})
    client.post("/registry/apply", data={"document": IDENTITIES_CSV,
                                         "kind": "identities"})
    key = db.create_api_key("ci-key")["key"]
    h = {"X-API-Key": key}

    status = client.get("/api/v1/registry/status", headers=h).json()
    assert status["assets"] == 2 and status["identities"] == 1

    rows = client.get("/api/v1/registry/assets", headers=h).json()
    assert [r["asset_id"] for r in rows] == ["srv-db-01", "wks-014"]
    assert "ip:10.1.2.50" in rows[0]["aliases"]

    ids = client.get("/api/v1/registry/identities", headers=h).json()
    assert ids[0]["identity_id"] == "u-jdoe"

    # the resolver endpoint answers "which asset, and why" through the REAL resolver
    res = client.get("/api/v1/registry/resolve",
                     params={"host": "SRV-DB-01", "user": "CORP\\jdoe"},
                     headers=h).json()
    assert res["asset_id"] == "srv-db-01" and res["via"] == "host"
    assert res["identity_id"] == "u-jdoe"
    assert "identity:vip" in res["context_tags"]


def test_the_api_needs_a_key(client):
    for path in ("/api/v1/registry/status", "/api/v1/registry/assets",
                 "/api/v1/registry/identities", "/api/v1/registry/resolve"):
        assert client.get(path).status_code == 401, path


def test_the_api_offers_no_registry_write(client):
    """The boundary, asserted rather than assumed. An api_keys row has no role, so a
    write here would let a forwarder's key re-declare which hosts are crown jewels."""
    from app.main import app

    write_methods = {"POST", "PUT", "PATCH", "DELETE"}
    offending = [
        (r.path, sorted(r.methods & write_methods))
        for r in app.routes
        if getattr(r, "path", "").startswith("/api/v1/registry")
        and getattr(r, "methods", set()) & write_methods
    ]
    assert offending == [], f"registry writes must not be on /api/v1: {offending}"
