# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""CSV import/export for the asset & identity registry. DB-free.

The parsing rules matter more than they look: this is the surface an operator points
a CMDB export at, and a rule that silently drops a column or shreds a cell produces a
registry that is subtly wrong rather than obviously broken — which then stamps every
event ingested afterwards.
"""
from __future__ import annotations

import pytest

from app.assets import csvio


# ── round trip ───────────────────────────────────────────────────────────────
def test_the_shipped_asset_template_parses():
    """The template is what an operator starts from, so a broken one is a broken
    onboarding path."""
    plan = csvio.read_assets(csvio.ASSET_TEMPLATE)
    assert plan.ok, plan.errors
    (row,) = plan.rows
    assert row["asset_id"] == "srv-db-01" and row["criticality"] == "critical"
    assert row["category"] == ["server", "pci"] and row["watchlist"] == ["crown-jewel"]
    assert ("hostname", "srv-db-01") in row["aliases"]
    assert ("ip", "10.1.2.50") in row["aliases"]


def test_the_shipped_identity_template_parses():
    plan = csvio.read_identities(csvio.IDENTITY_TEMPLATE)
    assert plan.ok, plan.errors
    (row,) = plan.rows
    assert row["priority"] == "high" and row["watchlist"] == ["vip"]
    assert ("sam", "corp\\jdoe") in row["aliases"]


def test_export_then_import_reproduces_the_registry():
    """Export -> edit in a spreadsheet -> re-import has to be lossless, or it is a
    trap rather than a workflow. The export writes exactly the columns the import
    reads, and this is what holds those two in step."""
    stored = [{
        "asset_id": "srv-db-01", "display_name": "DB", "criticality": "critical",
        "category": ["server", "pci"], "owner": "dbteam", "business_unit": "payments",
        "environment": "prod", "watchlist": ["crown-jewel"], "enabled": True,
        "notes": "", "aliases": ["hostname:srv-db-01", "ip:10.1.2.50",
                                 "cidr:10.9.0.0/16"],
    }]
    plan = csvio.read_assets(csvio.export_assets(stored))
    assert plan.ok, plan.errors
    (row,) = plan.rows
    for field in ("asset_id", "display_name", "criticality", "category", "owner",
                  "business_unit", "environment", "watchlist", "enabled"):
        assert row[field] == stored[0][field], field
    assert sorted(f"{t}:{v}" for t, v in row["aliases"]) == sorted(stored[0]["aliases"])


def test_a_disabled_entry_survives_the_round_trip():
    """`enabled` drops an asset's aliases from the index, so losing the flag on export
    would silently re-activate a decommissioned host."""
    out = csvio.export_assets([{"asset_id": "a1", "enabled": False,
                                "criticality": "low", "aliases": []}])
    (row,) = csvio.read_assets(out).rows
    assert row["enabled"] is False


# ── errors an operator can act on ────────────────────────────────────────────
def test_every_error_names_the_row_number_the_operator_sees():
    doc = "\n".join(["asset_id,criticality,ip",
                     "a1,critical,10.1.1.1",
                     ",high,10.1.1.2",                 # row 3
                     "a1,low,10.1.1.3",                # row 4 — duplicate
                     "a2,high,not-an-address"])        # row 5
    plan = csvio.read_assets(doc)
    assert not plan.ok
    assert any("row 3" in e and "empty" in e for e in plan.errors)
    assert any("row 4" in e and "twice" in e for e in plan.errors)
    assert any("row 5" in e and "not a valid ip" in e for e in plan.errors)
    # the good row is still parsed, so the operator sees what WOULD apply
    assert [r["asset_id"] for r in plan.rows] == ["a1"]


def test_a_mistyped_column_is_refused_rather_than_ignored():
    """A dropped `criticallity` column would import every row at the default level —
    a registry that looks populated and grades nothing."""
    plan = csvio.read_assets("asset_id,criticallity\na1,critical")
    assert not plan.ok and "criticallity" in plan.errors[0]


def test_a_missing_key_column_is_refused():
    assert not csvio.read_assets("hostname,criticality\nh1,low").ok
    assert not csvio.read_identities("email,priority\na@b.c,low").ok


def test_a_header_with_no_rows_is_an_error_not_a_silent_no_op():
    plan = csvio.read_assets("asset_id,criticality\n")
    assert not plan.ok and "no data rows" in plan.errors[0]


def test_an_empty_document_is_refused():
    assert not csvio.read_assets("").ok


# ── cell parsing ─────────────────────────────────────────────────────────────
def test_the_first_separator_present_wins_so_a_comma_value_is_not_shredded():
    """`Finance, EMEA` is one business unit. Splitting on all three separators would
    turn it into two labels in a file that uses semicolons everywhere else."""
    (row,) = csvio.read_assets('asset_id,category\na1,"finance, emea;server"').rows
    assert row["category"] == ["finance, emea", "server"]


@pytest.mark.parametrize("cell,want", [
    ("a;b", ["a", "b"]), ("a|b", ["a", "b"]), ("a,b", ["a", "b"]),
    ("  A ; B  ", ["a", "b"]), ("solo", ["solo"]), ("", []),
])
def test_multi_valued_cells(cell, want):
    (row,) = csvio.read_assets(f'asset_id,category\na1,"{cell}"').rows
    assert row["category"] == want


@pytest.mark.parametrize("cell,want", [
    ("false", False), ("FALSE", False), ("0", False), ("no", False),
    ("disabled", False), ("true", True), ("1", True), ("", True), ("yes", True),
])
def test_enabled_accepts_the_spellings_a_spreadsheet_produces(cell, want):
    (row,) = csvio.read_assets(f"asset_id,enabled\na1,{cell}").rows
    assert row["enabled"] is want


def test_aliases_are_normalized_on_import():
    """The stored side must be canonical, or resolution does one dict lookup against
    text that never matches."""
    (row,) = csvio.read_assets(
        "asset_id,hostname,ip,mac\na1,SRV-01.,::ffff:10.1.1.1,AA-BB-CC-DD-EE-FF").rows
    assert dict(row["aliases"]) == {"hostname": "srv-01", "ip": "10.1.1.1",
                                    "mac": "aa:bb:cc:dd:ee:ff"}


def test_a_leading_zero_address_is_refused_rather_than_reinterpreted():
    """Python rejects `010.1.1.1` outright (CVE-2021-29921: such octets used to be
    read as octal, so it and `10.1.1.1` were different addresses to different
    libraries). Refusing surfaces the typo to the operator; silently picking one
    reading would point the alias at a host nobody declared."""
    plan = csvio.read_assets("asset_id,ip\na1,010.1.1.1")
    assert not plan.ok and "not a valid ip" in plan.errors[0]


def test_one_column_may_carry_several_aliases_of_its_type():
    (row,) = csvio.read_assets("asset_id,ip\na1,10.1.1.1;10.1.1.2").rows
    assert row["aliases"] == [("ip", "10.1.1.1"), ("ip", "10.1.1.2")]


def test_an_unknown_criticality_becomes_unknown_not_the_typo():
    (row,) = csvio.read_assets("asset_id,criticality\na1,criticl").rows
    assert row["criticality"] == "unknown"


def test_a_row_with_no_alias_is_flagged_but_not_rejected():
    """Legitimate when an operator is only editing criticality on entries declared
    elsewhere — but worth surfacing, because such a row resolves nothing on its own."""
    plan = csvio.read_assets("asset_id,criticality\na1,critical\na2,low")
    assert plan.ok and plan.aliasless == [2, 3]


def test_blank_lines_are_skipped_not_counted_as_errors():
    plan = csvio.read_assets("asset_id,criticality\na1,low\n,\na2,high")
    assert plan.ok and [r["asset_id"] for r in plan.rows] == ["a1", "a2"]


def test_the_import_marks_its_source_so_a_csv_row_is_distinguishable():
    (row,) = csvio.read_assets("asset_id,criticality\na1,low").rows
    assert row["source"] == "csv"
