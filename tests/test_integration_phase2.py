# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Real-PostgreSQL integration tests for the Phase-2 onboarding wave.

The wave shipped a new table (`content_packs`), a new column
(`ingest_batches.dropped_rows`) and an eight-statement multi-table transaction
(`db.apply_content_pack`) with NO integration coverage of any kind: the only
verification was a manual smoke run that left no artifact, and the one unit test that
names `list_content_packs` monkeypatches it, so the real SELECT had never executed.
That is this repo's defect class (b) in its purest form — an assertion that never
reads back from the database — so every assertion below re-queries Postgres rather
than trusting what the function under test returned.

The ingest-action section covers the other half: `dropped` has to survive all the way
into a batch row, on BOTH write paths (`ingest.ingest` for upload/API/collectors and
`streaming._write_group` for the live receivers), or an operator sees a rule that
deletes data reported as a duplicate.
"""
from __future__ import annotations

import pytest

from app import contentpack as cp
from app import ingest_actions

pytestmark = pytest.mark.integration


PACK = """
pack: 1
name: probe-pack
version: 1.0.0
description: A pack that installs one of everything the DB layer writes.
parsers:
  - id: probe-parser
    title: Probe field map
    match_key: product
    match_value: probe-fw
    vendor: probe
    product: firewall
    field_map: {srcip: src_ip, dstip: dst_ip}
rules:
  - id: probe-rule
    title: Probe admin login
    yaml: |
      id: probe-rule
      title: Probe admin login
      level: high
      logsource: {vendor: probe}
      detection:
        selection: {user_name: admin}
        condition: selection
"""


def _read(db) -> tuple[list, list, list]:
    """The three tables a pack writes, read straight back out of Postgres."""
    with db.pool().connection() as conn:
        parsers = conn.execute(
            "SELECT parser_id, title, field_map, vendor, product, enabled "
            "FROM custom_parsers ORDER BY parser_id").fetchall()
        rules = conn.execute(
            "SELECT rule_id, title, yaml_text, enabled FROM custom_rules "
            "ORDER BY rule_id").fetchall()
        packs = conn.execute(
            "SELECT name, version, format, digest, document, installed_by "
            "FROM content_packs ORDER BY name").fetchall()
    return parsers, rules, packs


# --------------------------------------------------------------------------- #
#  Content packs — the write transaction and the read query                    #
# --------------------------------------------------------------------------- #
def test_installing_a_pack_writes_every_row_it_promised(clean_db):
    """Mutation: drop the `custom_rules` INSERT from `db.apply_content_pack` — the
    ApplyResult still lists 'create rule', so only a read-back catches it."""
    pack = cp.parse(PACK)
    plan = cp.plan_install(pack, cp.snapshot())
    cp.apply_plan(plan, cp.DbWriter("integration-user"))

    parsers, rules, packs = _read(clean_db)
    assert [p["parser_id"] for p in parsers] == ["probe-parser"]
    assert [r["rule_id"] for r in rules] == ["probe-rule"]
    assert [k["name"] for k in packs] == ["probe-pack"]

    # jsonb round-trips as a dict, not as the JSON string that was bound.
    assert parsers[0]["field_map"] == {"srcip": "src_ip", "dstip": "dst_ip"}
    assert parsers[0]["vendor"] == "probe" and parsers[0]["enabled"] is True
    assert "id: probe-rule" in rules[0]["yaml_text"]
    assert packs[0]["version"] == "1.0.0" and packs[0]["format"] == 1
    assert packs[0]["digest"] == cp.digest(pack)


def test_the_installing_user_is_recorded_on_the_pack_row(clean_db):
    """`installed_by` was structurally dead: `DbWriter` took no user, so the column,
    the /api/v1/packs field and the console's "Installed by" cell were always NULL.

    Mutation: drop `installed_by` from `DbWriter.flush`'s call — every other
    assertion in this file still passes.
    """
    cp.apply_plan(cp.plan_install(cp.parse(PACK), cp.snapshot()),
                  cp.DbWriter("integration-user"))
    _, _, packs = _read(clean_db)
    assert packs[0]["installed_by"] == "integration-user"


def test_an_unattributed_install_stores_null_rather_than_an_empty_string(clean_db):
    cp.apply_plan(cp.plan_install(cp.parse(PACK), cp.snapshot()), cp.DbWriter())
    _, _, packs = _read(clean_db)
    assert packs[0]["installed_by"] is None


def test_list_content_packs_returns_what_was_actually_stored(clean_db):
    """The real SELECT, never executed before: every unit test monkeypatches it.
    Mutation: rename any column in the SELECT list — psycopg raises UndefinedColumn."""
    cp.apply_plan(cp.plan_install(cp.parse(PACK), cp.snapshot()),
                  cp.DbWriter("integration-user"))
    rows = clean_db.list_content_packs()
    assert [r["name"] for r in rows] == ["probe-pack"]
    row = rows[0]
    assert set(row) >= {"name", "version", "format", "digest", "document",
                        "signed_by", "installed_at", "installed_by"}
    # The stored document must re-parse into the same pack, or upgrade/uninstall —
    # both of which derive ownership from it — are working off something else.
    assert cp.parse(str(row["document"])).key == "probe-pack@1.0.0"


def test_installed_packs_reads_ownership_back_through_the_registry(clean_db):
    cp.apply_plan(cp.plan_install(cp.parse(PACK), cp.snapshot()), cp.DbWriter())
    state = cp.snapshot()
    assert state.owner_of("parser", "probe-parser") == "probe-pack"
    assert state.owner_of("rule", "probe-rule") == "probe-pack"


def test_upgrading_a_pack_deletes_what_the_new_version_dropped(clean_db):
    """The upgrade path against a real table: v2 drops the rule, so the row must go.
    Mutation: skip the `removed_rules` DELETE loop — the plan still says 'delete'."""
    cp.apply_plan(cp.plan_install(cp.parse(PACK), cp.snapshot()), cp.DbWriter())
    v2 = PACK.replace("version: 1.0.0", "version: 2.0.0").split("rules:")[0]
    plan = cp.plan_install(cp.parse(v2), cp.snapshot())
    cp.apply_plan(plan, cp.DbWriter())

    parsers, rules, packs = _read(clean_db)
    assert [p["parser_id"] for p in parsers] == ["probe-parser"]   # still owned
    assert rules == []                                             # dropped by v2
    assert [(k["name"], k["version"]) for k in packs] == [("probe-pack", "2.0.0")]


def test_uninstalling_removes_exactly_what_the_pack_installed(clean_db):
    cp.apply_plan(cp.plan_install(cp.parse(PACK), cp.snapshot()), cp.DbWriter())
    cp.apply_plan(cp.plan_uninstall("probe-pack", cp.snapshot()), cp.DbWriter())
    assert _read(clean_db) == ([], [], [])


def test_an_uninstall_reports_each_removal_exactly_once(clean_db):
    """`apply_plan` appended every non-parser/rule DELETE twice — once in the deletion
    loop and again from its real owner — so an operator's confirmation listed the pack
    (and any cim/compliance entry) two times. Mutation: drop the `kind not in
    ('parser', 'rule')` guard."""
    cp.apply_plan(cp.plan_install(cp.parse(PACK), cp.snapshot()), cp.DbWriter())
    result = cp.apply_plan(cp.plan_uninstall("probe-pack", cp.snapshot()), cp.DbWriter())
    described = [c.describe() for c in result.applied]
    assert len(described) == len(set(described)), described


def test_a_pack_that_conflicts_writes_nothing_at_all(clean_db):
    """Atomicity where it matters: a refused plan must leave the tables untouched."""
    clean_db.upsert_custom_rule("probe-rule", "Hand-authored", "id: probe-rule", True)
    plan = cp.plan_install(cp.parse(PACK), cp.snapshot())
    assert plan.conflicts
    with pytest.raises(cp.PackError):
        cp.apply_plan(plan, cp.DbWriter())

    parsers, rules, packs = _read(clean_db)
    assert parsers == [] and packs == []                  # nothing landed
    assert rules[0]["title"] == "Hand-authored"           # and nothing was clobbered


# --------------------------------------------------------------------------- #
#  Ingest actions — `dropped` has to reach the batch row                       #
# --------------------------------------------------------------------------- #
DROP_RULE = {
    "id": "drop-probe-noise", "action": "drop", "order": 10,
    "logsource": {"vendor": "probe"},
    "detection": {"selection": {"user_name": "noisy"}, "condition": "selection"},
}


@pytest.fixture
def drop_index():
    """Install one drop rule for the duration of a test, then restore the real index."""
    action = ingest_actions.action_from_dict(DROP_RULE, source="test")
    previous = ingest_actions.get_index()
    ingest_actions.set_index(ingest_actions.ActionIndex([action]))
    yield
    ingest_actions.set_index(previous)


def _doc() -> str:
    """Two events, one of which the rule above deletes."""
    import json
    return "\n".join(json.dumps(r) for r in (
        {"vendor": "probe", "user_name": "noisy", "message": "drop me"},
        {"vendor": "probe", "user_name": "quiet", "message": "keep me"},
    ))


def test_a_dropped_event_is_counted_as_dropped_not_as_a_duplicate(clean_db, drop_index):
    """The operator-facing half. Mutation: revert `ingest.py` to
    `result.total - inserted` — the row then reports 1 duplicate and 0 dropped, i.e.
    "we already had this data" instead of "a rule deleted it"."""
    from app import ingest

    summary = ingest.ingest(_doc(), "generic_json", filename="probe.json")
    with clean_db.pool().connection() as conn:
        row = conn.execute(
            "SELECT total_rows, inserted_rows, duplicate_rows, dropped_rows "
            "FROM ingest_batches WHERE id = %s", (summary["batch_id"],)).fetchone()
    assert row["total_rows"] == 2
    assert row["inserted_rows"] == 1
    assert row["dropped_rows"] == 1
    assert row["duplicate_rows"] == 0
    # The invariant the column exists to preserve.
    assert row["total_rows"] == (row["inserted_rows"] + row["duplicate_rows"]
                                 + row["dropped_rows"])


def test_only_the_surviving_event_is_stored(clean_db, drop_index):
    from app import ingest

    ingest.ingest(_doc(), "generic_json", filename="probe.json")
    with clean_db.pool().connection() as conn:
        rows = conn.execute("SELECT user_name FROM events ORDER BY user_name").fetchall()
    assert [r["user_name"] for r in rows] == ["quiet"]


def test_the_live_receiver_path_counts_drops_the_same_way(clean_db, drop_index):
    """`streaming._write_group` is a SEPARATE call site — syslog and NetFlow do not go
    through `ingest.ingest`, so fixing only that one would leave every dropped live
    event counted as a duplicate. Mutation: drop `- result.dropped` in streaming.py."""
    from app import pipeline, streaming

    events = list(pipeline.parse_events(_doc(), "generic_json"))
    inserted = streaming._write_group(events, "generic_json", "syslog", "10.0.0.1", "probe")
    assert inserted == 1
    with clean_db.pool().connection() as conn:
        row = conn.execute(
            "SELECT total_rows, inserted_rows, duplicate_rows, dropped_rows "
            "FROM ingest_batches ORDER BY id DESC LIMIT 1").fetchone()
    assert (row["total_rows"], row["inserted_rows"], row["duplicate_rows"],
            row["dropped_rows"]) == (2, 1, 0, 1)
