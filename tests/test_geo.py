# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Geo enrichment: the index, precedence, caching, and the resolver.

DB-FREE and FILE-FREE — every index here is built from literals through
`geo.literal_source`, which is the same constructor `geo.load` feeds from a real
database file. Nothing in this module opens a socket, a database or a `.mmdb`.

The resolver is the piece that has to be right: it decides what lands on every stored
event, it runs identically at ingest and in `db.backfill_geo`, and a wrong answer is
invisible in the data — an event stamped with the wrong country looks exactly like an
event from that country.

WHY `_scope` IS PATCHED RATHER THAN CALLED FOR REAL. `ranges.scope` belongs to another
module in the same slice and may not exist when this file runs; more importantly, what
this file OWNS is the shaping of that answer — the role prefix, the lower-casing, the
sort, the de-duplication, and the fact that scope survives an empty index. Those are
tested against a deterministic fake so they cannot pass or fail for reasons that live
in someone else's file. `test_scope_is_wired_to_the_real_ranges_module` is the one
test that asserts the real seam, and it skips (loudly) when `ranges.py` is absent.
"""
from __future__ import annotations

import dataclasses
import ipaddress
import pathlib
from datetime import datetime, timezone

import pytest

from app.enrich import geo
from app.enrich.models import EMPTY_GEO, GeoResult
from app.models import NormalizedEvent

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def evt(**kw) -> NormalizedEvent:
    kw.setdefault("event_time", datetime(2026, 8, 5, tzinfo=timezone.utc))
    kw.setdefault("vendor", "test")
    return NormalizedEvent(**kw)


def fake_scope(ip: str):
    """A deterministic stand-in for `ranges.scope`. Only the shapes this file shapes."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.is_loopback:
        return "loopback"
    if addr.is_private:
        return "private"
    return "public"


@pytest.fixture
def scoped(monkeypatch):
    """Wire the deterministic scope fake in. Requested explicitly, not autouse, so
    `test_scope_is_wired_to_the_real_ranges_module` can see the real binding."""
    monkeypatch.setattr(geo, "_scope", fake_scope)
    return fake_scope


@pytest.fixture(autouse=True)
def _isolate_module_cache():
    """The cached index is module state shared with every other test in the process."""
    before, gen = geo._cache, geo._generation
    yield
    geo._cache, geo._generation = before, gen


def src(rows, name="fake"):
    """A source from literals: ``{ip: {'country': .., 'asn': ..}}``."""
    return geo.literal_source(rows, name=name)


class CountingSource:
    """A source that records how many times it was asked — for the memo test."""

    def __init__(self, rows):
        self.rows = dict(rows)
        self.calls = 0

    def lookup(self, ip):
        self.calls += 1
        return self.rows.get(ip)

    def __len__(self):
        return len(self.rows)


# ══════════════════════════════════════════════════════════════════════════════
#  GeoResult — the frozen contract everything else is built against
# ══════════════════════════════════════════════════════════════════════════════
def test_a_default_result_is_empty_and_is_the_shared_singleton():
    assert GeoResult() == EMPTY_GEO
    assert EMPTY_GEO.is_empty() is True
    assert (EMPTY_GEO.src_country, EMPTY_GEO.dst_country) == (None, None)
    assert (EMPTY_GEO.src_asn, EMPTY_GEO.dst_asn) == (None, None)
    assert EMPTY_GEO.context_tags == ()


@pytest.mark.parametrize("kw", [
    {"src_country": "US"}, {"dst_country": "DE"}, {"src_asn": 15169},
    {"dst_asn": 13335}, {"context_tags": ("src:private",)},
])
def test_any_single_populated_field_makes_a_result_non_empty(kw):
    """`db._geo_context` short-circuits on `is_empty`, so a field it did not count
    would be silently dropped on the way to the column."""
    assert GeoResult(**kw).is_empty() is False


def test_the_result_is_frozen():
    with pytest.raises(dataclasses.FrozenInstanceError):
        GeoResult().src_country = "US"          # type: ignore[misc]


# ══════════════════════════════════════════════════════════════════════════════
#  Normalization at the boundary
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("raw,want", [
    ("US", "US"), ("us", "US"), ("  gb  ", "GB"),
    ("USA", None), ("U", None), ("", None), (None, None),
    ("ÉÉ", None),                               # isalpha() is True; isascii() is not
    ("U1", None), (12, None),
])
def test_country_codes_are_two_upper_ascii_letters_or_nothing(raw, want):
    assert geo.norm_country(raw) == want


@pytest.mark.parametrize("raw,want", [
    (15169, 15169), ("15169", 15169), ("AS15169", 15169), ("as15169", 15169),
    (" 15169 ", 15169), (15169.0, 15169), (4294967295, 4294967295),
    (0, None),                                  # AS 0 is reserved (RFC 7607)
    (-1, None), (4294967296, None),
    (True, None), (False, None),                # int(True) == 1 would mean AS 1
    ("", None), ("AS", None), ("nope", None), (None, None), ([], None),
])
def test_asns_are_coerced_to_a_positive_32_bit_int_or_dropped(raw, want):
    assert geo.norm_asn(raw) == want


@pytest.mark.parametrize("raw,want", [
    ("10.1.1.1", "10.1.1.1"),
    ("  8.8.8.8  ", "8.8.8.8"),
    (ipaddress.ip_address("10.1.1.1"), "10.1.1.1"),        # what psycopg hands back
    (ipaddress.ip_interface("10.1.1.1/32"), "10.1.1.1"),   # ...with a prefix
    ("10.1.1.1/24", "10.1.1.1"),
    ("::ffff:8.8.8.8", "8.8.8.8"),                         # IPv4-mapped is unwrapped
    ("2001:0DB8:0000::1", "2001:db8::1"),                  # canonical IPv6 spelling
    ("0.0.0.0", "0.0.0.0"),                                # falsy-looking, still an address
    (None, ""), ("", ""), ("   ", ""),
    ("not-an-ip", "not-an-ip"),                            # passed through, not swallowed
])
def test_addresses_are_normalized_for_both_the_scope_and_the_database_layer(raw, want):
    assert geo._ip_text(raw) == want


# ══════════════════════════════════════════════════════════════════════════════
#  The resolver
# ══════════════════════════════════════════════════════════════════════════════
def test_scope_labels_land_with_no_database_file_at_all(scoped):
    """THE decision this slice is built on: built-in range classification must work
    with no data file. An `is_empty()` short-circuit copied from the asset resolver
    would silently delete this on every install that never side-loads a database."""
    res = geo.resolve(evt(src_ip="10.1.1.1", dst_ip="8.8.8.8"), geo.EMPTY_INDEX)

    assert res.context_tags == ("dst:public", "src:private")
    assert (res.src_country, res.dst_country) == (None, None)
    assert (res.src_asn, res.dst_asn) == (None, None)
    assert res.is_empty() is False


def test_both_sides_resolve_independently(scoped):
    index = geo.GeoIndex([src({"10.1.1.1": {"country": "gb", "asn": "AS2856"},
                               "8.8.8.8": {"country": "us", "asn": 15169}})])

    res = geo.resolve(evt(src_ip="10.1.1.1", dst_ip="8.8.8.8"), index)

    assert (res.src_country, res.src_asn) == ("GB", 2856)
    assert (res.dst_country, res.dst_asn) == ("US", 15169)
    assert res.context_tags == ("dst:public", "src:private")


def test_a_stored_row_resolves_identically_to_a_normalized_event(scoped):
    """`db.backfill_geo` re-derives from SELECTed rows through this exact function, and
    psycopg loads an `inet` column as an address OBJECT — so the mapping shape is fed
    the objects, not strings, which is how it actually arrives."""
    index = geo.GeoIndex([src({"10.1.1.1": {"country": "GB"},
                               "8.8.8.8": {"country": "US", "asn": 15169}})])

    from_event = geo.resolve(evt(src_ip="10.1.1.1", dst_ip="8.8.8.8"), index)
    from_row = geo.resolve({"src_ip": ipaddress.ip_address("10.1.1.1"),
                            "dst_ip": ipaddress.ip_address("8.8.8.8"),
                            "id": 7, "message": "unrelated"}, index)

    assert from_row == from_event
    assert from_row.context_tags == from_event.context_tags


def test_an_event_with_no_addresses_costs_one_identity_check(scoped):
    assert geo.resolve(evt(host_name="wks-01"), geo.EMPTY_INDEX) is EMPTY_GEO


@pytest.mark.parametrize("bad", ["not-an-ip", "10.1.1.256", "999", "-", "10.1.1.1.1"])
def test_a_malformed_address_yields_nothing_and_never_raises(bad, scoped):
    index = geo.GeoIndex([src({"8.8.8.8": {"country": "US"}})])
    assert geo.resolve(evt(src_ip=bad), index) is EMPTY_GEO


def test_a_scope_function_that_raises_costs_the_label_not_the_event(monkeypatch):
    def explode(ip):
        raise RuntimeError("hostile prefix table")

    monkeypatch.setattr(geo, "_scope", explode)
    index = geo.GeoIndex([src({"8.8.8.8": {"country": "US"}})])

    res = geo.resolve(evt(src_ip="8.8.8.8"), index)

    assert res.context_tags == ()
    assert res.src_country == "US"


def test_tags_are_sorted_deduplicated_and_lower_cased(monkeypatch):
    """The array is canonical or the backfill rewrites every heap tuple it touches —
    and it is GIN-indexed and SHARED with the asset labels, so a label differing only
    in case would be a second, permanently non-matching value.

    The surrounding whitespace is the interesting half: `canonical_tags` can only trim
    the ENDS of a finished label, so a scope of ``"  Link-Local  "`` has to be stripped
    before the role prefix goes on or it survives as ``"src:  link-local"``.
    """
    monkeypatch.setattr(geo, "_scope", lambda ip: "  Link-Local  ")

    res = geo.resolve(evt(src_ip="169.254.1.1", dst_ip="169.254.9.9"), geo.EMPTY_INDEX)

    assert res.context_tags == ("dst:link-local", "src:link-local")


#: Enough distinct labels that hash order matching sorted order is a 1-in-11!
#: coincidence. Two labels — all `resolve` can ever emit — is NOT enough: a set of two
#: short strings comes out sorted often enough that a missing `sorted()` survives, which
#: is exactly how this mutant escaped the first time.
_MESSY_TAGS = ["src:Public", "dst:PRIVATE", "src:public", "  dst:cgnat  ", "", "   ",
               "src:zone-z", "src:alpha", "dst:mmm", "src:beta", "dst:aaa", "src:kkk",
               "dst:zzz", "src:ccc", None]


def test_canonical_tags_sorts_deduplicates_lower_cases_and_drops_blanks():
    """`events.context_tags` is written by four places (db._row's merge, both
    backfills, and here). They must agree byte-for-byte or a no-op backfill rewrites
    the whole table — and `tuple(set(...))` orders by HASH, which Python randomizes per
    process, so ingest and a later backfill run would disagree in production only."""
    assert geo.canonical_tags(_MESSY_TAGS) == (
        "dst:aaa", "dst:cgnat", "dst:mmm", "dst:private", "dst:zzz",
        "src:alpha", "src:beta", "src:ccc", "src:kkk", "src:public", "src:zone-z")


def test_canonical_tags_is_stable_across_hash_seeds(tmp_path):
    """The property that actually bites: the ingest worker and `db.backfill_geo` are
    DIFFERENT PROCESSES with different PYTHONHASHSEEDs. Measured, not reasoned about —
    the same input is canonicalized in four fresh interpreters."""
    import os
    import subprocess
    import sys

    script = tmp_path / "canon.py"
    script.write_text(
        "import sys; sys.path.insert(0, %r)\n"
        "from app.enrich import geo\n"
        "print('|'.join(geo.canonical_tags(%r)))\n" % (str(REPO_ROOT), _MESSY_TAGS),
        encoding="utf-8")

    seen = set()
    for seed in ("0", "1", "42", "12345"):
        env = {**os.environ, "PYTHONHASHSEED": seed}
        out = subprocess.run([sys.executable, str(script)], capture_output=True,
                             text=True, env=env, check=True)
        seen.add(out.stdout.strip())

    assert len(seen) == 1, f"canonicalization is hash-order dependent: {seen}"
    assert seen.pop().startswith("dst:aaa|dst:cgnat|")


def test_the_two_sides_keep_their_roles_when_the_scope_is_the_same(scoped):
    res = geo.resolve(evt(src_ip="10.1.1.1", dst_ip="10.9.9.9"), geo.EMPTY_INDEX)
    assert res.context_tags == ("dst:private", "src:private")


def test_a_one_sided_event_labels_only_that_side(scoped):
    res = geo.resolve(evt(dst_ip="8.8.8.8"), geo.EMPTY_INDEX)
    assert res.context_tags == ("dst:public",)


# ══════════════════════════════════════════════════════════════════════════════
#  Precedence
# ══════════════════════════════════════════════════════════════════════════════
def test_the_first_source_that_answers_a_field_wins(scoped):
    """The override layer is first, so an operator can correct a binary database they
    cannot edit."""
    index = geo.GeoIndex([src({"8.8.8.8": {"country": "NZ"}}, name="override"),
                          src({"8.8.8.8": {"country": "US"}}, name="bulk")])

    assert geo.resolve(evt(src_ip="8.8.8.8"), index).src_country == "NZ"


def test_country_and_asn_may_come_from_different_files(scoped):
    """The NORMAL shape, not an edge case: MaxMind ships country and ASN as two
    separate databases, so neither answers the other's field."""
    index = geo.GeoIndex([src({"8.8.8.8": {"country": "US"}}, name="country"),
                          src({"8.8.8.8": {"asn": 15169}}, name="asn")])

    res = geo.resolve(evt(src_ip="8.8.8.8"), index)

    assert (res.src_country, res.src_asn) == ("US", 15169)


def test_a_partial_answer_does_not_stop_the_later_source_filling_the_rest(scoped):
    index = geo.GeoIndex([src({"8.8.8.8": {"country": "US", "asn": None}}),
                          src({"8.8.8.8": {"country": "NZ", "asn": 15169}})])

    res = geo.resolve(evt(src_ip="8.8.8.8"), index)

    assert res.src_country == "US"              # first source still wins the country
    assert res.src_asn == 15169                 # ...but did not answer the ASN


def test_a_source_that_raises_is_skipped_and_the_next_one_still_answers(scoped):
    class Broken:
        def lookup(self, ip):
            raise ValueError("invalid node in search tree")

    index = geo.GeoIndex([geo.GeoSource(name="broken", kind="mmdb",
                                        lookup=Broken().lookup),
                          src({"8.8.8.8": {"country": "US"}})])

    res = geo.resolve(evt(src_ip="8.8.8.8"), index)

    assert res.src_country == "US"
    assert index.failures()["failures"] == 1
    assert "broken" in index.failures()["error"]


@pytest.fixture
def wired(monkeypatch):
    """Pretend `app.config.Settings` already carries the geo fields. Without this,
    `load` correctly appends a wiring error — see the mis-wiring test below."""
    monkeypatch.setattr(geo, "_settings_wired", lambda: True)


def test_load_orders_the_csv_override_ahead_of_the_binary_databases(monkeypatch, wired):
    """Precedence is decided by the order `load` appends, so it is pinned here."""
    monkeypatch.setattr(geo, "_setting", {"geo_country_db": "c.mmdb",
                                          "geo_asn_db": "a.mmdb",
                                          "geo_ranges_csv": "r.csv"}.get)
    monkeypatch.setattr(geo, "_open_csv",
                        lambda raw, name="ranges": src({}, name=name))
    monkeypatch.setattr(geo, "_open_mmdb", lambda raw, name: src({}, name=name))

    index = geo.load()

    assert [s.name for s in index.sources] == ["ranges", "country", "asn"]
    assert index.errors == ()


def test_a_source_that_will_not_open_is_recorded_not_raised(monkeypatch, wired):
    """A bad FILE is cached as a value. Not caching it would re-open and re-parse a
    70 MB database once per event while logging at full ingest rate."""
    monkeypatch.setattr(geo, "_setting", {"geo_country_db": "missing.mmdb",
                                          "geo_ranges_csv": "r.csv"}.get)
    monkeypatch.setattr(geo, "_open_csv",
                        lambda raw, name="ranges": src({}, name=name))

    def boom(raw, name):
        raise FileNotFoundError("/abs/missing.mmdb (configured as 'missing.mmdb')")

    monkeypatch.setattr(geo, "_open_mmdb", boom)

    index = geo.load()

    assert [s.name for s in index.sources] == ["ranges"]
    assert len(index.errors) == 1
    assert "country: FileNotFoundError" in index.errors[0]
    assert "/abs/missing.mmdb" in index.errors[0]


def test_nothing_configured_is_an_empty_index_with_no_errors(monkeypatch, wired):
    """The ordinary state of a fresh install: no database side-loaded, scope labels
    still land, and nothing is wrong."""
    monkeypatch.setattr(geo, "_setting", lambda name: "")
    index = geo.load()
    assert index.is_empty() is True
    assert index.errors == ()


def test_a_settings_object_with_no_geo_fields_is_reported_as_a_wiring_defect(
        monkeypatch):
    """`getattr(settings, name, "")` cannot tell "configured nothing" from "the field
    was never added" — both are "". Left undistinguished, a typo in the wiring change
    looks exactly like a healthy install whose country columns happen to be NULL, which
    is the `ingest_actions_dir` failure this repo already paid for once."""
    monkeypatch.setattr(geo, "_settings", lambda: object())

    index = geo.load()

    assert index.is_empty() is True
    assert len(index.errors) == 1
    assert "geo_ranges_csv" in index.errors[0] and "geo_country_db" in index.errors[0]


def test_a_settings_object_carrying_the_geo_fields_is_not_a_wiring_defect(monkeypatch):
    """The shape the wiring change produces: fields present, values empty."""
    class Wired:
        geo_ranges_csv = ""
        geo_country_db = ""
        geo_asn_db = ""

    monkeypatch.setattr(geo, "_settings", lambda: Wired())

    assert geo.load().errors == ()


# ══════════════════════════════════════════════════════════════════════════════
#  The index
# ══════════════════════════════════════════════════════════════════════════════
def test_an_empty_index_answers_without_touching_any_source():
    assert geo.EMPTY_INDEX.is_empty() is True
    assert len(geo.EMPTY_INDEX) == 0
    assert geo.EMPTY_INDEX.lookup("8.8.8.8") == (None, None)


def test_repeated_addresses_are_memoized_including_the_misses():
    counter = CountingSource({"8.8.8.8": {"country": "US"}})
    index = geo.GeoIndex([geo.GeoSource(name="c", kind="literal",
                                        lookup=counter.lookup)])

    for _ in range(5):
        assert index.lookup("8.8.8.8") == ("US", None)
        assert index.lookup("1.1.1.1") == (None, None)

    assert counter.calls == 2                   # one per distinct address, not per call


def test_the_memo_is_cleared_wholesale_at_its_bound():
    counter = CountingSource({})
    index = geo.GeoIndex([geo.GeoSource(name="c", kind="literal",
                                        lookup=counter.lookup)])
    for i in range(geo._MEMO_MAX + 10):
        index.lookup(f"10.0.{i // 256}.{i % 256}")
    assert len(index._memo) <= geo._MEMO_MAX


def test_a_source_that_answers_with_junk_is_ignored_rather_than_stored():
    index = geo.GeoIndex([geo.GeoSource(name="junk", kind="literal",
                                        lookup=lambda ip: "not-a-mapping")])
    assert index.lookup("8.8.8.8") == (None, None)


# ---- fingerprint ---------------------------------------------------------- #
def _fp(**kw):
    base = dict(name="country", kind="mmdb", lookup=lambda ip: None,
                path="/db/GeoLite2-Country.mmdb", size=7_000_000, mtime_ns=1234,
                rows=99, build="GeoLite2-Country@1770000000")
    base.update(kw)
    return geo.GeoIndex([geo.GeoSource(**base)]).fingerprint


def test_the_fingerprint_is_stable_for_identical_sources():
    assert _fp() == _fp()


@pytest.mark.parametrize("change", [
    {"path": "/db/other.mmdb"}, {"size": 7_000_001}, {"mtime_ns": 1235},
    {"build": "GeoLite2-Country@1780000000"}, {"name": "asn"}, {"rows": 100},
])
def test_the_fingerprint_moves_when_an_input_to_a_resolution_moves(change):
    """`db.backfill_geo` compares this against `geo_meta.backfill_hash`; anything it
    cannot see is a side-load that silently reports history as current."""
    assert _fp(**change) != _fp()


def test_the_fingerprint_encodes_precedence_order_not_just_membership():
    a = geo.GeoSource(name="a", kind="csv", lookup=lambda ip: None, path="/a")
    b = geo.GeoSource(name="b", kind="mmdb", lookup=lambda ip: None, path="/b")
    assert geo.GeoIndex([a, b]).fingerprint != geo.GeoIndex([b, a]).fingerprint


def test_the_empty_index_has_a_real_fingerprint_not_a_null_one():
    """Scope labels are derived with NO file, so rows written before this slice need a
    backfill even on an install that side-loads nothing. `db.geo_status` must not copy
    the asset registry's "nothing declared, nothing owed" guard."""
    assert isinstance(geo.EMPTY_INDEX.fingerprint, str)
    assert len(geo.EMPTY_INDEX.fingerprint) == 32


def test_the_derivation_version_is_part_of_the_fingerprint(monkeypatch):
    """Bumping it must demand a backfill even though every file on disk is unchanged —
    that is the only way a change to the label vocabulary in geo.py can reach history."""
    before = geo.GeoIndex().fingerprint
    monkeypatch.setattr(geo, "_DERIVATION_VERSION", "geo2")
    assert geo.GeoIndex().fingerprint != before


# ══════════════════════════════════════════════════════════════════════════════
#  Caching — the discipline copied from app/assets/registry.py
# ══════════════════════════════════════════════════════════════════════════════
def test_get_index_caches_one_load(monkeypatch):
    calls = []
    monkeypatch.setattr(geo, "_cache", None)
    monkeypatch.setattr(geo, "load", lambda: calls.append(1) or geo.GeoIndex())

    first = geo.get_index()

    assert geo.get_index() is first
    assert len(calls) == 1


def test_get_index_degrades_to_empty_and_does_not_cache_the_failure(monkeypatch):
    """It runs inside the write path: a geo layer that cannot be built must cost an
    event its context, never the event. And because `load` turns a bad FILE into a
    value, reaching here means a defect in this module — which a fixed deployment
    should recover from without a restart, hence no caching."""
    monkeypatch.setattr(geo, "_cache", None)

    def boom():
        raise RuntimeError("defect")

    monkeypatch.setattr(geo, "load", boom)

    assert geo.get_index() is geo.EMPTY_INDEX
    assert geo._cache is None                   # NOT cached — retry next call


def test_a_failed_reload_keeps_the_previous_index(monkeypatch):
    good = geo.GeoIndex([src({"8.8.8.8": {"country": "US"}})])
    geo.set_index(good)

    def boom():
        raise RuntimeError("unreadable")

    monkeypatch.setattr(geo, "load", boom)

    assert geo.reload() is good
    assert geo.get_index() is good


def test_a_reload_where_every_source_broke_keeps_the_previous_index(monkeypatch):
    """`load` reports a broken file as a VALUE, so the "failed reload" rule has to
    cover an index that is empty-with-errors as well as an exception. Installing it
    would strip country and ASN from every later event, and those rows would look
    resolved-to-nothing rather than unresolved."""
    good = geo.GeoIndex([src({"8.8.8.8": {"country": "US"}})])
    geo.set_index(good)
    monkeypatch.setattr(geo, "load",
                        lambda: geo.GeoIndex([], ["country: MMDBError: truncated"]))

    assert geo.reload() is good


def test_a_reload_that_deliberately_unconfigures_everything_is_honoured(monkeypatch):
    """An empty index with NO errors is an operator removing the setting, not a fault."""
    geo.set_index(geo.GeoIndex([src({"8.8.8.8": {"country": "US"}})]))
    monkeypatch.setattr(geo, "load", lambda: geo.GeoIndex())

    assert geo.reload().is_empty() is True


def test_a_partial_reload_is_installed_with_its_errors_published(monkeypatch):
    geo.set_index(geo.GeoIndex([src({}, name="country"), src({}, name="asn")]))
    monkeypatch.setattr(geo, "load",
                        lambda: geo.GeoIndex([src({}, name="country")],
                                             ["asn: MMDBError: bad metadata"]))

    index = geo.reload()

    assert [s.name for s in index.sources] == ["country"]
    assert index.errors == ("asn: MMDBError: bad metadata",)


def test_set_index_installs_directly_and_bumps_the_generation():
    before = geo.generation()
    pinned = geo.GeoIndex([src({})])

    geo.set_index(pinned)

    assert geo.get_index() is pinned
    assert geo.generation() == before + 1


def test_stats_reports_unloaded_before_anything_has_been_read():
    geo.set_index(None)
    s = geo.stats()
    assert s["loaded"] is False and s["mode"] == "unloaded"
    assert s["fingerprint"] is None and s["sources"] == []


def test_stats_names_the_scope_only_mode_so_null_columns_are_explainable():
    """"Why is src_country empty?" on a fresh install is a configuration answer, not a
    fault, and /health has to be able to say so."""
    geo.set_index(geo.GeoIndex())
    s = geo.stats()
    assert s["loaded"] is True and s["mode"] == "scope-only"
    assert s["errors"] == [] and s["lookup_failures"] == 0


def test_stats_reports_the_resolved_path_next_to_the_configured_one():
    """The `ingest_actions_dir` incident in this repo: a relative path verified at the
    repo root loads nothing under a unit with a different WorkingDirectory, and every
    check still says ok. An operator staring at NULL columns needs the absolute path."""
    source = geo.GeoSource(name="country", kind="mmdb", lookup=lambda ip: None,
                           configured="geo/Country.mmdb",
                           path="/srv/logocean/geo/Country.mmdb", size=7, mtime_ns=9,
                           rows=3, build="GeoLite2-Country@1770000000")
    geo.set_index(geo.GeoIndex([source], ["asn: FileNotFoundError: nope"]))

    s = geo.stats()

    assert s["mode"] == "scope+country/asn"
    assert s["sources"][0]["configured"] == "geo/Country.mmdb"
    assert s["sources"][0]["path"] == "/srv/logocean/geo/Country.mmdb"
    assert s["errors"] == ["asn: FileNotFoundError: nope"]
    assert s["fingerprint"] == geo._cache.fingerprint


# ══════════════════════════════════════════════════════════════════════════════
#  Adapting the other groups' classes
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("record,want", [
    ({"country": {"iso_code": "US"}}, {"country": "US", "asn": None}),
    ({"country": {"iso_code": "gb"}, "city": {"names": {"en": "London"}}},
     {"country": "GB", "asn": None}),
    # An anonymous-proxy/satellite record carries no `country` block at all.
    ({"registered_country": {"iso_code": "NL"}}, {"country": "NL", "asn": None}),
    # `country` present but useless -> fall through to `registered_country`.
    ({"country": {}, "registered_country": {"iso_code": "NL"}},
     {"country": "NL", "asn": None}),
    ({"autonomous_system_number": 15169,
      "autonomous_system_organization": "GOOGLE"}, {"country": None, "asn": 15169}),
    ({"country": {"iso_code": "US"}, "autonomous_system_number": 15169},
     {"country": "US", "asn": 15169}),
    ({"continent": {"code": "EU"}}, None),      # nothing we store
    ({}, None), (None, None), ("junk", None), ([1, 2], None),
])
def test_maxmind_record_shapes_are_reduced_to_the_two_stored_facts(record, want):
    assert geo._from_mmdb_record(record) == want


def test_mmdb_source_adapts_a_reader_and_carries_its_metadata_into_the_fingerprint():
    class FakeReader:
        metadata = {"database_type": "GeoLite2-Country", "build_epoch": 1770000000,
                    "node_count": 1234, "record_size": 28}

        def get(self, ip):
            return {"country": {"iso_code": "us"}} if ip == "8.8.8.8" else None

        def close(self):
            self.closed = True

    reader = FakeReader()
    source = geo.mmdb_source(reader, "country", configured="c.mmdb", path="/abs/c.mmdb",
                             size=11, mtime_ns=22)

    assert source.lookup("8.8.8.8") == {"country": "US", "asn": None}
    assert source.lookup("1.1.1.1") is None
    assert source.build == "GeoLite2-Country@1770000000"
    assert source.rows == 1234
    assert source.kind == "mmdb"

    source.close()
    assert reader.closed is True


def test_mmdb_source_survives_a_reader_with_no_metadata_attribute():
    class Bare:
        def get(self, ip):
            return {"autonomous_system_number": 64512}

    source = geo.mmdb_source(Bare(), "asn")
    assert source.lookup("10.1.1.1") == {"country": None, "asn": 64512}
    assert source.build == "" and source.rows == 0
    source.close()                              # no close() on the handle: a no-op


def test_range_source_adapts_a_range_table_shape():
    class FakeTable:
        def lookup(self, ip):
            return {"country": "de", "asn": "AS3320"} if ip == "9.9.9.9" else None

        def __len__(self):
            return 42

    source = geo.range_source(FakeTable(), configured="r.csv", path="/abs/r.csv")

    assert source.kind == "csv" and source.rows == 42
    index = geo.GeoIndex([source])
    assert index.lookup("9.9.9.9") == ("DE", 3320)


def test_close_releases_every_handle_and_a_broken_one_does_not_stop_the_rest():
    class Closer:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    class Angry:
        def close(self):
            raise OSError("already closed")

    ok = Closer()
    index = geo.GeoIndex([geo.GeoSource("a", "mmdb", lambda ip: None, handle=Angry()),
                          geo.GeoSource("b", "mmdb", lambda ip: None, handle=ok)])

    index.close()

    assert ok.closed is True


# ══════════════════════════════════════════════════════════════════════════════
#  The seam to Group B
# ══════════════════════════════════════════════════════════════════════════════
def test_scope_is_wired_to_the_real_ranges_module():
    """The guarded import at the top of geo.py keeps a broken `ranges.py` from taking
    the ingest writer down with it — which also means a missing one is INVISIBLE
    except here and in `stats()['scope_available']`."""
    ranges = pytest.importorskip(
        "app.enrich.ranges",
        reason="Group B's ranges.py has not landed; geo is running the scope stub")
    assert geo._SCOPE_AVAILABLE is True
    assert geo._scope is ranges.scope


def test_stats_reports_whether_scope_classification_is_available():
    geo.set_index(geo.GeoIndex())
    assert geo.stats()["scope_available"] is geo._SCOPE_AVAILABLE


def test_the_real_mmdb_reader_has_the_shape_mmdb_source_adapts():
    """Only the SEAM. Whether the reader decodes MaxMind's format correctly is
    tests/test_mmdb.py's job; what this pins is that `mmdb_source` is adapting the
    members that actually exist, so a rename there fails here rather than at ingest."""
    mmdb = pytest.importorskip("app.enrich.mmdb",
                               reason="Group A's mmdb.py has not landed")
    for member in ("get", "close", "metadata", "__enter__", "__exit__"):
        assert hasattr(mmdb.MMDBReader, member), member
    assert issubclass(mmdb.MMDBError, Exception)


def test_the_real_range_table_resolves_end_to_end_through_range_source(tmp_path):
    """The CSV override layer, from a file on disk to a GeoResult, through Group B's
    real loader — the one cross-module path a fake cannot prove."""
    csvdb = pytest.importorskip("app.enrich.csvdb",
                                reason="Group B's csvdb.py has not landed")
    path = tmp_path / "ranges.csv"
    path.write_text("network,country,asn\n8.8.8.0/24,us,AS15169\n10.0.0.0/8,GB,3320\n",
                    encoding="utf-8")

    source = geo.range_source(csvdb.RangeTable.load(str(path)), path=str(path))
    index = geo.GeoIndex([source])

    res = geo.resolve(evt(src_ip="8.8.8.8", dst_ip="10.1.1.1"), index)

    assert (res.src_country, res.src_asn) == ("US", 15169)
    assert (res.dst_country, res.dst_asn) == ("GB", 3320)
    assert source.kind == "csv" and source.rows == 2
