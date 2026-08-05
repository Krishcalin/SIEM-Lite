# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Conformance: our from-spec MMDB reader against databases MaxMind actually built.

WHY THIS FILE EXISTS, AND WHY IT IS SEPARATE FROM tests/test_mmdb.py.
`app/enrich/mmdb.py` is a binary-format parser written from the published spec, with
no `maxminddb` to check it against — the charter forbids the dependency. Its own test
file round-trips through a writer that THIS PROJECT also wrote, which proves the
offset chain is internally coherent and cannot prove it agrees with a real file: a
reader and a writer that misunderstand the format the same way round-trip perfectly.

A wrong answer here is not a crash. It is a plausible wrong country on a stored event.

So this file asserts KNOWN ANSWERS from MaxMind's own published test databases. It is
the only test in the repo that depends on third-party data, which is why the data is
NOT vendored: the files are MaxMind's, they are a few tens of KB, and fetching them is
two lines. The CI integration job fetches them and sets `MMDB_TEST_DATA`, so this runs
on every push; locally:

    mkdir -p /tmp/mmdb && cd /tmp/mmdb
    base=https://raw.githubusercontent.com/maxmind/MaxMind-DB/main/test-data
    for f in GeoIP2-Country-Test.mmdb GeoLite2-ASN-Test.mmdb \\
             MaxMind-DB-test-ipv4-24.mmdb MaxMind-DB-test-ipv4-28.mmdb \\
             MaxMind-DB-test-ipv4-32.mmdb MaxMind-DB-test-decoder.mmdb; do
      curl -sSLO "$base/$f"; done
    MMDB_TEST_DATA=/tmp/mmdb python -m pytest tests/test_mmdb_conformance.py -q

SKIPPING IS ACCEPTABLE HERE AND ALMOST NOWHERE ELSE IN THIS SUITE. The data is
optional and external; a developer without it should not be blocked. What makes the
skip honest rather than a hiding place is that CI supplies the data, so the assertions
below actually run before anything merges — and `test_the_corpus_is_complete_when_it_is_present`
fails rather than skips if the directory exists but is missing files.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.enrich import geo
from app.enrich.mmdb import MMDBReader

_DIR = os.getenv("MMDB_TEST_DATA", "").strip()

pytestmark = pytest.mark.skipif(
    not _DIR or not Path(_DIR).is_dir(),
    reason="set MMDB_TEST_DATA to a directory of MaxMind's published test databases "
           "(see this module's docstring) — CI does this automatically")

#: Every file these tests read. Named here so a partial corpus fails loudly.
_FILES = ("GeoIP2-Country-Test.mmdb", "GeoLite2-ASN-Test.mmdb",
          "MaxMind-DB-test-ipv4-24.mmdb", "MaxMind-DB-test-ipv4-28.mmdb",
          "MaxMind-DB-test-ipv4-32.mmdb", "MaxMind-DB-test-decoder.mmdb")


def db(name: str) -> Path:
    return Path(_DIR) / name


def test_the_corpus_is_complete_when_it_is_present():
    """A directory that exists but is missing files is a broken fetch, not an opt-out.
    Failing here beats every other test in the file silently proving less."""
    missing = [f for f in _FILES if not db(f).is_file()]
    assert not missing, f"MMDB_TEST_DATA={_DIR} is missing: {', '.join(missing)}"


@pytest.mark.parametrize("record_size", [24, 28, 32])
def test_every_record_size_decodes_a_real_maxmind_tree(record_size):
    """The 28-bit split — the middle byte whose nibbles feed two different records —
    is the single most likely bug in a from-spec reader. These are MaxMind's own
    fixtures for all three sizes."""
    with MMDBReader(db(f"MaxMind-DB-test-ipv4-{record_size}.mmdb")) as r:
        assert r.metadata["record_size"] == record_size
        assert r.get("1.1.1.1") == {"ip": "1.1.1.1"}
        assert r.get("1.1.1.2") == {"ip": "1.1.1.2"}
        assert r.get("255.255.255.255") is None      # outside the fixture's tree


@pytest.mark.parametrize("ip,country,registered", [
    ("81.2.69.160", "GB", "US"),          # the canonical GeoIP2 test address
    ("89.160.20.112", "SE", "DE"),        # country and registered_country DIFFER
    ("2a02:d300::1", "UA", "UA"),         # IPv6
])
def test_real_geoip2_country_answers(ip, country, registered):
    """Known answers from MaxMind's own GeoIP2-Country test database.

    `89.160.20.112` is the load-bearing one: its `country` and `registered_country`
    are different, so it pins `_from_mmdb_record`'s precedence against a REAL record
    shape rather than a hand-built literal."""
    with MMDBReader(db("GeoIP2-Country-Test.mmdb")) as r:
        rec = r.get(ip)
    assert rec is not None, f"{ip} should have a record"
    assert rec["country"]["iso_code"] == country
    assert rec["registered_country"]["iso_code"] == registered


def test_an_unallocated_address_has_no_record():
    with MMDBReader(db("GeoIP2-Country-Test.mmdb")) as r:
        assert r.get("10.0.0.1") is None


def test_real_geolite2_asn_answers():
    with MMDBReader(db("GeoLite2-ASN-Test.mmdb")) as r:
        v4 = r.get("1.128.0.1")
        v6 = r.get("2600:6000::1")
    assert v4["autonomous_system_number"] == 1221
    assert v4["autonomous_system_organization"] == "Telstra Pty Ltd"
    assert v6["autonomous_system_number"] == 237


def test_every_data_type_decodes_from_maxminds_own_torture_file():
    """MaxMind's decoder fixture carries one value of every type in the spec. This is
    what proves the control byte, the extended types, the size encodings and the
    pointer classes against bytes we did not write."""
    with MMDBReader(db("MaxMind-DB-test-decoder.mmdb")) as r:
        rec = r.get("::1.1.1.0")
    assert rec is not None

    assert rec["utf8_string"] == "unicode! ☯ - ♫"
    assert rec["boolean"] is True
    assert rec["bytes"] == b"\x00\x00\x00*"
    assert rec["uint16"] == 100
    assert rec["uint32"] == 268435456
    assert rec["int32"] == -268435456
    assert rec["uint64"] == 1152921504606846976
    assert rec["uint128"] == 1329227995784915872903807060280344576
    assert rec["array"] == [1, 2, 3]
    assert rec["map"] == {"mapX": {"arrayX": [7, 8, 9], "utf8_stringX": "hello"}}
    # double is 8-byte and exact at this value; float is 4-byte and is NOT
    assert rec["double"] == 42.123456
    assert rec["float"] == pytest.approx(1.1, rel=1e-6)
    assert rec["float"] != 1.1, "a 4-byte float must not round-trip as a Python float"


def test_the_geo_adapter_reads_a_real_database_end_to_end(tmp_path):
    """The chain the whole from-spec reader exists to serve — setting -> loader ->
    MMDBReader -> the GeoLite2 record shape -> a stored column value — against real
    vendor output rather than a literal record.

    Reviewers found `geo._open_mmdb` at 0% coverage: nothing in the repo pointed it at
    a file. This is that test.
    """
    from app.config import settings

    country, asn = db("GeoIP2-Country-Test.mmdb"), db("GeoLite2-ASN-Test.mmdb")
    prev = (settings.geo_country_db, settings.geo_asn_db)
    try:
        object.__setattr__(settings, "geo_country_db", str(country))
        object.__setattr__(settings, "geo_asn_db", str(asn))
        index = geo.reload()
        assert not index.is_empty(), "both databases should have loaded"

        res = geo.resolve({"src_ip": "81.2.69.160", "dst_ip": "1.128.0.1"}, index)
        assert res.src_country == "GB"
        assert res.dst_asn == 1221
        # scope labels come from the built-in ranges and need no file
        assert "src:public" in res.context_tags
    finally:
        object.__setattr__(settings, "geo_country_db", prev[0])
        object.__setattr__(settings, "geo_asn_db", prev[1])
        geo.set_index(None)
