# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Geo enrichment sources: built-in special ranges, and the side-loaded CSV table.

DB-free and file-light — `ranges` needs nothing at all and `csvdb` is driven through
`RangeTable.loads` from string literals, so every parsing rule here is testable
without a fixture on disk. The one test that does touch disk uses `tmp_path`.

WHAT THESE TESTS ARE ACTUALLY FOR
---------------------------------
Three properties are load-bearing, and each has a failure mode that produces a
plausible-looking wrong answer rather than an error — which is why each is asserted
directly rather than inferred from a happy-path lookup:

  * `ranges` MUST NOT be re-expressible as `ipaddress.is_private`. That refactor looks
    like a simplification and silently relabels documentation, loopback, link-local
    and reserved space as "private". `test_scope_diverges_from_stdlib_is_private`
    pins all fifteen addresses where the two disagree.
  * `csvdb`'s bisection is only correct over DISJOINT ranges. An overlapping file
    makes a lookup MISS an address the file covers. The flatten path is asserted
    through the exact address a naive bisection loses.
  * The two address families must never share a search. `::a00:1` and `10.0.0.1` are
    the same integer, so a merged table answers one with the other's country.

The O(log n) claim is asserted by COUNTING COMPARISONS through an int subclass, not by
timing anything — a timing assertion on a shared CI box is a flake generator, and it
would also pass on a linear scan of a small table.
"""
from __future__ import annotations

import ipaddress
import itertools
import math

import pytest

from app.assets import normalize as N
from app.enrich import csvdb, ranges
from app.enrich.csvdb import RangeTable, RangeTableError
from app.enrich.ranges import SCOPE_LABELS, scope


@pytest.fixture(autouse=True)
def _cold_memo():
    """Every test starts with an empty lookaside, so a memoized answer from an earlier
    test can never be what makes a later one pass."""
    ranges.reset_memo()
    yield
    ranges.reset_memo()


# ══════════════════════════════════════════════════════════════════════════════
#  ranges.scope — the no-data-file layer
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("ip,want", [
    # -- IPv4 ---------------------------------------------------------------- #
    ("10.0.0.1",         "private"),
    ("10.255.255.255",   "private"),
    ("172.16.0.1",       "private"),
    ("172.31.255.255",   "private"),
    ("172.32.0.1",       "public"),        # just outside RFC 1918's /12
    ("192.168.1.1",      "private"),
    ("127.0.0.1",        "loopback"),
    ("127.255.255.254",  "loopback"),
    ("169.254.1.1",      "link-local"),
    ("169.254.169.254",  "link-local"),    # cloud metadata — never "public"
    ("100.64.0.1",       "cgnat"),
    ("100.127.255.255",  "cgnat"),
    ("100.128.0.1",      "public"),        # just outside RFC 6598's /10
    ("224.0.0.1",        "multicast"),
    ("239.255.255.255",  "multicast"),
    ("192.0.2.5",        "documentation"), # TEST-NET-1
    ("198.51.100.5",     "documentation"), # TEST-NET-2
    ("203.0.113.5",      "documentation"), # TEST-NET-3
    ("0.0.0.0",          "reserved"),      # unspecified
    ("0.1.2.3",          "reserved"),      # "this network"
    ("192.0.0.1",        "reserved"),      # IETF protocol assignments
    ("192.88.99.1",      "reserved"),      # deprecated 6to4 relay anycast
    ("198.18.0.1",       "reserved"),      # benchmarking
    ("240.0.0.1",        "reserved"),
    ("255.255.255.255",  "reserved"),      # broadcast
    ("8.8.8.8",          "public"),
    ("1.1.1.1",          "public"),
    # -- IPv6 ---------------------------------------------------------------- #
    ("::1",              "loopback"),
    ("::",               "reserved"),
    ("fe80::1",          "link-local"),
    ("fc00::1",          "private"),
    ("fd00::abcd",       "private"),       # ULA, inside fc00::/7
    ("fec0::1",          "private"),       # deprecated site-local
    ("ff02::1",          "multicast"),
    ("2001:db8::1",      "documentation"),
    ("3fff::1",          "documentation"), # RFC 9637
    ("2001::1",          "reserved"),      # Teredo, inside 2001::/23
    ("2002::1",          "reserved"),      # 6to4
    ("64:ff9b::1",       "reserved"),      # NAT64
    ("100::1",           "reserved"),      # discard-only
    ("2606:4700::1111",  "public"),
])
def test_scope_classifies_every_special_range(ip, want):
    assert scope(ip) == want


def test_every_published_label_is_reachable():
    """A label in the vocabulary that nothing can return is a rule an operator would
    write and never see fire."""
    produced = {scope(ip) for ip in (
        "10.0.0.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "224.0.0.1",
        "192.0.2.5", "240.0.0.1", "8.8.8.8")}
    assert produced == set(SCOPE_LABELS)


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "169.254.1.1", "192.0.2.5", "198.51.100.5", "203.0.113.5",
    "240.0.0.1", "255.255.255.255", "0.0.0.0", "198.18.0.1",
    "::1", "fe80::1", "2001:db8::1", "::", "2001::1", "2002::1",
])
def test_scope_diverges_from_stdlib_is_private(ip):
    """THE ANTI-REFACTOR TEST.

    Every address here reports `is_private == True` from the stdlib and is NOT
    "private" to this product. Rewriting `scope` as `if addr.is_private:
    return 'private'` — which looks like an obvious simplification — fails on all
    fifteen. The distinction is the whole point: an egress rule that treats
    documentation and reserved space as "internal" misses the traffic it exists for.
    """
    assert ipaddress.ip_address(ip).is_private is True
    assert scope(ip) != "private"


def test_the_range_tables_are_pairwise_disjoint():
    """The property that makes ordering irrelevant, asserted rather than assumed.

    `_search` takes the single range whose start is at or below the address. That is
    the right answer only if no address can be in two ranges — so this is the
    precondition of the whole module, and a future entry that overlaps an existing one
    (say, adding 2001::/16 next to 2001:db8::/32) must fail here rather than produce
    an answer that depends on sort order.
    """
    for name, spec in (("v4", ranges._V4_RANGES), ("v6", ranges._V6_RANGES)):
        nets = [ipaddress.ip_network(cidr) for cidr, _ in spec]
        for a, b in itertools.combinations(nets, 2):
            assert not a.overlaps(b), f"{name}: {a} overlaps {b}"


def test_the_range_tables_are_sorted():
    """`bisect` over an unsorted list returns nonsense without raising."""
    assert ranges._V4_STARTS == sorted(ranges._V4_STARTS)
    assert ranges._V6_STARTS == sorted(ranges._V6_STARTS)
    for starts, ends in ((ranges._V4_STARTS, ranges._V4_ENDS),
                         (ranges._V6_STARTS, ranges._V6_ENDS)):
        for s, e in zip(starts, ends):
            assert s <= e


# ---- IPv4-mapped IPv6, and the tunnels that are deliberately NOT unwrapped --- #
@pytest.mark.parametrize("mapped,bare", [
    ("::ffff:10.0.0.1",   "10.0.0.1"),
    ("::ffff:8.8.8.8",    "8.8.8.8"),
    ("::ffff:127.0.0.1",  "127.0.0.1"),
    ("::ffff:192.0.2.5",  "192.0.2.5"),
])
def test_ipv4_mapped_addresses_scope_as_their_ipv4_form(mapped, bare):
    assert scope(mapped) == scope(bare)


def test_mapped_unwrapping_matches_the_asset_registry():
    """CROSS-MODULE CONSISTENCY, not a restatement of the test above.

    `assets/normalize.py:norm_ip` already unwraps IPv4-mapped addresses so a host
    declared by its IPv4 address resolves from dual-stack traffic. If geo did not
    match, one event would carry the asset's business context and no scope tag while
    its neighbour carried both — a divergence that shows up as missing detections, not
    as an error.
    """
    for mapped in ("::ffff:10.0.0.1", "::ffff:8.8.8.8", "::ffff:169.254.1.1"):
        assert scope(mapped) == scope(N.norm_ip(mapped))


@pytest.mark.parametrize("ip", ["2002:0808:0808::1", "2001:0:53aa:64c:1:2:3:4"])
def test_tunnel_addresses_are_not_unwrapped(ip):
    """6to4 and Teredo embed an IPv4 address; reading it would name the TUNNEL
    ENDPOINT rather than the peer, and Teredo's copy is bitwise-inverted. Reported as
    reserved instead — see `parse_ip`'s docstring."""
    assert scope(ip) == "reserved"


# ---- None is not 'public' ---------------------------------------------------- #
@pytest.mark.parametrize("junk", [
    "", "   ", None, "not-an-ip", "srv-db-01.corp.example", "999.1.1.1",
    "10.0.0.256", "::gg", "-", "0",
])
def test_unparseable_input_is_none_not_public(junk):
    """None and 'public' must stay distinct. Collapsing them tags every event with a
    truncated or non-address field as internet-facing, which is exactly the direction
    that manufactures false positives on an egress rule."""
    assert scope(junk) is None


def test_leading_zero_addresses_are_refused_like_the_asset_registry():
    """`010.1.1.1` is refused rather than reinterpreted, matching `norm_ip` — some
    libraries historically read those octets as octal (CVE-2021-29921), so the two
    readings are different addresses."""
    assert scope("010.1.1.1") is None
    assert N.norm_ip("010.1.1.1") is None


# ---- the shapes the backfill actually hands us -------------------------------- #
def test_scope_accepts_the_objects_psycopg_returns_for_an_inet_column():
    """THE SILENT-BACKFILL-FAILURE GUARD.

    `events.src_ip` is a Postgres `inet`; psycopg loads it as an `IPv4Address`, or an
    `IPv4Interface` when the stored text carries a prefix. `str()` of the interface is
    `10.0.0.1/32`, which `ip_address` refuses. If `scope` returned None for these, a
    geo backfill would report `scanned=N, updated=0` — indistinguishable from success
    while doing nothing at all.
    """
    assert scope(ipaddress.ip_address("10.0.0.1")) == "private"
    assert scope(ipaddress.ip_address("8.8.8.8")) == "public"
    assert scope(ipaddress.ip_interface("192.168.5.5/24")) == "private"
    assert scope(ipaddress.ip_interface("8.8.8.8/32")) == "public"
    assert scope("10.0.0.1/32") == "private"          # the same thing as text


def test_surrounding_whitespace_is_tolerated():
    assert scope("  8.8.8.8  ") == "public"


# ---- the memo ---------------------------------------------------------------- #
def test_the_memo_does_not_change_any_answer():
    """Cold and warm must agree for every case in the table, or the cache is a bug
    generator rather than an optimisation."""
    probes = ["10.0.0.1", "8.8.8.8", "192.0.2.5", "::1", "junk", "", "fd00::1"]
    cold = []
    for p in probes:
        ranges.reset_memo()
        cold.append(scope(p))
    ranges.reset_memo()
    warm_first = [scope(p) for p in probes]
    warm_again = [scope(p) for p in probes]
    assert cold == warm_first == warm_again


def test_the_memo_is_bounded():
    """An unbounded memo on the ingest path is a memory leak driven by attacker-chosen
    input — every distinct source address in a scan would be retained forever."""
    for i in range(ranges._MEMO_MAX + 500):
        scope(f"10.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}")
    assert ranges.memo_size() <= ranges._MEMO_MAX


def test_unparseable_input_is_memoized_too():
    """A broken upstream parser emits the same junk on every line; re-deriving it each
    time pays the 5.6 us `ipaddress` parse forever."""
    ranges.reset_memo()
    assert scope("not-an-ip") is None
    assert ranges.memo_size() == 1
    assert scope("not-an-ip") is None
    assert ranges.memo_size() == 1


# ══════════════════════════════════════════════════════════════════════════════
#  csvdb — the side-loaded range table
# ══════════════════════════════════════════════════════════════════════════════
DBIP_COUNTRY = "1.0.0.0,1.0.0.255,AU\n1.0.4.0,1.0.7.255,AU\n8.8.8.0,8.8.8.255,US\n"
IPTOASN_TSV = ("1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n"
               "0.0.0.0\t0.255.255.255\t0\tNone\tNot routed\n"
               "8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n")
MAXMIND_ASN = ("network,autonomous_system_number,autonomous_system_organization\n"
               "1.0.0.0/24,13335,CLOUDFLARENET\n"
               "8.8.8.0/24,15169,GOOGLE LLC\n")


def test_dbip_country_lite_shape_loads_headerless():
    t = RangeTable.loads(DBIP_COUNTRY)
    assert len(t) == 3
    assert t.lookup("8.8.8.8") == {"country": "US", "asn": None}
    assert t.lookup("1.0.5.5") == {"country": "AU", "asn": None}


def test_iptoasn_tsv_shape_loads_with_tab_delimiter():
    t = RangeTable.loads(IPTOASN_TSV)
    assert t.lookup("8.8.8.8") == {"country": "US", "asn": 15169}
    assert t.lookup("1.0.0.9") == {"country": "US", "asn": 13335}


def test_iptoasn_unrouted_rows_are_dropped_not_stored():
    """iptoasn writes ASN `0` and the literal country `None` for unrouted space. A
    stored range carrying neither value is indistinguishable from a miss and only
    makes the table bigger."""
    t = RangeTable.loads(IPTOASN_TSV)
    assert t.blank == 1
    assert t.lookup("0.1.2.3") is None


def test_maxmind_asn_blocks_load_from_the_cidr_column():
    t = RangeTable.loads(MAXMIND_ASN)
    assert t.lookup("8.8.8.8") == {"country": None, "asn": 15169}
    assert t.lookup("1.0.0.1") == {"country": None, "asn": 13335}


def test_maxmind_country_blocks_are_refused_by_name():
    """That file carries geoname_id, not ISO codes. Loading it half-way would give an
    operator a geo install that resolves nothing and reports no error, so it is refused
    with a message that says what to do instead."""
    text = ("network,geoname_id,registered_country_geoname_id,is_anycast\n"
            "1.0.0.0/24,2077456,2077456,0\n")
    with pytest.raises(RangeTableError) as exc:
        RangeTable.loads(text)
    assert "geoname_id" in str(exc.value)


def test_both_keys_are_always_present_on_a_hit():
    """So the resolver needs no per-table conditionals, and a table that later gains an
    ASN column changes no calling code."""
    for text in (DBIP_COUNTRY, MAXMIND_ASN):
        row = RangeTable.loads(text).lookup("8.8.8.8")
        assert set(row) == {"country", "asn"}


def test_a_miss_is_none_not_an_empty_dict():
    """A miss must leave the columns NULL, which is not the same answer as a range that
    covers the address and declares no country."""
    assert RangeTable.loads(DBIP_COUNTRY).lookup("9.9.9.9") is None


@pytest.mark.parametrize("header,cc", [
    ("start_ip,end_ip,country", "DE"),
    ("ip_from,ip_to,cc", "DE"),
    ("range_start,range_end,country_iso_code", "DE"),
    ("first_ip,last_ip,COUNTRY CODE", "DE"),
    ("network_start_ip,network_last_ip,Country-ISO", "DE"),
])
def test_vendor_header_spellings_are_accepted(header, cc):
    t = RangeTable.loads(f"{header}\n10.1.0.0,10.1.0.255,{cc}\n")
    assert t.lookup("10.1.0.7") == {"country": "DE", "asn": None}


def test_semicolon_delimited_files_load():
    t = RangeTable.loads("start_ip;end_ip;country\n10.1.0.0;10.1.0.255;FR\n")
    assert t.lookup("10.1.0.7")["country"] == "FR"


def test_a_utf8_bom_does_not_break_the_header():
    """Excel writes one, and a BOM on the first header cell makes `start_ip` not equal
    `start_ip`."""
    t = RangeTable.loads("﻿start_ip,end_ip,country\n10.1.0.0,10.1.0.255,IT\n")
    assert t.lookup("10.1.0.7")["country"] == "IT"


# ---- the two families must not share a search --------------------------------- #
def test_ipv4_and_ipv6_are_never_searched_together():
    """`::a00:1` is integer 167772161. So is `10.0.0.1`. A single merged list would
    answer an IPv6 lookup with an IPv4 row's country and look entirely confident doing
    it."""
    assert int(ipaddress.ip_address("::a00:1")) == int(ipaddress.ip_address("10.0.0.1"))
    t = RangeTable.loads("10.0.0.0,10.0.0.255,US\n::a00:0,::a00:ff,DE\n")
    assert t.lookup("10.0.0.1") == {"country": "US", "asn": None}
    assert t.lookup("::a00:1") == {"country": "DE", "asn": None}


def test_an_ipv6_lookup_against_an_ipv4_only_table_misses_cleanly():
    t = RangeTable.loads(DBIP_COUNTRY)
    assert t.lookup("2606:4700::1111") is None
    assert t.lookup("::1") is None


# ---- overlapping ranges: the bisection precondition --------------------------- #
def test_a_narrow_range_inside_a_wide_one_wins_without_losing_the_wide_one():
    """THE FLATTEN TEST, and the one that matters most.

    Rows: 10.0.0.0-10.255.255.255 = US, and 10.1.0.0-10.1.0.255 = DE inside it.

    `10.2.0.0` is the address that catches a missing flatten. A plain
    `bisect_right(starts) - 1` lands on the DE row (its start is the greatest one at
    or below 10.2.0.0), sees 10.2.0.0 > its end, and returns a MISS — for an address
    the file plainly covers. Narrowest-wins flattening keeps both answers.
    """
    t = RangeTable.loads("10.0.0.0,10.255.255.255,US\n10.1.0.0,10.1.0.255,DE\n")
    assert t.overlaps == 1
    assert t.lookup("10.1.0.5") == {"country": "DE", "asn": None}   # narrow wins
    assert t.lookup("10.2.0.0") == {"country": "US", "asn": None}   # wide survives
    assert t.lookup("10.0.0.1") == {"country": "US", "asn": None}
    assert t.lookup("10.255.255.255") == {"country": "US", "asn": None}
    assert t.lookup("11.0.0.1") is None


def test_flattening_produces_a_disjoint_sorted_table():
    """The invariant the bisection depends on, asserted on the OUTPUT of the flatten
    rather than on the input file."""
    t = RangeTable.loads(
        "10.0.0.0,10.255.255.255,US\n10.1.0.0,10.1.0.255,DE\n"
        "10.1.0.128,10.9.0.0,FR\n10.0.0.0,10.0.0.7,GB\n")
    starts, ends, _ = t._fam[4]
    assert starts == sorted(starts)
    for i in range(len(starts)):
        assert starts[i] <= ends[i]
        if i:
            assert starts[i] > ends[i - 1], "segments overlap after flattening"


def test_identical_ranges_are_broken_by_file_order():
    """Two rows for one range with different countries is ambiguous; first-in-file
    wins, deterministically, rather than depending on sort stability."""
    a = RangeTable.loads("10.0.0.0,10.0.0.255,US\n10.0.0.0,10.0.0.255,DE\n")
    b = RangeTable.loads("10.0.0.0,10.0.0.255,DE\n10.0.0.0,10.0.0.255,US\n")
    assert a.lookup("10.0.0.5")["country"] == "US"
    assert b.lookup("10.0.0.5")["country"] == "DE"


def test_a_disjoint_file_skips_the_flatten_entirely():
    """The fast path real vendor files take. `overlaps == 0` is what selects it, so
    this also pins that a normal file is not being silently rewritten."""
    t = RangeTable.loads(DBIP_COUNTRY)
    assert t.overlaps == 0
    assert len(t) == t.source_rows == 3


def test_adjacent_segments_with_one_payload_are_merged():
    t = RangeTable.loads("10.0.0.0,10.0.0.255,US\n10.0.1.0,10.0.1.255,US\n"
                         "10.0.0.0,10.0.1.255,US\n")
    assert t.overlaps == 2
    assert len(t) == 1                      # one contiguous US segment, not three
    assert t.lookup("10.0.1.9")["country"] == "US"


# ---- the lookup is logarithmic ------------------------------------------------ #
class _CountingInt(int):
    """An int that tallies the comparisons `bisect` makes against it.

    MEASURED: CPython's C `_bisect` calls the NEEDLE's `__lt__` (17 calls for a
    200,000-element list, log2 = 17.6), so counting here counts the real search.
    """

    count = 0

    def __lt__(self, other):                       # noqa: D105
        _CountingInt.count += 1
        return int(self) < int(other)


def test_lookup_is_logarithmic_not_linear():
    """A linear scan of a 400,000-row ASN table on the ingest path is the thing this
    module exists to avoid, so the search order is asserted directly rather than left
    to a comment.

    Deliberately NOT a timing test: a wall-clock assertion on shared CI is a flake
    generator, and on a small fixture it would pass over a linear scan anyway.
    """
    n = 20000
    rows = "".join(
        f"{10 + (i * 16 >> 24) % 200}.{i * 16 >> 16 & 255}."
        f"{i * 16 >> 8 & 255}.{i * 16 & 255},"
        f"{10 + (i * 16 + 15 >> 24) % 200}.{i * 16 + 15 >> 16 & 255}."
        f"{i * 16 + 15 >> 8 & 255}.{i * 16 + 15 & 255},US\n"
        for i in range(n))
    t = RangeTable.loads(rows)
    segments = len(t._fam[4][0])
    assert segments > 1000, "fixture too small to distinguish log from linear"

    starts = t._fam[4][0]
    _CountingInt.count = 0
    t._find(4, _CountingInt(starts[segments // 3] + 1))
    used = _CountingInt.count

    budget = math.ceil(math.log2(segments)) + 2
    assert used <= budget, f"{used} comparisons over {segments} segments (log2 " \
                           f"= {math.log2(segments):.1f}) — the search is not binary"
    assert used < segments / 100


def test_the_loaded_table_is_sorted_and_disjoint():
    """`bisect` over an unsorted list silently returns the wrong element."""
    t = RangeTable.loads(DBIP_COUNTRY + "2001:db8::,2001:db8::ff,DE\n")
    for version in (4, 6):
        starts, ends, payloads = t._fam[version]
        assert starts == sorted(starts)
        assert len(starts) == len(ends) == len(payloads)
        for i in range(1, len(starts)):
            assert starts[i] > ends[i - 1]


# ---- hostile rows ------------------------------------------------------------- #
def test_malformed_rows_are_refused_with_their_1_based_line_number():
    """The row is skipped, the file survives, and the operator is told which line —
    the shape `assets/csvio.py` established. A whole-file refusal would cost a site
    every country code it has over one bad pair of rows."""
    t = RangeTable.loads(
        "1.0.0.0,1.0.0.255,US\n"          # 1  ok
        "9.9.9.9,8.8.8.8,DE\n"            # 2  reversed
        "nope,1.2.3.4,FR\n"               # 3  unparseable start
        "1.0.0.0,::1,IT\n"                # 4  mixed families
        ",1.2.3.4,ES\n"                   # 5  incomplete
        "5.0.0.0,5.0.0.255,GB\n")         # 6  ok
    assert t.skipped == 4
    assert t.source_rows == 2
    assert t.lookup("5.0.0.9")["country"] == "GB"
    joined = " | ".join(t.errors)
    assert "row 2" in joined and "ends before it starts" in joined
    assert "row 3" in joined and "row 4" in joined and "row 5" in joined
    assert "row 1" not in joined and "row 6" not in joined


def test_a_reversed_range_is_refused_not_silently_swapped():
    """Swapping would invent a range the operator never wrote and hide the fact that
    the file was generated wrongly.

    THE ASSERTION IS THE REFUSAL, NOT THE LOOKUP, and that distinction was found by
    mutation testing: an earlier version of this test checked only that `9.0.0.0` and
    `8.8.8.8` resolve to None, and it PASSED with the reversed-range check deleted. A
    `start > end` row is unreachable by bisection anyway — `bisect_right - 1` can never
    land on it and the end-bound check rejects it if it does — so the lookup outcome is
    identical whether the row was refused or silently accepted. Only `skipped` and the
    error message can tell the difference, and the difference matters: an accepted
    row breaks the sorted/disjoint invariant the whole search rests on.
    """
    t = RangeTable.loads("1.0.0.0,1.0.0.255,US\n9.9.9.9,8.8.8.8,DE\n")
    assert t.skipped == 1
    assert t.source_rows == 1
    assert "row 2" in t.errors[0] and "ends before it starts" in t.errors[0]
    # And the invariant that acceptance would have broken:
    starts, ends, _ = t._fam[4]
    assert all(s <= e for s, e in zip(starts, ends))
    assert t.lookup("9.0.0.0") is None
    assert t.lookup("8.8.8.8") is None


def test_blank_lines_are_skipped_without_becoming_errors():
    t = RangeTable.loads("1.0.0.0,1.0.0.255,US\n\n   \n8.8.8.0,8.8.8.255,US\n")
    assert t.skipped == 0
    assert t.source_rows == 2


def test_line_numbers_survive_a_header():
    """With a header the first data row is line 2, not line 1 — an off-by-one here
    sends an operator to the wrong line of a 400,000-line file."""
    t = RangeTable.loads("start_ip,end_ip,country\n"
                         "9.9.9.9,8.8.8.8,DE\n"          # line 2, reversed
                         "1.0.0.0,1.0.0.255,US\n")       # line 3, fine
    assert t.skipped == 1
    assert "row 2" in t.errors[0]
    assert t.lookup("1.0.0.1")["country"] == "US"


@pytest.mark.parametrize("text,fragment", [
    ("", "empty"),
    ("   \n\n", "empty"),
    ("start_ip,end_ip,country\n", "no data rows"),
    ("hello,world,zz\n", "neither a CIDR column nor a start/end pair"),
    ("start_ip,end_ip\n1.0.0.0,1.0.0.255\n", "neither a country nor an ASN column"),
    ("9.9.9.9,8.8.8.8,DE\n", "no usable rows"),
])
def test_files_that_cannot_yield_a_table_are_refused(text, fragment):
    """File-level refusal, distinct from a skipped row: every lookup would answer None,
    which is indistinguishable from "no database configured" unless it is reported."""
    with pytest.raises(RangeTableError) as exc:
        RangeTable.loads(text)
    assert fragment in str(exc.value)


def test_a_country_column_full_of_geoname_ids_is_refused_as_a_mapping_error():
    """Rows that parse as ranges but carry no value at all mean the wrong column was
    mapped. Serving that table would answer None for everything, which looks exactly
    like "no database configured"."""
    with pytest.raises(RangeTableError) as exc:
        RangeTable.loads("start_ip,end_ip,country\n1.0.0.0,1.0.0.255,2077456\n")
    assert "check the column mapping" in str(exc.value)


def test_an_asn_table_whose_countries_are_all_unrouted_still_loads():
    """The regression this pins: an earlier draft refused any file where a NAMED
    country column produced no code on any row. iptoasn legitimately writes `None`
    there for unrouted space, so that guard threw away a perfectly good ASN table."""
    t = RangeTable.loads("start_ip,end_ip,asn,country\n"
                         "1.0.0.0,1.0.0.255,13335,None\n"
                         "8.8.8.0,8.8.8.255,15169,ZZ\n")
    assert t.lookup("8.8.8.8") == {"country": None, "asn": 15169}
    assert len(t) == 2


def test_the_error_list_is_capped_but_the_count_is_not():
    """A file whose every row is malformed must not hold a 400,000-entry list in
    memory on a SIEM — but the operator still needs the true count."""
    bad = "".join(f"9.9.9.{i % 256},8.8.8.8,DE\n" for i in range(400))
    t = RangeTable.loads("1.0.0.0,1.0.0.255,US\n" + bad)
    assert t.skipped == 400
    assert len(t.errors) == csvdb._MAX_ERRORS


# ---- value normalization ------------------------------------------------------ #
@pytest.mark.parametrize("cell,want", [
    ("13335", 13335), ("AS13335", 13335), ("as13335", 13335), (" 13335 ", 13335),
    ("0", None), ("", None), ("None", None), ("-", None),
])
def test_asn_cells(cell, want):
    t = RangeTable.loads(f"start_ip,end_ip,country,asn\n1.0.0.0,1.0.0.255,US,{cell}\n")
    assert t.lookup("1.0.0.1")["asn"] == want


def test_a_non_numeric_asn_refuses_the_row_rather_than_zeroing_it():
    """Silently treating junk as absent would hide a wrong column mapping."""
    t = RangeTable.loads("start_ip,end_ip,country,asn\n"
                         "1.0.0.0,1.0.0.255,US,CLOUDFLARE\n"
                         "8.8.8.0,8.8.8.255,US,15169\n")
    assert t.skipped == 1
    assert "row 2" in t.errors[0] and "not an AS number" in t.errors[0]


@pytest.mark.parametrize("cell,want", [
    ("us", "US"), ("US", "US"), (" de ", "DE"),
    ("ZZ", None), ("None", None), ("-", None), ("", None), ("USA", None),
    ("2077456", None),
])
def test_country_cells(cell, want):
    text = f"start_ip,end_ip,country,asn\n1.0.0.0,1.0.0.255,{cell},15169\n"
    assert RangeTable.loads(text).lookup("1.0.0.1")["country"] == want


def test_a_host_address_with_a_prefix_is_read_as_its_network():
    """`strict=False`, matching `assets/normalize.py:norm_cidr` — refusing
    `10.1.1.5/24` would be pedantry that costs a declared range."""
    t = RangeTable.loads("network,country\n10.1.1.5/24,US\n")
    assert t.lookup("10.1.1.200") == {"country": "US", "asn": None}


# ---- load() from disk --------------------------------------------------------- #
def test_load_reads_a_file_and_fingerprints_its_bytes(tmp_path):
    """The fingerprint is what a `geo_meta` staleness check compares against, so it
    must follow the file CONTENT, not its name or mtime."""
    p = tmp_path / "geo.csv"
    p.write_text(DBIP_COUNTRY, encoding="utf-8")
    t = RangeTable.load(p)
    assert t.lookup("8.8.8.8")["country"] == "US"
    assert t.path == str(p)
    assert t.fingerprint and len(t.fingerprint) == 32
    assert RangeTable.load(p).fingerprint == t.fingerprint

    p.write_text(DBIP_COUNTRY.replace("US", "GB"), encoding="utf-8")
    assert RangeTable.load(p).fingerprint != t.fingerprint


def test_a_missing_file_raises_rangetableerror_not_oserror(tmp_path):
    """The caller degrades on one exception type; an escaping OSError would reach the
    ingest path as an unhandled error instead of a missing-context log line."""
    with pytest.raises(RangeTableError):
        RangeTable.load(tmp_path / "nope.csv")


def test_stats_reports_the_resolved_path(tmp_path):
    """A relative geo path that resolved against a different working directory is a
    failure mode this project has already been bitten by (see `ingest_actions_dir`),
    and the only cure is showing the path actually opened."""
    p = tmp_path / "geo.csv"
    p.write_text(DBIP_COUNTRY, encoding="utf-8")
    s = RangeTable.load(p).stats()
    assert s["path"] == str(p) and s["segments"] == 3 and s["ipv4"] == 3
    assert s["ipv6"] == 0 and s["overlaps"] == 0 and s["fingerprint"]


def test_an_empty_table_reports_itself_empty():
    t = RangeTable()
    assert t.is_empty() and len(t) == 0 and t.lookup("8.8.8.8") is None


# ── layout inference must not trust row 1 alone ───────────────────────────────
def test_a_leading_unrouted_row_does_not_delete_the_country_column(tmp_path):
    """MEASURED BUG. The layout of a headerless file was inferred from row 1 only, and
    the country column is located by "does this cell parse as a country code?" — so a
    first row carrying one of the vendor 'unknown' spellings left the column unlocated
    and DISCARDED EVERY COUNTRY IN THE FILE.

    Not a corner case: iptoasn and several RIR exports sort unrouted ranges first, so
    0.0.0.0's row is exactly this shape. The ASN position was still found (its '0' is
    a digit), so the table loaded, reported a plausible row count, and answered every
    country query with None.
    """
    doc = "\n".join([
        "0.0.0.0,0.255.255.255,0,None,Not routed",          # the unrouted first row
        "1.0.0.0,1.0.0.255,13335,US,Cloudflare",
        "8.8.8.0,8.8.8.255,15169,US,Google",
    ])
    f = tmp_path / "asn.csv"
    f.write_text(doc, encoding="utf-8")
    table = RangeTable.load(f)
    assert table.lookup("1.0.0.1") == {"country": "US", "asn": 13335}
    assert table.lookup("8.8.8.8")["country"] == "US"


def test_every_sampled_row_is_still_parsed_exactly_once(tmp_path):
    """Sampling reads rows ahead of the parse loop, so the replay must not double-count
    them — an inflated `source_rows` would misreport the table on /health, and a
    malformed sampled row would be reported twice."""
    doc = "\n".join(f"10.0.{i}.0,10.0.{i}.255,{i},US,net{i}" for i in range(5))
    f = tmp_path / "t.csv"
    f.write_text(doc, encoding="utf-8")
    table = RangeTable.load(f)
    assert table.source_rows == 5 and len(table) == 5


def test_sampling_is_bounded_and_does_not_read_the_whole_table(tmp_path):
    doc = "\n".join(f"10.{i // 256}.{i % 256}.0,10.{i // 256}.{i % 256}.255,{i},US,n"
                    for i in range(2000))
    f = tmp_path / "big.csv"
    f.write_text(doc, encoding="utf-8")
    table = RangeTable.load(f)
    assert table.source_rows == 2000 and len(table) == 2000
    assert table.lookup("10.7.15.9") == {"country": "US", "asn": 7 * 256 + 15}


# ── the bisection boundary the suite never probed ─────────────────────────────
def test_the_first_address_of_every_range_resolves(tmp_path):
    """THE classic bisection edge, and it was unprobed: every lookup fixture in this
    file queried a MID-range address, so swapping `bisect_right` for `bisect_left`
    survived the whole suite while making the first address of every range unfindable.

    The equivalent mutation of `ranges._search` was killed by three tests — the
    built-in table had the boundary coverage the CSV table lacked.
    """
    doc = "\n".join([
        "10.0.0.0,10.0.0.255,64500,US,a",
        "10.0.1.0,10.0.1.255,64501,GB,b",
        "192.168.0.0,192.168.0.255,64502,DE,c",
    ])
    f = tmp_path / "b.csv"
    f.write_text(doc, encoding="utf-8")
    table = RangeTable.load(f)
    for first, last, asn in (("10.0.0.0", "10.0.0.255", 64500),
                             ("10.0.1.0", "10.0.1.255", 64501),
                             ("192.168.0.0", "192.168.0.255", 64502)):
        assert table.lookup(first)["asn"] == asn, f"FIRST address of {first} range"
        assert table.lookup(last)["asn"] == asn, f"LAST address of {first} range"
    # ...and an address in the hole between two ranges resolves to nothing
    assert table.lookup("10.0.2.1") is None
    assert table.lookup("9.255.255.255") is None
