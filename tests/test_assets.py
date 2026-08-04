# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Asset & identity registry: alias canonicalization, the index, and the resolver.

DB-free — every test here builds an index from literals through `assets.build`, which
is the same constructor `registry.load` feeds from the tables. The database half
(CRUD, alias collisions, ingest stamping, backfill) is in test_integration_assets.py.

The resolver is the piece that has to be right: it decides which business context
lands on every stored event, it runs identically at ingest and in the backfill, and a
wrong answer is invisible in the data — an event resolved to the wrong asset looks
exactly like an event about that asset.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app import assets
from app.assets import normalize as N
from app.models import NormalizedEvent


def evt(**kw) -> NormalizedEvent:
    kw.setdefault("event_time", datetime(2026, 8, 4, tzinfo=timezone.utc))
    kw.setdefault("vendor", "test")
    return NormalizedEvent(**kw)


def index(assets_=(), identities=(), asset_aliases=(), identity_aliases=()):
    """An index from compact literals: assets/identities as dicts, aliases as
    ``(type, value, owner_id)`` triples."""
    return assets.build(
        asset_rows=[dict(enabled=True, **a) for a in assets_],
        identity_rows=[dict(enabled=True, **i) for i in identities],
        asset_alias_rows=[{"alias_type": t, "alias_value": v, "asset_id": o}
                          for t, v, o in asset_aliases],
        identity_alias_rows=[{"alias_type": t, "alias_value": v, "identity_id": o}
                             for t, v, o in identity_aliases])


# ══════════════════════════════════════════════════════════════════════════════
#  Alias canonicalization
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("raw,want", [
    ("WKS-01", "wks-01"), ("wks-01.", "wks-01"), ("  Srv-DB-01  ", "srv-db-01"),
    ("", None), (None, None),
])
def test_hostnames_are_lower_cased_and_dot_stripped(raw, want):
    assert N.norm_hostname(raw) == want


@pytest.mark.parametrize("raw,want", [
    ("10.1.1.1", "10.1.1.1"),
    ("  192.168.0.1 ", "192.168.0.1"),
    ("2001:0DB8:0000::1", "2001:db8::1"),          # canonical IPv6 form
    ("not-an-ip", None), ("10.1.1.256", None), ("", None),
])
def test_addresses_go_through_ipaddress_not_a_string_compare(raw, want):
    """Two spellings of one address must not be declarable as two aliases of two
    different assets."""
    assert N.norm_ip(raw) == want


@pytest.mark.parametrize("mapped", ["::ffff:10.1.1.1", "::FFFF:10.1.1.1",
                                    "::ffff:a01:101"])
def test_an_ipv4_mapped_address_resolves_as_its_ipv4_form(mapped):
    """Dual-stack sockets and JVM servers log ``::ffff:10.1.1.1`` for what is plainly
    ``10.1.1.1``, and Python renders that as a THIRD spelling (``::ffff:a01:101``).
    Without unwrapping, a host declared by its IPv4 address is unresolvable from half
    its own traffic."""
    assert N.norm_ip(mapped) == "10.1.1.1"

    idx = index(assets_=[{"asset_id": "srv"}], asset_aliases=[("ip", "10.1.1.1", "srv")])
    assert assets.resolve(evt(src_ip=mapped), idx).asset_id == "srv"


def test_a_cidr_written_with_a_host_address_stores_as_its_network():
    # An operator writing 10.1.1.5/24 means the network; refusing it would be
    # pedantry that costs a declared subnet.
    assert N.norm_cidr("10.1.1.5/24") == "10.1.1.0/24"
    assert N.norm_cidr("10.1.1.0/24") == "10.1.1.0/24"
    assert N.norm_cidr("nonsense") is None


@pytest.mark.parametrize("raw", ["AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff",
                                 "aa:bb:cc:dd:ee:ff", "AABBCCDDEEFF"])
def test_every_mac_spelling_normalizes_to_one(raw):
    assert N.norm_mac(raw) == "aa:bb:cc:dd:ee:ff"


def test_a_mac_that_is_not_twelve_hex_digits_is_refused():
    assert N.norm_mac("aa:bb:cc:dd:ee") is None
    assert N.norm_mac("zz:bb:cc:dd:ee:ff") is None


def test_sam_keeps_its_domain():
    """Dropping the domain would merge corp\\jdoe with a partner domain's jdoe —
    the wrong-merge this module exists to avoid."""
    assert N.norm_sam("CORP\\JDoe") == "corp\\jdoe"
    assert N.norm_sam("CORP/JDoe") == "corp\\jdoe"      # forward slash normalized
    assert N.norm_sam("JDoe") == "jdoe"


def test_norm_alias_refuses_an_unknown_type_rather_than_guessing():
    # A lenient fallback would create a row that nothing can ever match.
    assert assets.norm_alias("hostname", "WKS-01") == "wks-01"
    assert assets.norm_alias("serial_number", "abc") is None
    assert assets.norm_alias("", "abc") is None


# ── candidate extraction ────────────────────────────────────────────────────
def test_a_dotted_host_offers_the_fqdn_before_the_short_name():
    assert N.asset_candidates("WKS-01.corp.example") == [
        ("fqdn", "wks-01.corp.example"), ("hostname", "wks-01")]
    assert N.asset_candidates("WKS-01") == [("hostname", "wks-01")]


def test_an_address_in_a_host_field_is_resolved_as_an_address():
    # Otherwise a declared `ip` alias would be unreachable from host_name.
    assert N.asset_candidates("10.1.2.3") == [("ip", "10.1.2.3")]


def test_an_email_user_offers_upn_then_email_and_never_a_bare_sam():
    """The classic wrong merge: jdoe@partner.example resolving to the internal jdoe
    would attribute an outside party's actions to an employee."""
    got = N.identity_candidates("John.Doe@Corp.Example")
    assert got == [("upn", "john.doe@corp.example"), ("email", "john.doe@corp.example")]
    assert not any(t == "sam" for t, _ in got)


def test_a_qualified_sam_offers_the_qualified_form_first_then_the_bare_one():
    assert N.identity_candidates("CORP\\JDoe") == [("sam", "corp\\jdoe"), ("sam", "jdoe")]


def test_a_bare_user_offers_sam_then_employee_id():
    assert N.identity_candidates("jdoe") == [("sam", "jdoe"), ("employee_id", "jdoe")]
    assert N.identity_candidates("  ") == []


# ══════════════════════════════════════════════════════════════════════════════
#  The index
# ══════════════════════════════════════════════════════════════════════════════
def test_an_alias_of_a_disabled_asset_is_dropped_at_build_time():
    """So the resolver never checks `enabled` per event, and can never hand back an
    id with no object behind it."""
    idx = assets.build(
        asset_rows=[{"asset_id": "gone", "enabled": False}],
        identity_rows=[], asset_alias_rows=[
            {"alias_type": "hostname", "alias_value": "ghost", "asset_id": "gone"}],
        identity_alias_rows=[])
    assert idx.assets == {} and idx.asset_alias == {}
    assert assets.resolve(evt(host_name="ghost"), idx).asset_id is None


def test_an_alias_pointing_at_a_missing_asset_is_dropped():
    idx = index(asset_aliases=[("hostname", "orphan", "no-such-asset")])
    assert idx.asset_alias == {}


def test_an_exact_ip_alias_beats_the_subnet_it_sits_in():
    """Declaring one server inside an already-declared /24 must not be silently
    ignored."""
    idx = index(assets_=[{"asset_id": "srv"}, {"asset_id": "net"}],
                asset_aliases=[("ip", "10.1.2.50", "srv"),
                               ("cidr", "10.1.2.0/24", "net")])
    assert idx.asset_for_ip("10.1.2.50") == "srv"
    assert idx.asset_for_ip("10.1.2.51") == "net"


def test_the_most_specific_cidr_wins_deterministically():
    """An address inside both /8 and /24 belongs to the /24 — always, rather than to
    whichever row the database happened to return first."""
    idx = index(assets_=[{"asset_id": "wide"}, {"asset_id": "narrow"}],
                asset_aliases=[("cidr", "10.0.0.0/8", "wide"),
                               ("cidr", "10.1.2.0/24", "narrow")])
    assert idx.asset_for_ip("10.1.2.7") == "narrow"
    assert idx.asset_for_ip("10.9.9.9") == "wide"
    # ...and the ordering does not depend on insertion order
    flipped = index(assets_=[{"asset_id": "wide"}, {"asset_id": "narrow"}],
                    asset_aliases=[("cidr", "10.1.2.0/24", "narrow"),
                                   ("cidr", "10.0.0.0/8", "wide")])
    assert flipped.asset_for_ip("10.1.2.7") == "narrow"


def test_an_ipv4_address_never_matches_an_ipv6_network():
    idx = index(assets_=[{"asset_id": "v6"}],
                asset_aliases=[("cidr", "2001:db8::/32", "v6")])
    assert idx.asset_for_ip("10.1.2.3") is None
    assert idx.asset_for_ip("2001:db8::1") == "v6"


def test_the_cidr_memo_returns_the_same_answer_as_the_scan():
    idx = index(assets_=[{"asset_id": "net"}],
                asset_aliases=[("cidr", "10.0.0.0/8", "net")])
    first = idx.asset_for_ip("10.1.2.3")            # scans, then memoizes
    assert first == "net" and idx.asset_for_ip("10.1.2.3") == "net"
    # a miss is memoized too, and must stay a miss
    assert idx.asset_for_ip("192.168.1.1") is None
    assert idx.asset_for_ip("192.168.1.1") is None


def test_an_empty_index_short_circuits():
    assert assets.EMPTY_INDEX.is_empty()
    assert assets.resolve(evt(host_name="anything"), assets.EMPTY_INDEX) is assets.EMPTY


# ── the fingerprint ─────────────────────────────────────────────────────────
def test_the_fingerprint_covers_what_changes_a_resolution():
    base = index(assets_=[{"asset_id": "a", "criticality": "low"}],
                 asset_aliases=[("hostname", "h", "a")])
    assert base.fingerprint == index(
        assets_=[{"asset_id": "a", "criticality": "low"}],
        asset_aliases=[("hostname", "h", "a")]).fingerprint          # stable

    changed = index(assets_=[{"asset_id": "a", "criticality": "critical"}],
                    asset_aliases=[("hostname", "h", "a")])
    assert changed.fingerprint != base.fingerprint                   # criticality
    moved = index(assets_=[{"asset_id": "a", "criticality": "low"}],
                  asset_aliases=[("hostname", "other", "a")])
    assert moved.fingerprint != base.fingerprint                     # an alias


def test_disabling_an_asset_changes_the_fingerprint():
    """It changes every future row, so it must make a backfill owed."""
    on = assets.build([{"asset_id": "a", "enabled": True}], [],
                      [{"alias_type": "hostname", "alias_value": "h", "asset_id": "a"}], [])
    off = assets.build([{"asset_id": "a", "enabled": False}], [],
                       [{"alias_type": "hostname", "alias_value": "h", "asset_id": "a"}], [])
    assert on.fingerprint != off.fingerprint


def test_display_only_edits_do_not_change_the_fingerprint():
    """`owner` and `notes` cannot change a resolution, so editing them must not
    demand a full re-derive of history."""
    a = index(assets_=[{"asset_id": "a", "owner": "alice", "notes": "x"}],
              asset_aliases=[("hostname", "h", "a")])
    b = index(assets_=[{"asset_id": "a", "owner": "bob", "notes": "y"}],
              asset_aliases=[("hostname", "h", "a")])
    assert a.fingerprint == b.fingerprint


# ══════════════════════════════════════════════════════════════════════════════
#  The resolver
# ══════════════════════════════════════════════════════════════════════════════
FULL = dict(
    assets_=[
        {"asset_id": "srv-db-01", "criticality": "critical",
         "category": ["server", "pci"], "environment": "prod",
         "watchlist": ["crown-jewel"]},
        {"asset_id": "wks-014", "criticality": "low", "category": ["workstation"],
         "environment": "prod"},
        {"asset_id": "dmz-net", "criticality": "high", "category": ["dmz"]},
    ],
    identities=[
        {"identity_id": "u-jdoe", "priority": "high", "watchlist": ["vip"]},
        {"identity_id": "svc-bk", "priority": "medium",
         "watchlist": ["service-account"]},
    ],
    asset_aliases=[("hostname", "srv-db-01", "srv-db-01"),
                   ("ip", "10.1.2.50", "srv-db-01"),
                   ("fqdn", "wks-014.corp.example", "wks-014"),
                   ("cidr", "10.9.0.0/16", "dmz-net")],
    identity_aliases=[("sam", "jdoe", "u-jdoe"),
                      ("email", "john.doe@corp.example", "u-jdoe"),
                      ("sam", "corp\\svc_backup", "svc-bk")])


@pytest.fixture
def idx():
    return index(**FULL)


def test_host_name_is_the_subject_even_when_addresses_also_resolve(idx):
    """host_name names the machine the event is ABOUT; for endpoint telemetry,
    authentication and process events there is no ambiguity at all."""
    r = assets.resolve(evt(host_name="SRV-DB-01", src_ip="10.9.9.9"), idx)
    assert r.asset_id == "srv-db-01" and r.asset_via == "host"
    assert r.asset_criticality == "critical"


def test_src_ip_is_the_subject_when_there_is_no_host_name(idx):
    r = assets.resolve(evt(src_ip="10.1.2.50", dst_ip="10.9.9.9"), idx)
    assert r.asset_id == "srv-db-01" and r.asset_via == "src"


def test_dst_ip_is_the_last_resort(idx):
    r = assets.resolve(evt(dst_ip="10.1.2.50"), idx)
    assert r.asset_id == "srv-db-01" and r.asset_via == "dst"


def test_an_fqdn_event_matches_a_short_name_declaration(idx):
    r = assets.resolve(evt(host_name="WKS-014.corp.example"), idx)
    assert r.asset_id == "wks-014" and r.asset_criticality == "low"


def test_the_losing_side_of_a_flow_is_still_queryable_through_context_tags(idx):
    """THE trade the single subject column makes. Without role-prefixed labels from
    every resolved side, 'traffic TO a crown jewel' would be unanswerable on a row
    whose subject is the source."""
    r = assets.resolve(evt(src_ip="10.9.9.9", dst_ip="10.1.2.50"), idx)
    assert r.asset_id == "dmz-net"                    # the subject is the source
    assert "dst:crown-jewel" in r.context_tags        # ...and the destination is NOT lost
    assert "src:dmz" in r.context_tags


def test_context_tags_are_sorted_and_deduplicated(idx):
    """A row re-derived by the backfill must be byte-identical to the same row
    written at ingest, or the backfill rewrites every heap tuple for no change."""
    r = assets.resolve(evt(host_name="srv-db-01", src_ip="10.1.2.50",
                           user_name="jdoe"), idx)
    assert list(r.context_tags) == sorted(set(r.context_tags))


def test_identity_resolves_by_sam_email_and_qualified_sam(idx):
    assert assets.resolve(evt(user_name="CORP\\jdoe"), idx).identity_id == "u-jdoe"
    assert assets.resolve(evt(user_name="jdoe"), idx).identity_id == "u-jdoe"
    assert assets.resolve(
        evt(user_name="John.Doe@corp.example"), idx).identity_id == "u-jdoe"
    assert assets.resolve(evt(user_name="CORP\\svc_backup"), idx).identity_id == "svc-bk"
    assert assets.resolve(evt(user_name="nobody"), idx).identity_id is None


def test_an_identity_contributes_its_watchlist_and_its_priority(idx):
    r = assets.resolve(evt(user_name="jdoe"), idx)
    assert r.identity_priority == "high" and "identity:vip" in r.context_tags


def test_nothing_declared_resolves_to_an_empty_resolution(idx):
    r = assets.resolve(evt(host_name="unknown-box", user_name="nobody"), idx)
    assert r.is_empty() and r.asset_id is None and r.context_tags == ()


def test_the_resolver_never_raises_on_a_malformed_event(idx):
    for bad in (evt(host_name="   "), evt(src_ip="not-an-ip"), evt(user_name="@"),
                evt(host_name="10.1.2.999"), evt()):
        assets.resolve(bad, idx)          # must not raise


def test_a_stored_row_resolves_identically_to_a_normalized_event(idx):
    """The property the whole design rests on: `backfill_assets` re-derives from
    SELECTed rows and MUST agree with what ingest wrote, or a corrected row would
    differ from an identically-shaped fresh one for no visible reason."""
    fields = dict(host_name="SRV-DB-01", user_name="CORP\\jdoe",
                  src_ip="10.9.9.9", dst_ip="10.1.2.50")
    from_object = assets.resolve(evt(**fields), idx)
    from_row = assets.resolve(dict(fields), idx)       # a mapping, as SELECT returns
    assert from_object == from_row


def test_criticality_ranking_orders_worst_first():
    assert assets.rank("critical") < assets.rank("high") < assets.rank("low")
    assert assets.rank("nonsense") > assets.rank("low")     # unknown sorts last


def test_an_unrecognised_criticality_becomes_unknown_not_stored_verbatim():
    """A typo that survived into the column would compare as its own level forever
    and silently never match a rule gating on `critical`."""
    assert assets.normalize_level("criticl") == "unknown"
    assert assets.normalize_level("CRITICAL") == "critical"
    assert assets.normalize_level(None) == "unknown"
