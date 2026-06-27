"""Unit tests for threat-intel: classification, feed parsing, matching, alerting.

All DB-free — the IOC index and feed parsers are pure; only feed *loading*
touches the network/disk and isn't exercised here.
"""
from app.models import NormalizedEvent
from app.threatintel.feeds import parse_feed, split_feeds
from app.threatintel.matcher import (Ioc, IocHit, IocIndex, TI_RULE_ID, classify,
                                      make_ioc, normalize, ti_alert)


def _idx(*iocs) -> IocIndex:
    ix = IocIndex()
    for i in iocs:
        ix.add(i)
    return ix


def _evt(**kw) -> NormalizedEvent:
    kw.setdefault("event_time", None)
    kw.setdefault("vendor", "v")
    return NormalizedEvent(**kw)


# ── classification / normalization ──────────────────────────────────────────
def test_classify():
    assert classify("1.2.3.4") == "ip"
    assert classify("2001:db8::1") == "ip"
    assert classify("10.0.0.0/8") == "cidr"
    assert classify("evil.com") == "domain"
    assert classify("a" * 32) == "hash" and classify("b" * 40) == "hash"
    assert classify("c" * 64) == "hash"
    assert classify("http://x.test/p") == "url"
    assert classify("just a sentence") is None
    assert classify("") is None


def test_normalize_and_make_ioc():
    assert normalize("Evil.COM", "domain") == "evil.com"
    assert normalize("1.2.3.4", "ip") == "1.2.3.4"
    assert make_ioc("EVIL.com", "feed").indicator == "evil.com"
    assert make_ioc("garbage value", "feed") is None
    forced = make_ioc("1.2.3.4", "feed", ioc_type="ip")
    assert forced.ioc_type == "ip" and forced.source == "feed"


# ── feed parsing ────────────────────────────────────────────────────────────
def test_parse_feed_plain_lines_with_comments():
    text = "# header\n1.2.3.4\nevil.com\nhttp://bad/x\n" + ("a" * 32)
    iocs = parse_feed(text, "feedA")
    assert {i.ioc_type for i in iocs} == {"ip", "domain", "url", "hash"}
    assert all(i.source == "feedA" and i.severity == "high" for i in iocs)


def test_parse_feed_csv_type_and_severity():
    text = "1.2.3.4,ip,critical,known scanner\nevil.com,domain"
    d = {i.indicator: i for i in parse_feed(text, "f", default_severity="medium")}
    assert d["1.2.3.4"].severity == "critical" and d["1.2.3.4"].description == "known scanner"
    assert d["evil.com"].severity == "medium" and d["evil.com"].ioc_type == "domain"


def test_parse_feed_json_array_of_strings_and_objects():
    arr = '["1.2.3.4", {"indicator": "evil.com", "severity": "high", "type": "domain"}]'
    assert {i.ioc_type for i in parse_feed(arr, "f")} == {"ip", "domain"}


def test_parse_feed_dedups_within_feed():
    assert len(parse_feed("1.2.3.4\n1.2.3.4\n1.2.3.4", "f")) == 1


def test_split_feeds():
    assert split_feeds("a, b\nc  d") == ["a", "b", "c", "d"]
    assert split_feeds("") == []


# ── matching ────────────────────────────────────────────────────────────────
def test_match_ip_exact_and_cidr():
    ix = _idx(Ioc("1.2.3.4", "ip", "f", "high"), Ioc("10.0.0.0/8", "cidr", "f", "medium"))
    assert ix.match(_evt(src_ip="1.2.3.4"))[0].ioc_type == "ip"
    assert ix.match(_evt(dst_ip="10.1.2.3"))[0].ioc_type == "cidr"
    assert ix.match(_evt(src_ip="8.8.8.8")) == []


def test_match_domain_in_field_and_embedded_in_message():
    ix = _idx(make_ioc("evil.com", "f"))
    assert ix.match(_evt(host_name="evil.com"))[0].indicator == "evil.com"
    hits = ix.match(_evt(message="GET http://evil.com/payload HTTP/1.1"))
    assert hits and hits[0].ioc_type == "domain"


def test_match_hash_in_raw_and_url_in_message():
    h = "a" * 64
    ix = _idx(make_ioc(h, "f"), make_ioc("http://bad.test/x", "f"))
    hh = ix.match(_evt(raw={"file": {"sha256": h.upper()}}))    # case-insensitive
    assert hh and hh[0].ioc_type == "hash" and hh[0].indicator == h
    uh = ix.match(_evt(message="downloaded http://bad.test/x just now"))
    assert any(x.ioc_type == "url" for x in uh)


def test_match_dedups_same_indicator():
    ix = _idx(Ioc("1.2.3.4", "ip", "f", "high"))
    hits = ix.match(_evt(src_ip="1.2.3.4", message="seen from 1.2.3.4 again"))
    assert len(hits) == 1


def test_index_counts_and_len():
    ix = _idx(Ioc("1.2.3.4", "ip", "f", "high"), Ioc("evil.com", "domain", "f", "high"))
    assert len(ix) == 2 and ix.counts()["ip"] == 1 and ix.counts()["domain"] == 1


# ── alert builder ───────────────────────────────────────────────────────────
def test_ti_alert_summarizes_and_takes_max_severity():
    hits = [IocHit("1.2.3.4", "ip", "feedA", "high", "1.2.3.4"),
            IocHit("evil.com", "domain", "https://x/y", "critical", "evil.com")]
    a = ti_alert(hits, _evt(src_ip="1.2.3.4"), dedup_hash="dh", batch_id=7)
    assert a["rule_id"] == TI_RULE_ID and a["level"] == "critical"
    assert "1.2.3.4" in a["message"] and "evil.com" in a["message"]
    assert a["dedup_hash"] == "dh" and a["batch_id"] == 7
