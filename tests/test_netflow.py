# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Unit tests for the NetFlow v5 / v9 / IPFIX decoder, parser and receiver.

No sockets, no database, no credentials: every packet is built here with
`struct.pack` and fed to the pure `decode_*` functions, and the receiver is
exercised through a duck-typed fake queue.

Each test names the code mutation that makes it fail — a test that still passes
with the code broken is worse than no test.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import struct
from datetime import datetime, timezone

import pytest

from app import pipeline
from app.cim import match
from app.parsers import netflow as netflow_parser
from app.receivers import netflow as nf
from app.receivers.netflow import (NetflowReceiver, Template, TemplateCache,
                                   TemplateField, decode_ipfix, decode_packet,
                                   decode_v5, decode_v9, iter_ipfix_messages,
                                   packet_version)
from app.util import parse_ts

_UTC = timezone.utc
_EXPORT_SECS = 1_750_000_000        # exporter wall clock at export
_UPTIME_MS = 3_600_000              # exporter has been up one hour
_BOOT = _EXPORT_SECS - 3600         # => boot instant, the v5/v9 sysUpTime origin


# ── packet builders ────────────────────────────────────────────────────────────
def _ip(text: str) -> bytes:
    return ipaddress.ip_address(text).packed


def _v5_record(src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=80, proto=6,
               packets=5, octets=400, first_ms=3_500_000, last_ms=3_550_000) -> bytes:
    return struct.pack("!4s4s4sHHIIIIHHBBBBHHBBH",
                       _ip(src), _ip(dst), _ip("10.0.0.254"),
                       1, 2, packets, octets, first_ms, last_ms, sport, dport,
                       0, 0x18, proto, 0, 64500, 64501, 24, 24, 0)


def _v5_packet(records, *, count=None, uptime_ms=_UPTIME_MS, secs=_EXPORT_SECS,
               nsecs=0, sequence=7) -> bytes:
    header = struct.pack("!HHIIIIBBH", 5, len(records) if count is None else count,
                         uptime_ms, secs, nsecs, sequence, 1, 2, 1000)
    return header + b"".join(records)


def _template(template_id: int, fields) -> bytes:
    """A v9/IPFIX template record: id, field count, then (ie, length) pairs."""
    body = struct.pack("!HH", template_id, len(fields))
    for ie, length in fields:
        body += struct.pack("!HH", ie, length)
    return body


def _enterprise_spec(ie: int, length: int, enterprise: int) -> bytes:
    return struct.pack("!HHI", ie | 0x8000, length, enterprise)


def _set(set_id: int, body: bytes, pad: int = 0) -> bytes:
    body = body + b"\x00" * pad
    return struct.pack("!HH", set_id, 4 + len(body)) + body


def _v9_packet(sets: bytes, *, count=99, uptime_ms=_UPTIME_MS, secs=_EXPORT_SECS,
               sequence=11, domain=1) -> bytes:
    return struct.pack("!HHIIII", 9, count, uptime_ms, secs, sequence, domain) + sets


def _ipfix_packet(sets: bytes, *, length=None, secs=_EXPORT_SECS, sequence=3,
                  domain=7) -> bytes:
    total = 16 + len(sets)
    return struct.pack("!HHIII", 10, total if length is None else length,
                       secs, sequence, domain) + sets


#: src ip, dst ip, src port, dst port, protocol, packets, bytes, last/first switched.
_V9_FIELDS = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (2, 4), (1, 4), (21, 4), (22, 4)]
_V9_RECORD_LEN = 29


def _v9_data(src="192.0.2.5", dst="198.51.100.9", sport=51000, dport=443, proto=6,
             packets=12, octets=9000, last_ms=3_550_000, first_ms=3_500_000) -> bytes:
    return (_ip(src) + _ip(dst) + struct.pack("!HHB", sport, dport, proto)
            + struct.pack("!IIII", packets, octets, last_ms, first_ms))


# ── NetFlow v5 ─────────────────────────────────────────────────────────────────
def test_decode_v5_yields_flows_with_absolute_times():
    flows = decode_v5(_v5_packet([_v5_record()]), "192.0.2.9")
    assert len(flows) == 1
    flow = flows[0]
    assert flow["flow_version"] == "v5" and flow["exporter"] == "192.0.2.9"
    assert flow["src_ip"] == "10.0.0.1" and flow["dst_ip"] == "10.0.0.2"
    assert flow["src_port"] == 1234 and flow["dst_port"] == 80
    assert flow["protocol_number"] == 6 and flow["protocol"] == "tcp"
    assert flow["packets"] == 5 and flow["bytes"] == 400
    assert flow["flow_sequence"] == 7 and flow["flow_index"] == 0
    # sysUpTime-relative switch times resolved against the exporter's boot instant.
    # Mutation: drop the `boot +` term in `_abs_epoch` — these become 1970 dates.
    assert parse_ts(flow["end_time"]) == datetime.fromtimestamp(_BOOT + 3550, tz=_UTC)
    assert parse_ts(flow["start_time"]) == datetime.fromtimestamp(_BOOT + 3500, tz=_UTC)
    assert parse_ts(flow["export_time"]) == datetime.fromtimestamp(_EXPORT_SECS, tz=_UTC)
    assert flow["duration_ms"] == 50_000


def test_decode_v5_clamps_a_count_larger_than_the_packet():
    """The classic parse-confusion packet: a header claiming 30 records over one.

    Mutation: `count = min(count, _MAX_RECORDS)` (dropping `available`) — the
    record unpack then runs off the end of the datagram and raises struct.error.
    """
    packet = _v5_packet([_v5_record()], count=30)
    flows = decode_v5(packet)
    assert len(flows) == 1


def test_decode_v5_handles_a_truncated_packet():
    full = _v5_packet([_v5_record()])
    assert decode_v5(full[:30]) == []          # header intact, record cut short
    assert decode_v5(full[:10]) == []          # header itself cut short
    assert decode_v5(b"") == []


def test_decode_v5_numbers_identical_records_so_they_do_not_dedup_away():
    """Two byte-identical flows in one export must stay two rows.

    Mutation: delete the body of `_index` — both records then hash identically in
    `normalize.dedup_hash` and one is silently lost at insert.
    """
    flows = decode_v5(_v5_packet([_v5_record(), _v5_record()]))
    assert [f["flow_index"] for f in flows] == [0, 1]
    assert flows[0] != flows[1]


def test_decode_v5_falls_back_to_export_time_when_the_exporter_clock_is_unset():
    """A router that booted without NTP exports unix_secs ~ 0, which puts every
    flow before the epoch once sysUpTime is subtracted.

    Mutation: make `_sane` return `epoch` unconditionally — end_time becomes
    1969-12-31T23:59:10Z instead of the exporter's own (useless but honest)
    export time.
    """
    flows = decode_v5(_v5_packet([_v5_record()], secs=0))
    assert parse_ts(flows[0]["end_time"]) == datetime.fromtimestamp(0, tz=_UTC)
    assert flows[0]["end_time"] == flows[0]["export_time"]


def test_decode_v5_omits_a_flow_time_that_cannot_be_rescued():
    """When the export time is itself out of range there is nothing to fall back
    to, so the key is omitted rather than a garbage date stored.

    Mutation: return `fallback` from `_sane` without range-checking it — a
    year-2106 `end_time` appears.
    """
    flows = decode_v5(_v5_packet([_v5_record()], secs=2**32 - 1))
    assert "end_time" not in flows[0] and "start_time" not in flows[0]
    assert "export_time" in flows[0]         # what the device claimed is still kept


def test_decode_resolves_protocol_names_and_keeps_unknown_numbers():
    # Mutation: drop the `_PROTOCOLS.get(number, str(number))` default — an exotic
    # protocol loses `transport` entirely instead of carrying its IANA number.
    assert decode_v5(_v5_packet([_v5_record(proto=132)]))[0]["protocol"] == "sctp"
    assert decode_v5(_v5_packet([_v5_record(proto=17)]))[0]["protocol"] == "udp"
    assert decode_v5(_v5_packet([_v5_record(proto=253)]))[0]["protocol"] == "253"


def test_decode_v5_record_cap_is_enforced(monkeypatch):
    # Mutation: remove `_MAX_RECORDS` from the `min()` in decode_v5 — 3 flows.
    monkeypatch.setattr(nf, "_MAX_RECORDS", 2)
    flows = decode_v5(_v5_packet([_v5_record(), _v5_record(), _v5_record()]))
    assert len(flows) == 2


# ── NetFlow v9: templates ──────────────────────────────────────────────────────
def test_decode_v9_template_then_data():
    cache = TemplateCache()
    packet = _v9_packet(_set(0, _template(256, _V9_FIELDS))
                        + _set(256, _v9_data(), pad=3))
    flows = decode_v9(packet, cache, "203.0.113.4")
    assert cache.learned == 1 and len(cache) == 1
    assert len(flows) == 1
    flow = flows[0]
    assert flow["flow_version"] == "v9" and flow["observation_domain"] == 1
    assert flow["src_ip"] == "192.0.2.5" and flow["dst_ip"] == "198.51.100.9"
    assert flow["src_port"] == 51000 and flow["dst_port"] == 443
    assert flow["protocol"] == "tcp" and flow["packets"] == 12 and flow["bytes"] == 9000
    assert parse_ts(flow["end_time"]) == datetime.fromtimestamp(_BOOT + 3550, tz=_UTC)
    # The 3 trailing pad bytes are NOT a record. Mutation: in `_decode_data_set`
    # accept a short tail instead of breaking -> a second, garbage flow appears.
    assert len(flows) == 1


def test_decode_v9_data_before_its_template_is_dropped_and_counted():
    """Stated policy: an unknown template DROPS the data set and counts it — it is
    never buffered. The exporter's periodic template refresh is the recovery path.

    Mutation: delete `cache.unknown_drops += 1` — the counter assertion fails.
    """
    cache = TemplateCache()
    early = decode_v9(_v9_packet(_set(256, _v9_data())), cache, "203.0.113.4")
    assert early == [] and cache.unknown_drops == 1 and cache.learned == 0

    template_only = decode_v9(_v9_packet(_set(0, _template(256, _V9_FIELDS))),
                              cache, "203.0.113.4")
    assert template_only == []                        # the earlier data is NOT replayed
    later = decode_v9(_v9_packet(_set(256, _v9_data())), cache, "203.0.113.4")
    assert len(later) == 1 and cache.unknown_drops == 1


def test_decode_v9_templates_are_scoped_to_the_exporter():
    """Template ids are unique per exporter/domain only.

    Mutation: drop `exporter` from the cache key — the second exporter's data
    decodes against the first's template and yields a bogus flow.
    """
    cache = TemplateCache()
    decode_v9(_v9_packet(_set(0, _template(256, _V9_FIELDS))), cache, "10.1.1.1")
    other = decode_v9(_v9_packet(_set(256, _v9_data())), cache, "10.2.2.2")
    assert other == [] and cache.unknown_drops == 1


def test_decode_v9_ignores_the_header_record_count():
    """v9 `count` counts records, not FlowSets, and is attacker-controlled; the
    walk is driven by each FlowSet's own bounds-checked length.

    Mutation: bound the set walk by the header `count` — a lying count then
    truncates or over-runs a legitimate packet.
    """
    cache = TemplateCache()
    packet = _v9_packet(_set(0, _template(256, _V9_FIELDS))
                        + _set(256, _v9_data() + _v9_data()), count=0)
    assert len(decode_v9(packet, cache)) == 2


def test_decode_v9_stops_on_a_flowset_that_cannot_advance():
    """A FlowSet length below the 4-byte header would never move the cursor.

    Mutation: remove `set_len < _SET_HEADER.size` from the guard in `_walk_sets`
    — the walk spins forever (this test hangs rather than fails).
    """
    cache = TemplateCache()
    packet = _v9_packet(_set(0, _template(256, _V9_FIELDS))
                        + struct.pack("!HH", 256, 0)
                        + _set(256, _v9_data()))
    assert decode_v9(packet, cache) == []
    assert cache.learned == 1                          # the template before it did land


def test_decode_v9_stops_on_a_flowset_claiming_more_than_the_datagram():
    # Mutation: remove `offset + set_len > end` from the guard — the oversized set
    # is decoded from a short slice and the trailing real set is never reached.
    cache = TemplateCache()
    packet = _v9_packet(_set(0, _template(256, _V9_FIELDS))
                        + struct.pack("!HH", 256, 4096) + _v9_data())
    assert decode_v9(packet, cache) == []
    assert cache.learned == 1


def test_decode_v9_options_template_data_is_skipped_not_counted_unknown():
    """Options data carries exporter metadata, not flows.

    Mutation: stop setting `options=True` on the cached template — the options
    data set is decoded as flows and `options_skipped` stays 0.
    """
    cache = TemplateCache()
    options = struct.pack("!HHH", 257, 4, 4) + struct.pack("!HHHH", 1, 4, 34, 4)
    packet = _v9_packet(_set(1, options) + _set(257, b"\x00" * 8))
    assert decode_v9(packet, cache) == []
    assert cache.learned == 1 and cache.options_skipped == 1 and cache.unknown_drops == 0


def test_decode_v9_rejects_unusable_templates():
    """A 0-field template and a 0-byte record are both rejected, never cached: a
    0-byte record length would make `_decode_data_set` loop forever.

    Mutation: cache a template whose `_record_len` is 0 — `malformed` stays 0 and
    the data-set decode relies solely on the `nxt <= i` backstop.
    """
    cache = TemplateCache()
    decode_v9(_v9_packet(_set(0, struct.pack("!HH", 256, 0))), cache)
    assert cache.malformed == 1 and cache.learned == 0

    decode_v9(_v9_packet(_set(0, _template(257, [(8, 0)]))), cache)
    assert cache.malformed == 2 and cache.learned == 0
    assert decode_v9(_v9_packet(_set(257, b"\x00" * 8)), cache) == []


def test_decode_v9_rejects_a_template_with_too_many_fields():
    """A 300-field template is well-formed on the wire and would be cached without
    the field-count bound — the bound is what keeps one exporter from pinning
    megabytes of specifiers in the cache.

    Mutation: drop `field_count > _MAX_TEMPLATE_FIELDS` — `learned` becomes 1.
    (A bogus count with no body behind it is caught later by `_read_field_specs`,
    so the guard has to be tested with a body that really is that long.)
    """
    cache = TemplateCache()
    wide = _template(256, [(8, 4)] * 300)
    decode_v9(_v9_packet(_set(0, wide)), cache)
    assert cache.learned == 0 and cache.malformed == 1


def test_decode_v9_ignores_a_truncated_template_definition():
    # Mutation: let `_read_field_specs` return `complete=True` on a short body —
    # a template with fewer fields than declared is cached and mis-decodes data.
    cache = TemplateCache()
    truncated = struct.pack("!HH", 256, 4) + struct.pack("!HH", 8, 4)   # 1 of 4 specs
    decode_v9(_v9_packet(_set(0, truncated)), cache)
    assert cache.learned == 0 and cache.malformed == 1


# ── IPFIX ──────────────────────────────────────────────────────────────────────
def test_decode_ipfix_template_and_data():
    cache = TemplateCache()
    packet = _ipfix_packet(_set(2, _template(256, _V9_FIELDS))
                           + _set(256, _v9_data(src="203.0.113.7")))
    flows = decode_ipfix(packet, cache, "198.51.100.1")
    assert cache.learned == 1 and len(flows) == 1
    flow = flows[0]
    assert flow["flow_version"] == "ipfix" and flow["observation_domain"] == 7
    assert flow["src_ip"] == "203.0.113.7" and flow["protocol"] == "tcp"
    assert parse_ts(flow["export_time"]) == datetime.fromtimestamp(_EXPORT_SECS, tz=_UTC)
    # IPFIX carries no sysUpTime, so a sysUpTime-relative IE cannot be resolved and
    # must NOT be invented. Mutation: pass `boot=export_epoch` in decode_ipfix —
    # `end_time` appears, an hour wrong.
    assert "end_time" not in flow and "start_time" not in flow


def test_decode_ipfix_uses_absolute_timestamp_elements():
    # IE 153/152 = flowEnd/StartMilliseconds. Mutation: remove the `_END_IES` walk
    # from `_abs_epoch` — no end_time is derived at all.
    cache = TemplateCache()
    fields = [(8, 4), (12, 4), (153, 8), (152, 8)]
    end_ms, start_ms = (_EXPORT_SECS - 5) * 1000, (_EXPORT_SECS - 9) * 1000
    data = _ip("10.5.5.5") + _ip("10.6.6.6") + struct.pack("!QQ", end_ms, start_ms)
    flows = decode_ipfix(_ipfix_packet(_set(2, _template(256, fields))
                                       + _set(256, data)), cache)
    assert parse_ts(flows[0]["end_time"]) == datetime.fromtimestamp(_EXPORT_SECS - 5, tz=_UTC)
    assert flows[0]["duration_ms"] == 4000


def test_decode_ipfix_variable_length_and_enterprise_fields():
    """RFC 7011 variable-length encoding plus a vendor-private element.

    Mutation: treat 0xFFFF as a literal 65535-byte field — the record no longer
    fits and zero flows come back. Mutation 2: look an enterprise IE up in the
    IANA table anyway — `application_name` collides with the private field.
    """
    cache = TemplateCache()
    template = (struct.pack("!HH", 256, 3)
                + struct.pack("!HH", 8, 4)
                + struct.pack("!HH", 96, 0xFFFF)          # applicationName, variable
                + _enterprise_spec(1, 2, 12345))          # private IE 1, enterprise 12345
    data = _ip("10.9.9.9") + bytes([3]) + b"ssh" + struct.pack("!H", 4242)
    flows = decode_ipfix(_ipfix_packet(_set(2, template) + _set(256, data)), cache)
    assert len(flows) == 1
    assert flows[0]["src_ip"] == "10.9.9.9"
    assert flows[0]["application_name"] == "ssh"
    assert flows[0]["ie_12345_1"] == 4242
    assert "bytes" not in flows[0]                        # enterprise IE 1 != IANA IE 1


def test_decode_ipfix_header_length_bounds_the_message():
    """Bytes past the header's declared `length` are not part of the message.

    Mutation: `end = len(data)` instead of `min(length, len(data))` — the trailing
    data set is decoded too and 2 flows come back.
    """
    cache = TemplateCache()
    body = _set(2, _template(256, _V9_FIELDS)) + _set(256, _v9_data())
    trailing = _set(256, _v9_data(src="10.10.10.10"))
    packet = _ipfix_packet(body + trailing, length=16 + len(body))
    flows = decode_ipfix(packet, cache)
    assert len(flows) == 1 and flows[0]["src_ip"] == "192.0.2.5"


def test_decode_ipfix_survives_a_message_claiming_more_bytes_than_it_carries():
    # `length` says the message is complete but the datagram was cut mid-record:
    # decode what is whole, raise nothing, never over-read.
    cache = TemplateCache()
    body = _set(2, _template(256, _V9_FIELDS)) + _set(256, _v9_data())
    packet = _ipfix_packet(body)[:-7]
    assert decode_ipfix(packet, cache) == []
    assert cache.learned == 1                              # the template was complete


def test_decode_ipfix_rejects_a_bad_version_or_length():
    assert decode_ipfix(struct.pack("!HHIII", 10, 4, 1, 1, 1), TemplateCache()) == []
    assert decode_ipfix(b"\x00\x0a\x00", TemplateCache()) == []


# ── template cache bounds ──────────────────────────────────────────────────────
def test_template_cache_is_bounded_and_evicts_least_recently_used():
    """A hostile exporter cycling template ids (or spoofing source addresses, since
    the key includes the exporter) must not grow the cache without limit.

    Mutation: drop the `while len(...) > self.maxsize` loop in `put` — len is 3.
    """
    cache = TemplateCache(maxsize=2)
    fields = (TemplateField(8, 4),)
    for tid in (256, 257):
        cache.put(("e", 0, tid), Template(tid, fields, 4))
    cache.get(("e", 0, 256))                               # 256 is now the most recent
    cache.put(("e", 0, 258), Template(258, fields, 4))
    assert len(cache) == 2 and cache.evicted == 1
    assert cache.get(("e", 0, 257)) is None                # LRU victim
    assert cache.get(("e", 0, 256)) is not None
    assert cache.as_dict()["evicted"] == 1


def test_template_cache_maxsize_floor():
    cache = TemplateCache(maxsize=0)
    cache.put(("e", 0, 256), Template(256, (TemplateField(8, 4),), 4))
    assert len(cache) == 1                                 # never zero-sized


# ── dispatch + TCP framing ─────────────────────────────────────────────────────
def test_packet_version_and_decode_packet_dispatch():
    """Mutation: route v9 to `decode_v5` — the template is never learned, so
    `cache.learned` stays 0 and the IPFIX assertion below never sees its data."""
    assert packet_version(b"") == 0 and packet_version(b"\x00\x05") == 5
    cache = TemplateCache()
    assert len(decode_packet(_v5_packet([_v5_record()]), cache, "1.1.1.1")) == 1
    assert decode_packet(_v9_packet(_set(0, _template(256, _V9_FIELDS))), cache) == []
    assert cache.learned == 1                          # the v9 branch really ran
    ipfix = _ipfix_packet(_set(2, _template(256, _V9_FIELDS)) + _set(256, _v9_data()))
    assert len(decode_packet(ipfix, cache)) == 1
    assert decode_packet(struct.pack("!HH", 1, 0) + b"\x00" * 60, cache) == []
    assert decode_packet(b"", cache) == []


def test_decode_packet_rejects_an_oversized_datagram():
    """A UDP datagram cannot exceed 65535 bytes; anything longer reached us some
    other way and is refused before any decoding work is done.

    Mutation: drop `len(data) > _MAX_PACKET` from `decode_packet` — the padded
    packet decodes its one real flow instead of being refused.
    """
    padded = _v5_packet([_v5_record()]) + b"\x00" * nf._MAX_PACKET
    assert len(padded) > nf._MAX_PACKET
    assert decode_packet(padded, TemplateCache()) == []
    assert len(decode_v5(padded)) == 1                 # ...and it IS otherwise decodable


def test_decode_packet_works_without_a_cache_for_v5():
    assert len(decode_packet(_v5_packet([_v5_record()]))) == 1


def test_iter_ipfix_messages_frames_by_header_length():
    cache = TemplateCache()
    one = _ipfix_packet(_set(2, _template(256, _V9_FIELDS)))
    two = _ipfix_packet(_set(256, _v9_data()))
    messages, remainder = iter_ipfix_messages(one + two)
    assert messages == [one, two] and remainder == b""
    assert len(decode_ipfix(messages[0], cache)) == 0
    assert len(decode_ipfix(messages[1], cache)) == 1


def test_iter_ipfix_messages_holds_a_partial_message():
    one = _ipfix_packet(_set(2, _template(256, _V9_FIELDS)))
    partial = one[:9]
    messages, remainder = iter_ipfix_messages(one + partial)
    assert messages == [one] and remainder == partial      # held until the rest arrives
    assert iter_ipfix_messages(b"\x00\x0a\x00") == ([], b"\x00\x0a\x00")


def test_iter_ipfix_messages_drops_an_unframeable_stream():
    """No resync marker exists, so a non-IPFIX stream must not spin.

    Mutation: `continue` past a bad header instead of returning — the caller's
    buffer never shrinks and the connection loops on the same bytes.
    """
    assert iter_ipfix_messages(b"GET / HTTP/1.1\r\n\r\n") == ([], b"")
    assert iter_ipfix_messages(struct.pack("!HH", 10, 3) + b"\x00" * 20) == ([], b"")


def test_an_ipfix_options_template_is_learned_with_the_options_layout():
    """The IPFIX twin of `test_decode_v9_options_template_data_is_skipped_...`.

    `_learn_options_ipfix` and its dispatch at set id 3 were entirely uncovered, so
    both of these mutations passed the whole suite: stubbing the function out, and
    routing set id 3 to `_learn_templates` instead (which reads the Options body —
    id, field_count, scope_count — with the two-field FLOW layout, caches a garbage
    template without `options=True`, and then decodes its metadata as if it were
    flows, inventing src_ip/dst_port/bytes rows while `options_skipped` stays 0).

    nProbe, Cisco ASR 1000 and Juniper MX all send Options Templates.
    """
    cache = TemplateCache()
    # Options Template Set (id 3): template 258, 2 fields, 1 of them scope.
    body = struct.pack("!HHH", 258, 2, 1) + struct.pack("!HHHH", 145, 4, 41, 4)
    assert decode_ipfix(_ipfix_packet(_set(3, body)), cache) == []
    assert cache.learned == 1 and cache.malformed == 0

    cached = cache.get(("", 7, 258))
    assert cached is not None and cached.options is True     # the load-bearing flag
    assert [f.ie for f in cached.fields] == [145, 41]        # the OPTIONS layout, in order

    # its data set is skipped as metadata, not decoded into fabricated flows
    assert decode_ipfix(_ipfix_packet(_set(258, b"\x00" * 8)), cache) == []
    assert cache.options_skipped == 1 and cache.unknown_drops == 0


def test_redefining_a_live_template_is_counted_and_never_silent():
    """A template id whose shape changes under a live exporter.

    RFC 7011 makes a same-id redefinition legal, so it is applied — but it must not be
    INVISIBLE. Every subsequent data set for that id then routes to `options_skipped`,
    whose documented meaning is "this exporter sends metadata", so a spoofed 42-byte
    Options Template Set that blackholes a real exporter's flows read on /health as
    perfectly healthy: unknown_drops 0, malformed 0, evicted 0.
    """
    cache = TemplateCache()
    decode_ipfix(_ipfix_packet(_set(2, _template(256, _V9_FIELDS))), cache)
    assert len(decode_ipfix(_ipfix_packet(_set(256, _v9_data())), cache)) == 1
    assert cache.redefined == 0                      # nothing odd yet

    # the poisoning packet: template 256 redefined as an Options Template
    body = struct.pack("!HHH", 256, 2, 1) + struct.pack("!HHHH", 145, 4, 41, 4)
    decode_ipfix(_ipfix_packet(_set(3, body)), cache)

    assert cache.redefined == 1                      # THE signal that separates it
    assert decode_ipfix(_ipfix_packet(_set(256, _v9_data())), cache) == []
    assert cache.options_skipped == 1 and cache.unknown_drops == 0
    assert cache.as_dict()["redefined"] == 1         # and it reaches /health

    # the transposing variant — same id, same field count, IEs swapped — is caught too
    fresh = TemplateCache()
    decode_ipfix(_ipfix_packet(_set(2, _template(256, _V9_FIELDS))), fresh)
    swapped = [(12, 4), (8, 4)] + _V9_FIELDS[2:]
    decode_ipfix(_ipfix_packet(_set(2, _template(256, swapped))), fresh)
    assert fresh.redefined == 1


def test_a_redefinition_to_the_identical_shape_is_not_counted():
    """Exporters RE-SEND their templates periodically — Cisco's default is every 20
    packets / 30 minutes. Counting those would bury the real signal in noise."""
    cache = TemplateCache()
    for _ in range(5):
        decode_ipfix(_ipfix_packet(_set(2, _template(256, _V9_FIELDS))), cache)
    assert cache.learned == 5 and cache.redefined == 0


def test_the_tcp_handler_feeds_every_framed_message_to_ingest(monkeypatch):
    """`iter_ipfix_messages` is well covered but the handler that CONSUMES it was
    not, so replacing its ingest loop with `pass` — an IPFIX-over-TCP port that
    accepts connections and silently discards everything — passed the whole suite.
    The path is live: main.py passes `settings.netflow_tcp_port` to the constructor.
    """
    r = NetflowReceiver(host="127.0.0.1", udp_port=0, tcp_port=0, queue=None)
    seen: list = []
    monkeypatch.setattr(r, "ingest_packet", lambda msg, peer: seen.append((msg, peer)))

    one = _ipfix_packet(_set(2, _template(256, _V9_FIELDS)))
    two = _ipfix_packet(_set(256, _v9_data()))
    chunks = iter([one + two[:5], two[5:], b""])   # split mid-message on purpose

    class _Reader:
        async def read(self, n):
            return next(chunks)

    class _Writer:
        def get_extra_info(self, _):
            return ("198.51.100.7", 4739)

        def close(self):
            seen.append(("closed", None))

    asyncio.run(r._handle_tcp(_Reader(), _Writer()))

    assert [m for m, _ in seen[:2]] == [one, two]      # reassembled across reads
    assert {p for _, p in seen[:2]} == {"198.51.100.7"}
    assert seen[-1] == ("closed", None)                # and the writer is closed


def test_the_tcp_handler_drops_a_runaway_backlog_instead_of_growing(monkeypatch):
    r = NetflowReceiver(host="127.0.0.1", udp_port=0, tcp_port=0, queue=None)
    monkeypatch.setattr(r, "ingest_packet", lambda msg, peer: None)
    monkeypatch.setattr(nf, "_MAX_TCP_BUFFER", 128)
    # unframeable junk, so nothing is ever consumed out of the buffer
    chunks = iter([b"\x00\x0a\xff\xff" + b"x" * 200, b""])

    class _Reader:
        async def read(self, n):
            return next(chunks)

    class _Writer:
        def get_extra_info(self, _):
            return None

        def close(self):
            pass

    asyncio.run(r._handle_tcp(_Reader(), _Writer()))     # returns rather than spinning


# ── parser ─────────────────────────────────────────────────────────────────────
def _v5_events(**kw):
    flows = decode_v5(_v5_packet([_v5_record(**kw)]), "192.0.2.9")
    return list(netflow_parser.parse(json.dumps(flows)))


def test_parse_maps_a_decoded_v5_flow_onto_the_network_shape():
    events = _v5_events()
    assert len(events) == 1
    e = events[0]
    assert (e.vendor, e.product, e.log_type) == ("netflow", "v5", "netflow")
    assert e.src_ip == "10.0.0.1" and e.dst_ip == "10.0.0.2"
    assert e.src_port == 1234 and e.dst_port == 80
    assert e.protocol == "tcp" and e.bytes_total == 400
    assert e.host_name == "192.0.2.9"                      # exporter -> CIM `dvc`
    assert e.event_time == datetime.fromtimestamp(_BOOT + 3550, tz=_UTC)
    assert e.message == "tcp 10.0.0.1:1234 -> 10.0.0.2:80 5 pkts 400 bytes"
    # A flow is an observation, not a policy decision: `action` must stay NULL or
    # every allow/deny query over the Network model lies.
    assert e.action is None
    assert e.raw["flow_version"] == "v5"                   # raw kept verbatim


def test_parse_events_land_in_the_network_cim_model():
    """Mutation: change the parser's `log_type` to anything not in the shipped
    Network membership clause (e.g. "flowlog") — the tag disappears.
    """
    tags = match.tags_for(_v5_events()[0])
    assert "network" in tags


def test_parse_accepts_bare_array_wrapped_object_and_ndjson():
    flow = decode_v5(_v5_packet([_v5_record()]))[0]
    bare = json.dumps([flow])
    wrapped = json.dumps({"flows": [flow]})
    ndjson = json.dumps(flow) + "\n" + json.dumps(flow)
    for content, count in ((bare, 1), (wrapped, 1), (ndjson, 2)):
        events = list(netflow_parser.parse(content))
        # The src_ip assertion is the load-bearing one: without the "flows" wrapper
        # key `iter_json_records` yields the WRAPPER OBJECT itself, so a bare
        # `len(...) == 1` passes while every field is empty.
        # Mutation: drop "flows" from the `iter_json_records` call.
        assert len(events) == count
        assert all(e.src_ip == "10.0.0.1" and e.dst_port == 80 for e in events)


def test_parse_never_raises_on_garbage():
    assert list(netflow_parser.parse("")) == []
    assert list(netflow_parser.parse("not json at all")) == []
    assert list(netflow_parser.parse("[1, 2, 3]")) == []          # non-dict members
    events = list(netflow_parser.parse('[{"src_ip": "not-an-ip", "src_port": 99999}]'))
    assert len(events) == 1 and events[0].src_ip is None and events[0].src_port is None


def test_parse_falls_back_to_the_protocol_number_and_export_time():
    """A record with no name resolved upstream and no flow-time IE still produces a
    usable transport and event_time.

    Mutation: return None from `_protocol` when `protocol` is absent — `transport`
    is NULL for every such flow. Mutation 2: drop `export_time` from the
    `first(...)` chain — event_time is None and the pipeline stamps now().
    """
    flow = {"flow_version": "ipfix", "protocol_number": 132,
            "export_time": "2026-06-25T10:00:00.000Z", "src_ip": "10.0.0.1"}
    (event,) = list(netflow_parser.parse(json.dumps([flow])))
    assert event.protocol == "132"
    assert event.event_time == datetime(2026, 6, 25, 10, 0, tzinfo=_UTC)

    # A decoded record carries the resolved name, and it wins over the number.
    named = dict(flow, protocol="SCTP")
    (event,) = list(netflow_parser.parse(json.dumps([named])))
    assert event.protocol == "sctp"


def test_parse_sums_biflow_octets():
    # Mutation: read only `bytes` in `_bytes_total` — the reverse direction is lost.
    flow = {"flow_version": "ipfix", "bytes": 100, "out_bytes": 250}
    (event,) = list(netflow_parser.parse(json.dumps([flow])))
    assert event.bytes_total == 350


# ── receiver ───────────────────────────────────────────────────────────────────
class _FakeQueue:
    """Duck-typed stand-in: `ingest_packet` only ever calls `submit`."""

    def __init__(self):
        self.items = []

    def submit(self, item) -> bool:
        self.items.append(item)
        return True


@pytest.fixture
def wired(monkeypatch):
    """`PARSERS["netflow"]` is registered by the WIRE phase — `app/parsers/__init__.py`
    is a shared file this module does not own. Bind it for the duration of a test so the
    receiver's REAL `pipeline.parse_events` path (fmt validation included) runs now; the
    fixture becomes a no-op re-assignment once the wiring lands."""
    monkeypatch.setitem(pipeline.PARSERS, "netflow", netflow_parser)


def test_receiver_submits_decoded_flows_to_the_ingest_queue(wired):
    queue = _FakeQueue()
    receiver = NetflowReceiver(queue)
    receiver.ingest_packet(_v5_packet([_v5_record(), _v5_record(sport=2)]), "192.0.2.9")
    assert len(queue.items) == 1
    item = queue.items[0]
    # Mutation: submit with fmt "syslog" / source_type "syslog" — batches are then
    # attributed to the wrong source and the wrong parser on replay.
    assert item.fmt == "netflow" and item.source_type == "netflow"
    assert item.source_addr == "192.0.2.9" and item.vendor == "netflow"
    assert len(item.events) == 2
    assert item.events[0].host_name == "192.0.2.9"         # peer stamped as exporter
    assert receiver.stats.packets == 1 and receiver.stats.flows == 2


def test_receiver_keeps_templates_across_packets(wired):
    """The whole point of the receiver holding a TemplateCache.

    Mutation: build a fresh `TemplateCache()` inside `ingest_packet` — the data
    packet never decodes and nothing is submitted.
    """
    queue = _FakeQueue()
    receiver = NetflowReceiver(queue)
    receiver.ingest_packet(_v9_packet(_set(0, _template(256, _V9_FIELDS))), "10.0.0.1")
    assert queue.items == []
    receiver.ingest_packet(_v9_packet(_set(256, _v9_data())), "10.0.0.1")
    assert len(queue.items) == 1 and len(queue.items[0].events) == 1
    assert receiver.status()["templates"] == 1


def test_receiver_counts_undecodable_packets_without_submitting():
    queue = _FakeQueue()
    receiver = NetflowReceiver(queue)
    receiver.ingest_packet(b"", None)
    receiver.ingest_packet(b"random bytes that are not a flow export", None)
    assert queue.items == []
    assert receiver.stats.packets == 2 and receiver.stats.undecodable == 2
    assert receiver.stats.flows == 0


def test_receiver_reports_template_counters_on_status():
    queue = _FakeQueue()
    receiver = NetflowReceiver(queue, max_templates=8)
    receiver.ingest_packet(_v9_packet(_set(256, _v9_data())), "10.0.0.1")
    status = receiver.status()
    assert status["unknown_drops"] == 1 and status["packets"] == 1
    assert status["undecodable"] == 1 and status["templates"] == 0


def test_receiver_logs_a_parse_failure_only_once(monkeypatch):
    """An unregistered `fmt` raises on every single packet; logging each one would
    flood. Mutation: log unconditionally — `records` grows to 2.
    """
    queue, records = _FakeQueue(), []

    def boom(content, fmt):
        raise ValueError(f"unknown format: {fmt}")

    monkeypatch.setattr(nf.pipeline, "parse_events", boom)
    monkeypatch.setattr(nf.log, "exception", lambda *a, **k: records.append(a))
    receiver = NetflowReceiver(queue)
    for _ in range(2):
        receiver.ingest_packet(_v5_packet([_v5_record()]), "192.0.2.9")
    assert queue.items == []
    assert receiver.stats.parse_errors == 2 and len(records) == 1


def test_receiver_swallows_a_decoder_crash(monkeypatch):
    """A decoder bug must degrade to a dropped packet, never kill the receiver.

    Mutation: remove the try/except around `decode_packet` in `ingest_packet` —
    the exception escapes into `datagram_received` and the endpoint dies.
    """
    queue = _FakeQueue()

    def explode(data, cache, exporter):
        raise RuntimeError("decoder bug")

    monkeypatch.setattr(nf, "decode_packet", explode)
    receiver = NetflowReceiver(queue)
    receiver.ingest_packet(_v5_packet([_v5_record()]), "192.0.2.9")
    assert queue.items == [] and receiver.stats.undecodable == 1


def test_receiver_udp_protocol_forwards_the_peer_address(wired):
    queue = _FakeQueue()
    receiver = NetflowReceiver(queue)
    protocol = nf._UDPProtocol(receiver)
    protocol.datagram_received(_v5_packet([_v5_record()]), ("198.51.100.20", 2055))
    assert queue.items[0].source_addr == "198.51.100.20"
    protocol.datagram_received(_v5_packet([_v5_record()]), None)
    assert queue.items[1].source_addr is None
