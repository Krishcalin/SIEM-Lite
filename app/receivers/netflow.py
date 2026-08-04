# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""NetFlow v5 / v9 / IPFIX receiver (Phase 2 onboarding breadth).

Shape mirrors :mod:`app.receivers.syslog`: an asyncio datagram endpoint (plus an
optional TCP server for IPFIX-over-TCP), decoded records handed to the async
ingest queue, and never a direct database call.

WHAT IS PURE AND WHY
--------------------
`decode_packet(data, cache, exporter)` is a pure function from BYTES to a list of
flow dicts — no sockets, no clock, no settings. Everything below it (`decode_v5`,
`decode_v9`, `decode_ipfix`, `_learn_templates`, `_read_record`,
`iter_ipfix_messages`) is likewise module-level and pure, so the whole decoder is
unit-tested with `struct.pack`-built fixture packets and no network. The receiver
class is the thin layer: read datagram -> decode -> `pipeline.parse_events` ->
`queue.submit`.

TEMPLATES (the v9 / IPFIX problem)
----------------------------------
A v9/IPFIX data record is a bare byte blob: its layout lives in a Template
FlowSet that arrives *separately* on the same socket and is re-sent periodically
(Cisco's default template refresh is every 20 packets / 30 minutes). So the
decoder is stateful across packets even though each decode step is pure over
(bytes, cache).

Policy for a data record whose template has not been seen: **DROP IT AND COUNT
IT** (`TemplateCache.unknown_drops`). Buffering was rejected deliberately —
buffered bytes are unattributable (we cannot know their length, so we cannot even
tell how many records are in the set), the buffer would have to be bounded and
evicted anyway, and the exporter's own template refresh re-sends the same flows'
successors within one refresh interval. Losing the first few seconds of a new
exporter is the accepted cost; unbounded memory holding undecodable bytes is not.

The cache is bounded (`TemplateCache(maxsize)`, LRU by last use) so a hostile or
misconfigured exporter cycling template IDs — or spoofing thousands of source
addresses, since the key includes the exporter — cannot grow it without limit.

HOSTILE-INPUT RULES (every one of these is a test)
-------------------------------------------------
* The v5 header's record `count` is NEVER trusted: it is clamped to what the
  datagram actually carries. A packet claiming 30 records in 48 bytes yields one.
* The v9 header's `count` is ignored entirely; FlowSets are walked by their own
  `length`, which is bounds-checked against the datagram on every step.
* The IPFIX header's `length` is clamped to the real datagram size, so a message
  claiming more than it carries is decoded as truncated rather than over-read.
* A set/FlowSet whose declared length is < 4 stops the walk — that is the
  infinite-loop guard, and so is `nxt <= i` in `_decode_data_set`.
* A template with 0 fields, a 0-byte record length, more than
  `_MAX_TEMPLATE_FIELDS` fields or a record longer than `_MAX_TEMPLATE_LEN` is
  rejected, never cached: a 0-byte record would otherwise loop forever.
* Records decoded from one packet are capped at `_MAX_RECORDS`.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import struct
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from .. import pipeline
from ..streaming import IngestItem, IngestQueue

log = logging.getLogger("logocean")

#: Parser format key the decoded flows are fed to (app/parsers/netflow.py).
FORMAT = "netflow"
SOURCE_TYPE = "netflow"
VENDOR = "netflow"

# ── wire structures ────────────────────────────────────────────────────────────
_V5_HEADER = struct.Struct("!HHIIIIBBH")                     # 24 bytes
_V5_RECORD = struct.Struct("!4s4s4sHHIIIIHHBBBBHHBBH")       # 48 bytes
_V9_HEADER = struct.Struct("!HHIIII")                        # 20 bytes
_IPFIX_HEADER = struct.Struct("!HHIII")                      # 16 bytes
_SET_HEADER = struct.Struct("!HH")                           # set/flowset id + length
_SPEC = struct.Struct("!HH")                                 # field specifier
_U32 = struct.Struct("!I")
_TRIPLE = struct.Struct("!HHH")

# ── bounds (every one of these is a DoS guard, not a style choice) ─────────────
_MAX_PACKET = 65535            # a UDP datagram cannot exceed this
_MAX_RECORDS = 4096            # flow records decoded from one packet
_MAX_TEMPLATE_FIELDS = 255     # field specifiers in one template
_MAX_TEMPLATE_LEN = 8192       # bytes one data record may claim
_MAX_TEMPLATES = 4096          # cached templates, LRU-evicted beyond this
_MAX_TCP_BUFFER = 1024 * 1024  # IPFIX-over-TCP backlog before the stream is reset
_MIN_TIME = 0.0                # 1970-01-01 — a flow time outside this window is
_MAX_TIME = 4102444800.0       # 2100-01-01   nonsense and falls back to export time

# ── IANA Information Elements (v9 field types share the numbering) ────────────
_UINT, _IPV4, _IPV6, _MAC, _STR = "uint", "ipv4", "ipv6", "mac", "str"

#: ie -> (raw key, decoder kind). Keys are lower_snake_case scalars at the TOP
#: level of `raw` on purpose: CIM membership and fields read jsonb byte-exactly
#: and cannot descend into arrays (app/cim/match.py).
_FIELDS: dict[int, tuple[str, str]] = {
    1: ("bytes", _UINT), 2: ("packets", _UINT), 3: ("flows", _UINT),
    4: ("protocol_number", _UINT), 5: ("tos", _UINT), 6: ("tcp_flags", _UINT),
    7: ("src_port", _UINT), 8: ("src_ip", _IPV4), 9: ("src_mask", _UINT),
    10: ("input_snmp", _UINT), 11: ("dst_port", _UINT), 12: ("dst_ip", _IPV4),
    13: ("dst_mask", _UINT), 14: ("output_snmp", _UINT), 15: ("next_hop", _IPV4),
    16: ("src_as", _UINT), 17: ("dst_as", _UINT),
    21: ("last_switched", _UINT), 22: ("first_switched", _UINT),
    23: ("out_bytes", _UINT), 24: ("out_packets", _UINT),
    27: ("src_ip", _IPV6), 28: ("dst_ip", _IPV6),
    29: ("src_mask", _UINT), 30: ("dst_mask", _UINT),
    31: ("flow_label", _UINT), 32: ("icmp_type_code", _UINT),
    56: ("src_mac", _MAC), 58: ("src_vlan", _UINT), 59: ("dst_vlan", _UINT),
    60: ("ip_version", _UINT), 61: ("direction", _UINT), 62: ("next_hop", _IPV6),
    80: ("dst_mac", _MAC), 82: ("interface_name", _STR),
    95: ("application_id", _UINT), 96: ("application_name", _STR),
    136: ("flow_end_reason", _UINT), 148: ("flow_id", _UINT),
    150: ("flow_start_seconds", _UINT), 151: ("flow_end_seconds", _UINT),
    152: ("flow_start_ms", _UINT), 153: ("flow_end_ms", _UINT),
    154: ("flow_start_us", _UINT), 155: ("flow_end_us", _UINT),
    156: ("flow_start_ns", _UINT), 157: ("flow_end_ns", _UINT),
    176: ("icmp_type", _UINT), 177: ("icmp_code", _UINT),
    210: ("_pad", _UINT),                       # paddingOctets — decoded then dropped
    239: ("biflow_direction", _UINT),
}

_PROTOCOLS = {1: "icmp", 2: "igmp", 6: "tcp", 17: "udp", 41: "ipv6", 47: "gre",
              50: "esp", 51: "ah", 58: "ipv6-icmp", 89: "ospf", 103: "pim",
              112: "vrrp", 132: "sctp"}

#: Absolute flow-time IEs, most precise last checked first, with their divisor.
_START_IES = (("flow_start_seconds", 1.0), ("flow_start_ms", 1e3),
              ("flow_start_us", 1e6), ("flow_start_ns", 1e9))
_END_IES = (("flow_end_seconds", 1.0), ("flow_end_ms", 1e3),
            ("flow_end_us", 1e6), ("flow_end_ns", 1e9))


# ── value decoding ─────────────────────────────────────────────────────────────
def _decode_value(kind: str, raw: bytes):
    """One field's bytes -> a JSON scalar, or None when the length is wrong."""
    if not raw:
        return None
    if kind == _UINT:
        return int.from_bytes(raw, "big")
    if kind in (_IPV4, _IPV6):
        try:
            return str(ipaddress.ip_address(raw))
        except ValueError:
            return None
    if kind == _MAC:
        return ":".join(f"{b:02x}" for b in raw) if len(raw) == 6 else None
    return raw.decode("utf-8", "replace").rstrip("\x00").strip() or None


def _decode_unknown(raw: bytes):
    """An IE we have no mapping for. Kept rather than dropped so no data is lost:
    a short field reads as an integer, a long one as lower-case hex."""
    if not raw:
        return None
    return int.from_bytes(raw, "big") if len(raw) <= 8 else raw.hex()


def _proto_name(number) -> Optional[str]:
    if not isinstance(number, int):
        return None
    return _PROTOCOLS.get(number, str(number))


def _iso(epoch: float) -> Optional[str]:
    try:
        dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _abs_epoch(rec: dict, ies, uptime_key: str, boot: Optional[float]) -> Optional[float]:
    """Absolute epoch seconds for a flow edge, from whichever timestamp IE the
    template carried. Falls back to the sysUpTime-relative v5/v9 field, which is
    only meaningful when the exporter's boot time is known."""
    for key, divisor in ies:
        value = rec.get(key)
        if isinstance(value, int):
            return value / divisor
    value = rec.get(uptime_key)
    if isinstance(value, int) and boot is not None:
        return boot + value / 1000.0
    return None


def _sane(epoch: Optional[float], fallback: float) -> Optional[float]:
    """Clamp a computed flow time. A bogus sysUpTime can put a v5 flow in 1904;
    rather than store that, fall back to the packet's export time."""
    if epoch is None:
        return None
    if _MIN_TIME <= epoch <= _MAX_TIME:
        return epoch
    return fallback if _MIN_TIME <= fallback <= _MAX_TIME else None


def _stamp_times(rec: dict, boot: Optional[float], export_epoch: float) -> None:
    """Add ISO `export_time` / `start_time` / `end_time` (+ `duration_ms`)."""
    exported = _iso(export_epoch)
    if exported:
        rec["export_time"] = exported
    start = _sane(_abs_epoch(rec, _START_IES, "first_switched", boot), export_epoch)
    end = _sane(_abs_epoch(rec, _END_IES, "last_switched", boot), export_epoch)
    started = _iso(start) if start is not None else None
    ended = _iso(end) if end is not None else None
    if started:
        rec["start_time"] = started
    if ended:
        rec["end_time"] = ended
    if start is not None and end is not None and end >= start:
        rec["duration_ms"] = int(round((end - start) * 1000))


def _finish(fields: dict, meta: dict, boot: Optional[float], export_epoch: float) -> dict:
    """Merge exporter metadata into one decoded record and derive its times."""
    rec = dict(meta)
    rec.update(fields)
    name = _proto_name(rec.get("protocol_number"))
    if name:
        rec["protocol"] = name
    _stamp_times(rec, boot, export_epoch)
    return rec


def _index(flows: list[dict]) -> list[dict]:
    """Number the records of one packet. Two byte-identical flows in the same
    export would otherwise collapse into one row — `normalize.dedup_hash` digests
    `raw`, and every other field of such a pair is equal."""
    for i, flow in enumerate(flows):
        flow["flow_index"] = i
    return flows


# ── templates ──────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class TemplateField:
    """One field specifier: IANA IE id, wire length (0xFFFF = variable), and the
    enterprise number for a vendor-private IPFIX element (0 = IANA)."""
    ie: int
    length: int
    enterprise: int = 0


@dataclass(frozen=True)
class Template:
    """A cached v9/IPFIX template. `length` is the fixed record size, or -1 when
    the template contains a variable-length field. `options` marks an Options
    Template — its data sets carry exporter metadata, not flows, so they are
    skipped rather than counted as an unknown template."""
    template_id: int
    fields: tuple[TemplateField, ...]
    length: int
    options: bool = False


class TemplateCache:
    """Bounded LRU store keyed by (exporter, observation domain, template id).

    The exporter is part of the key because template ids are only unique per
    exporter/domain; that also means a spoofed source address mints new keys,
    which is exactly why the cache has a hard `maxsize` and evicts least-recently
    used entries instead of growing.
    """

    def __init__(self, maxsize: int = _MAX_TEMPLATES):
        self.maxsize = max(int(maxsize), 1)
        self._templates: "OrderedDict[tuple[str, int, int], Template]" = OrderedDict()
        self.learned = 0        # templates accepted
        self.evicted = 0        # templates pushed out by the size bound
        self.malformed = 0      # template definitions rejected as unusable
        self.unknown_drops = 0  # data sets dropped for want of their template
        self.options_skipped = 0
        self.redefined = 0      # a cached template REPLACED by a different shape

    def put(self, key: tuple[str, int, int], template: Template) -> None:
        """Cache a template, counting a genuine redefinition as its own event.

        RFC 7011 §8 makes template ids unique per observation domain regardless of
        type, so an Options Template legitimately REPLACES a data template with the
        same id — separating the key spaces would be the wrong fix and would leave a
        withdrawn template alive to decode garbage.

        What was wrong is that the replacement was INVISIBLE. Every subsequent data
        set for that id then routed to `options_skipped`, a counter whose documented
        meaning is "this exporter sends metadata" — so a redefinition that blackholes a
        real exporter's flows reads on /health as healthy, with `unknown_drops` and
        `malformed` both 0. That matters because NetFlow/IPFIX over UDP has no
        authentication and the key is just the source address: a spoofed 42-byte
        Options Template Set redefining a live id deletes that exporter's traffic, and
        redefining it with two IEs transposed silently swaps src and dst on every flow
        instead. `redefined` is the signal that separates either from normal operation;
        keeping the collector port reachable only from real exporters remains the
        network-level control, since the protocol offers none.
        """
        previous = self._templates.get(key)
        if previous is not None and (previous.options != template.options
                                     or previous.fields != template.fields):
            self.redefined += 1
            log.warning(
                "netflow: template %d from %s (domain %d) redefined — %s -> %s, "
                "%d field(s) -> %d; flows decoded with the old shape are unaffected, "
                "but a redefinition nobody made is how a spoofed exporter blackholes "
                "or transposes a real one",
                key[2], key[0], key[1],
                "options" if previous.options else "data",
                "options" if template.options else "data",
                len(previous.fields), len(template.fields))
        self._templates[key] = template
        self._templates.move_to_end(key)
        while len(self._templates) > self.maxsize:
            self._templates.popitem(last=False)
            self.evicted += 1

    def get(self, key: tuple[str, int, int]) -> Optional[Template]:
        template = self._templates.get(key)
        if template is not None:
            self._templates.move_to_end(key)
        return template

    def __len__(self) -> int:
        return len(self._templates)

    def as_dict(self) -> dict:
        return {"templates": len(self._templates), "learned": self.learned,
                "evicted": self.evicted, "malformed": self.malformed,
                "unknown_drops": self.unknown_drops,
                "options_skipped": self.options_skipped,
                "redefined": self.redefined}


def _record_len(fields) -> int:
    """Fixed record length for a field list, or -1 if any field is variable."""
    if any(f.length == 0xFFFF for f in fields):
        return -1
    return sum(f.length for f in fields)


def _read_field_specs(body: bytes, i: int, count: int,
                      ipfix: bool) -> tuple[list, int, bool]:
    """Read `count` field specifiers. Returns (fields, offset, complete)."""
    fields: list[TemplateField] = []
    for _ in range(count):
        if i + _SPEC.size > len(body):
            return fields, i, False
        ie, length = _SPEC.unpack_from(body, i)
        i += _SPEC.size
        enterprise = 0
        if ipfix and ie & 0x8000:
            if i + _U32.size > len(body):
                return fields, i, False
            enterprise = _U32.unpack_from(body, i)[0]
            i += _U32.size
            ie &= 0x7FFF
        fields.append(TemplateField(ie, length, enterprise))
    return fields, i, True


def _learn_templates(body: bytes, cache: TemplateCache, exporter: str,
                     domain: int, *, ipfix: bool) -> None:
    """Cache every template in a Template (Flow)Set."""
    i = 0
    while i + _SPEC.size <= len(body):
        template_id, field_count = _SPEC.unpack_from(body, i)
        i += _SPEC.size
        if template_id < 256:
            return                                   # 0 = set padding; 1-255 reserved
        if field_count == 0 or field_count > _MAX_TEMPLATE_FIELDS:
            cache.malformed += 1
            return                                   # cannot resync inside the set
        fields, i, complete = _read_field_specs(body, i, field_count, ipfix)
        if not complete:
            cache.malformed += 1
            return
        length = _record_len(fields)
        if length == 0 or length > _MAX_TEMPLATE_LEN:
            cache.malformed += 1                     # a 0-byte record would loop forever
            continue
        cache.put((exporter, domain, template_id), Template(template_id, tuple(fields), length))
        cache.learned += 1


def _learn_options_v9(body: bytes, cache: TemplateCache, exporter: str, domain: int) -> None:
    """NetFlow v9 Options Template FlowSet: id, scope BYTE length, option BYTE
    length, then (scope + option) / 4 field specifiers."""
    i = 0
    while i + _TRIPLE.size <= len(body):
        template_id, scope_len, option_len = _TRIPLE.unpack_from(body, i)
        i += _TRIPLE.size
        if template_id < 256:
            return
        total = scope_len + option_len
        if total == 0 or scope_len % 4 or option_len % 4 or total > _MAX_TEMPLATE_LEN:
            cache.malformed += 1
            return
        count = total // _SPEC.size
        if count > _MAX_TEMPLATE_FIELDS:
            cache.malformed += 1
            return
        fields, i, complete = _read_field_specs(body, i, count, ipfix=False)
        if not complete:
            cache.malformed += 1
            return
        cache.put((exporter, domain, template_id),
                  Template(template_id, tuple(fields), _record_len(fields), options=True))
        cache.learned += 1


def _learn_options_ipfix(body: bytes, cache: TemplateCache, exporter: str, domain: int) -> None:
    """IPFIX Options Template Set: id, total field count, scope field count."""
    i = 0
    while i + _TRIPLE.size <= len(body):
        template_id, field_count, scope_count = _TRIPLE.unpack_from(body, i)
        i += _TRIPLE.size
        if template_id < 256:
            return
        if field_count == 0 or field_count > _MAX_TEMPLATE_FIELDS or scope_count > field_count:
            cache.malformed += 1
            return
        fields, i, complete = _read_field_specs(body, i, field_count, ipfix=True)
        if not complete:
            cache.malformed += 1
            return
        cache.put((exporter, domain, template_id),
                  Template(template_id, tuple(fields), _record_len(fields), options=True))
        cache.learned += 1


# ── data records ───────────────────────────────────────────────────────────────
def _read_record(body: bytes, i: int, template: Template) -> tuple[Optional[dict], int]:
    """Decode ONE data record at `i`. Returns (fields, next offset), or
    (None, i) when the remaining bytes are shorter than the record."""
    out: dict = {}
    for field in template.fields:
        length = field.length
        if length == 0xFFFF:                         # RFC 7011 variable length
            if i >= len(body):
                return None, i
            length = body[i]
            i += 1
            if length == 255:                        # 255 escapes to a 2-byte length
                if i + 2 > len(body):
                    return None, i
                length = int.from_bytes(body[i:i + 2], "big")
                i += 2
        if i + length > len(body):
            return None, i
        raw = body[i:i + length]
        i += length
        known = _FIELDS.get(field.ie) if field.enterprise == 0 else None
        if known is None:
            key = (f"ie_{field.enterprise}_{field.ie}" if field.enterprise
                   else f"ie_{field.ie}")
            value = _decode_unknown(raw)
        else:
            key, kind = known
            if key == "_pad":
                continue
            value = _decode_value(kind, raw)
        if value is not None:
            out[key] = value
    return out, i


def _decode_data_set(body: bytes, template: Template, meta: dict,
                     boot: Optional[float], export_epoch: float,
                     budget: int) -> list[dict]:
    """Split one data set into records. Trailing bytes too short for a whole
    record are the set's 4-byte alignment padding and are ignored."""
    flows: list[dict] = []
    i = 0
    while len(flows) < budget and i < len(body):
        fields, nxt = _read_record(body, i, template)
        if fields is None or nxt <= i:               # short tail, or a 0-byte template
            break
        flows.append(_finish(fields, meta, boot, export_epoch))
        i = nxt
    return flows


def _meta(version: str, exporter: str, sequence: int,
          domain: Optional[int] = None) -> dict:
    meta = {"flow_version": version, "flow_sequence": sequence}
    if exporter:
        meta["exporter"] = exporter
    if domain is not None:
        meta["observation_domain"] = domain
    return meta


# ── per-version decoders (pure) ────────────────────────────────────────────────
def decode_v5(data: bytes, exporter: str = "") -> list[dict]:
    """Decode a NetFlow v5 datagram. The header's record `count` is clamped to
    what the datagram actually carries, so a packet claiming more records than it
    contains yields only the real ones."""
    if len(data) < _V5_HEADER.size:
        return []
    (version, count, uptime_ms, secs, nsecs,
     sequence, engine_type, engine_id, sampling) = _V5_HEADER.unpack_from(data, 0)
    if version != 5:
        return []
    available = (len(data) - _V5_HEADER.size) // _V5_RECORD.size
    count = min(count, available, _MAX_RECORDS)
    export_epoch = secs + min(nsecs, 999_999_999) / 1e9
    boot = export_epoch - uptime_ms / 1000.0
    meta = _meta("v5", exporter, sequence)
    meta["engine_type"] = engine_type
    meta["engine_id"] = engine_id
    meta["sampling_mode"] = sampling >> 14
    meta["sampling_interval"] = sampling & 0x3FFF
    flows: list[dict] = []
    for n in range(count):
        offset = _V5_HEADER.size + n * _V5_RECORD.size
        (src, dst, next_hop, in_if, out_if, packets, octets, first_ms, last_ms,
         src_port, dst_port, _pad1, tcp_flags, protocol, tos,
         src_as, dst_as, src_mask, dst_mask, _pad2) = _V5_RECORD.unpack_from(data, offset)
        fields = {
            "src_ip": _decode_value(_IPV4, src), "dst_ip": _decode_value(_IPV4, dst),
            "next_hop": _decode_value(_IPV4, next_hop),
            "src_port": src_port, "dst_port": dst_port,
            "protocol_number": protocol, "packets": packets, "bytes": octets,
            "tcp_flags": tcp_flags, "tos": tos,
            "input_snmp": in_if, "output_snmp": out_if,
            "src_as": src_as, "dst_as": dst_as,
            "src_mask": src_mask, "dst_mask": dst_mask,
            "first_switched": first_ms, "last_switched": last_ms,
        }
        flows.append(_finish({k: v for k, v in fields.items() if v is not None},
                             meta, boot, export_epoch))
    return _index(flows)


def decode_v9(data: bytes, cache: TemplateCache, exporter: str = "") -> list[dict]:
    """Decode a NetFlow v9 datagram against `cache`, learning any templates it
    carries. The header's `count` (records, not FlowSets) is deliberately IGNORED
    — FlowSets are walked by their own bounds-checked `length`."""
    if len(data) < _V9_HEADER.size:
        return []
    version, _count, uptime_ms, secs, sequence, domain = _V9_HEADER.unpack_from(data, 0)
    if version != 9:
        return []
    export_epoch = float(secs)
    boot = export_epoch - uptime_ms / 1000.0
    meta = _meta("v9", exporter, sequence, domain)
    return _index(_walk_sets(data, _V9_HEADER.size, len(data), cache, exporter,
                             domain, meta, boot, export_epoch, ipfix=False))


def decode_ipfix(data: bytes, cache: TemplateCache, exporter: str = "") -> list[dict]:
    """Decode an IPFIX (v10) message. The header `length` covers the whole
    message; it is clamped to the real byte count, so a message claiming more
    than it carries is read as truncated instead of over-read."""
    if len(data) < _IPFIX_HEADER.size:
        return []
    version, length, secs, sequence, domain = _IPFIX_HEADER.unpack_from(data, 0)
    if version != 10 or length < _IPFIX_HEADER.size:
        return []
    end = min(length, len(data))
    export_epoch = float(secs)
    meta = _meta("ipfix", exporter, sequence, domain)
    # IPFIX has no sysUpTime, so there is no boot instant: a stray sysUpTime-based
    # IE cannot be resolved and is left as the raw integer it is.
    return _index(_walk_sets(data, _IPFIX_HEADER.size, end, cache, exporter,
                             domain, meta, None, export_epoch, ipfix=True))


def _walk_sets(data: bytes, offset: int, end: int, cache: TemplateCache,
               exporter: str, domain: int, meta: dict, boot: Optional[float],
               export_epoch: float, *, ipfix: bool) -> list[dict]:
    """Shared v9/IPFIX set walk. Stops on any length that would run past `end` or
    fail to advance, keeping whatever decoded cleanly before it."""
    template_set = 2 if ipfix else 0
    options_set = 3 if ipfix else 1
    flows: list[dict] = []
    while offset + _SET_HEADER.size <= end and len(flows) < _MAX_RECORDS:
        set_id, set_len = _SET_HEADER.unpack_from(data, offset)
        if set_len < _SET_HEADER.size or offset + set_len > end:
            break                                    # truncated or nonsense length
        body = data[offset + _SET_HEADER.size:offset + set_len]
        if set_id == template_set:
            _learn_templates(body, cache, exporter, domain, ipfix=ipfix)
        elif set_id == options_set:
            if ipfix:
                _learn_options_ipfix(body, cache, exporter, domain)
            else:
                _learn_options_v9(body, cache, exporter, domain)
        elif set_id >= 256:
            template = cache.get((exporter, domain, set_id))
            if template is None:
                cache.unknown_drops += 1             # policy: drop, count, wait for refresh
            elif template.options:
                cache.options_skipped += 1           # exporter metadata, not a flow
            else:
                flows.extend(_decode_data_set(body, template, meta, boot, export_epoch,
                                              _MAX_RECORDS - len(flows)))
        offset += set_len
    return flows[:_MAX_RECORDS]


def packet_version(data: bytes) -> int:
    """The version word of a NetFlow/IPFIX datagram, or 0 if there isn't one."""
    return struct.unpack_from("!H", data, 0)[0] if len(data) >= 2 else 0


def decode_packet(data: bytes, cache: Optional[TemplateCache] = None,
                  exporter: str = "") -> list[dict]:
    """Decode ONE datagram into flow dicts. Pure over (bytes, cache): no clock,
    no socket, no settings. An unknown version, an empty or oversized packet all
    yield an empty list rather than raising."""
    if not data or len(data) > _MAX_PACKET:
        return []
    version = packet_version(data)
    if version == 5:
        return decode_v5(data, exporter)
    if version == 9:
        return decode_v9(data, cache if cache is not None else TemplateCache(), exporter)
    if version == 10:
        return decode_ipfix(data, cache if cache is not None else TemplateCache(), exporter)
    return []


def iter_ipfix_messages(buffer: bytes) -> tuple[list[bytes], bytes]:
    """Frame an IPFIX-over-TCP byte stream (RFC 7011 §10.4: the 16-byte header's
    `length` covers the whole message). Returns complete messages + remainder.

    A stream whose next header is not a plausible IPFIX header is unframeable —
    there is no resync marker to hunt for — so the backlog is dropped (remainder
    ``b""``) rather than retried forever.
    """
    messages: list[bytes] = []
    while len(buffer) >= _IPFIX_HEADER.size:
        version, length = struct.unpack_from("!HH", buffer, 0)
        if version != 10 or length < _IPFIX_HEADER.size:
            return messages, b""
        if len(buffer) < length:
            break
        messages.append(buffer[:length])
        buffer = buffer[length:]
    return messages, buffer


# ── receiver ───────────────────────────────────────────────────────────────────
@dataclass
class NetflowStats:
    packets: int = 0        # datagrams / TCP messages received
    flows: int = 0          # events submitted to the ingest queue
    undecodable: int = 0    # packets that yielded no flow at all
    parse_errors: int = 0   # decoded flows the parser refused

    def as_dict(self) -> dict:
        return {"packets": self.packets, "flows": self.flows,
                "undecodable": self.undecodable, "parse_errors": self.parse_errors}


class NetflowReceiver:
    """Owns the NetFlow UDP endpoint (and an optional IPFIX TCP server).

    Host/ports are constructor arguments rather than `settings` reads so the
    receiver is constructible in a unit test with no global configuration; the
    app lifespan passes the `NETFLOW_*` settings in.
    """

    def __init__(self, queue: IngestQueue, host: str = "0.0.0.0", udp_port: int = 2055,
                 tcp_port: int = 0, max_templates: int = _MAX_TEMPLATES):
        self.queue = queue
        self.host = host
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self.templates = TemplateCache(max_templates)
        self.stats = NetflowStats()
        self._udp_transport = None
        self._tcp_server: Optional[asyncio.AbstractServer] = None

    def ingest_packet(self, data: bytes, peer: Optional[str]) -> None:
        """Decode one datagram and hand its flows to the ingest queue."""
        self.stats.packets += 1
        try:
            flows = decode_packet(data, self.templates, peer or "")
        except Exception:  # noqa: BLE001 — a malformed packet must never kill the receiver
            self.stats.undecodable += 1
            log.debug("netflow: undecodable packet from %s", peer, exc_info=True)
            return
        if not flows:
            self.stats.undecodable += 1
            return
        try:
            events = list(pipeline.parse_events(json.dumps(flows), FORMAT))
        except Exception:  # noqa: BLE001
            self.stats.parse_errors += 1
            if self.stats.parse_errors == 1:   # once only: an unregistered fmt would flood
                log.exception("netflow: parsing decoded flows failed (format %r)", FORMAT)
            return
        if events:
            self.stats.flows += len(events)
            self.queue.submit(IngestItem(events, FORMAT, SOURCE_TYPE, peer, VENDOR))

    def status(self) -> dict:
        """Counters for /health: receiver totals plus the template cache."""
        return {**self.stats.as_dict(), **self.templates.as_dict()}

    async def _handle_tcp(self, reader: asyncio.StreamReader,
                          writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        peer_ip = peer[0] if peer else None
        buffer = b""
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                buffer += data
                messages, buffer = iter_ipfix_messages(buffer)
                for message in messages:
                    self.ingest_packet(message, peer_ip)
                if len(buffer) > _MAX_TCP_BUFFER:   # runaway sender — drop the backlog
                    buffer = b""
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        if self.udp_port:
            self._udp_transport, _ = await loop.create_datagram_endpoint(
                lambda: _UDPProtocol(self), local_addr=(self.host, self.udp_port))
            log.info("netflow UDP listening on %s:%d", self.host, self.udp_port)
        if self.tcp_port:
            self._tcp_server = await asyncio.start_server(
                self._handle_tcp, self.host, self.tcp_port)
            log.info("netflow (IPFIX) TCP listening on %s:%d", self.host, self.tcp_port)

    async def stop(self) -> None:
        if self._udp_transport is not None:
            self._udp_transport.close()
            self._udp_transport = None
        if self._tcp_server is not None:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
            self._tcp_server = None


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, receiver: NetflowReceiver):
        self._receiver = receiver

    def datagram_received(self, data: bytes, addr) -> None:
        self._receiver.ingest_packet(data[:_MAX_PACKET], addr[0] if addr else None)
