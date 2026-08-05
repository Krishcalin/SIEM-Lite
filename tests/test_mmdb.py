# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Tests for the from-spec MaxMind DB reader — including the writer they need.

THERE IS NO GeoLite2 FILE ON THIS MACHINE and no network to fetch one, so the only
honest way to test a binary format reader is to emit the binary format. The first
third of this file is a minimal MMDB WRITER: control bytes, every data type, real
pointers at every size class, and a search trie numbered into fixed-size nodes. The
tests then round-trip through `app.enrich.mmdb`.

WHAT THAT PROVES AND WHAT IT DOES NOT. A round-trip through my own encoder proves the
offset chain is internally coherent — tree size, the 16-byte separator, the two
different pointer bases, the record arithmetic — and every hostile-input test is a
true measurement of the reader's behaviour. It CANNOT prove agreement with a file
MaxMind actually built. The formulas come from the published spec cross-checked
against both reference implementations, but the first integration test against a real
GeoLite2-Country.mmdb, with a handful of known IP -> country answers, is the gate
that this suite is not.

The writer is deliberately dumb: no data deduplication, no node compaction, no
aliases unless asked. That is a feature — a clever writer that happened to share a
bug with the reader would round-trip perfectly and prove nothing.
"""
from __future__ import annotations

import contextlib
import ipaddress
import os
import random
import re
import struct
import sys

import pytest

from app.enrich import mmdb
from app.enrich.mmdb import MMDBError, MMDBReader

MARKER = b"\xab\xcd\xefMaxMind.com"
SEPARATOR = b"\x00" * 16


@contextlib.contextmanager
def raises_mmdb(match: str):
    """pytest's own `raises(..., match=)` is NOT safe in this file. Use this instead.

    Every message the reader emits begins with the database's path, and pytest derives
    `tmp_path` from the name of the test asking for it. So inside
    `test_an_empty_file_is_refused...`, `match="empty"` matches the DIRECTORY NAME —
    and keeps matching with the empty-file check deleted from the module. Measured:
    two mutants survived the first mutation run for exactly this reason and nothing
    else.

    This strips the path and matches only the diagnosis, which also pins that every
    message names its file — the only context an operator gets for a binary blob.
    """
    with pytest.raises(MMDBError) as caught:
        yield caught
    message = str(caught.value)
    _, sep, detail = message.partition(".mmdb: ")
    assert sep, f"message does not name the database file: {message!r}"
    assert re.search(match, detail), f"{match!r} not found in {detail!r}"


# ═══════════════════════════════════════════════════════════════════════════════
# a minimal MMDB writer
# ═══════════════════════════════════════════════════════════════════════════════
def _ctrl(type_num: int, size: int) -> bytes:
    """Control byte, then the extended-type byte, then the extended-size bytes.

    That order is the spec's and it is not the order the field diagram suggests; a
    writer that emits the size extension before the extended type produces a file
    that decodes as a completely different type.
    """
    if type_num >= 8:
        first, ext = 0, bytes([type_num - 7])
    else:
        first, ext = type_num, b""
    if size < 29:
        sz, extra = size, b""
    elif size < 285:
        sz, extra = 29, bytes([size - 29])
    elif size < 65821:
        sz, extra = 30, struct.pack("!H", size - 285)
    else:
        sz, extra = 31, (size - 65821).to_bytes(3, "big")
    return bytes([(first << 5) | sz]) + ext + extra


def _str(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _ctrl(2, len(raw)) + raw


def _uint(value: int, type_num: int) -> bytes:
    # Leading zero bytes omitted, and zero is encoded as a zero-length payload.
    raw = b"" if value == 0 else value.to_bytes((value.bit_length() + 7) // 8, "big")
    return _ctrl(type_num, len(raw)) + raw


def _int32(value: int) -> bytes:
    raw = struct.pack("!i", value)
    if value >= 0:
        raw = raw.lstrip(b"\x00")          # a negative int32 always occupies 4 bytes
    return _ctrl(8, len(raw)) + raw


def _double(value: float) -> bytes:
    return _ctrl(3, 8) + struct.pack("!d", value)


def _float(value: float) -> bytes:
    return _ctrl(15, 4) + struct.pack("!f", value)


def _bool(value: bool) -> bytes:
    return _ctrl(14, 1 if value else 0)    # the value IS the size; there is no payload


def _blob(raw: bytes) -> bytes:
    return _ctrl(4, len(raw)) + raw


def _map(pairs: dict) -> bytes:
    out = _ctrl(7, len(pairs))
    for key, value in pairs.items():
        out += _str(key) + value
    return out


def _array(items) -> bytes:
    return _ctrl(11, len(items)) + b"".join(items)


def _pointer(value: int, force_class: int | None = None) -> bytes:
    """A pointer to `value`, an offset relative to the START OF THE DATA SECTION.

    `force_class` exists so a test can emit a class-3 pointer at a small offset: the
    classes overlap in what they CAN encode (class 3 reaches everything), they only
    tile in what the smallest encoding is. Without it, class 3 would need a 128MB
    fixture to reach and would go untested.
    """
    if force_class is None:
        force_class = (0 if value < 2048 else
                       1 if value < 526336 else
                       2 if value < 134744064 else 3)
    if force_class == 0:
        assert value < 2048, value
        return bytes([(1 << 5) | (0 << 3) | ((value >> 8) & 0x07), value & 0xFF])
    if force_class == 1:
        # 19 bits: the top 3 live in the control byte, the low 16 in the payload. The
        # masks are not decoration — without them `to_bytes` overflows the moment a
        # target passes 64KB, which is where a draft of this writer stopped working.
        v = value - 2048
        assert 0 <= v < (1 << 19), value
        return (bytes([(1 << 5) | (1 << 3) | ((v >> 16) & 0x07)])
                + (v & 0xFFFF).to_bytes(2, "big"))
    if force_class == 2:
        v = value - 526336
        assert 0 <= v < (1 << 27), value
        return (bytes([(1 << 5) | (2 << 3) | ((v >> 24) & 0x07)])
                + (v & 0xFFFFFF).to_bytes(3, "big"))
    return bytes([(1 << 5) | (3 << 3)]) + value.to_bytes(4, "big")


class _Trie:
    """A binary trie of two-slot nodes, numbered in creation order at emit time.

    A slot holds None (empty), another node (walk on), or a leaf tuple. Nothing is
    compacted, so the node count is larger than a real database's for the same
    networks — irrelevant here, and it keeps the numbering trivially checkable.
    """

    def __init__(self):
        self.root: list = [None, None]
        self.nodes: list[list] = [self.root]

    def _new(self) -> list:
        node: list = [None, None]
        self.nodes.append(node)
        return node

    def insert(self, bits, leaf) -> None:
        node = self.root
        for i, bit in enumerate(bits):
            if i == len(bits) - 1:
                node[bit] = leaf
                return
            nxt = node[bit]
            if not isinstance(nxt, list):
                nxt = self._new()
                node[bit] = nxt
            node = nxt

    def alias(self, bits, target: list) -> None:
        """Point the end of `bits` at an EXISTING node — how MaxMind maps
        ::ffff:0:0/96 and 2002::/16 back onto the ::/96 subtree."""
        node = self.root
        for i, bit in enumerate(bits):
            if i == len(bits) - 1:
                node[bit] = target
                return
            nxt = node[bit]
            if not isinstance(nxt, list):
                nxt = self._new()
                node[bit] = nxt
            node = nxt

    def walk(self, bits) -> list:
        node = self.root
        for bit in bits:
            node = node[bit]
        return node


def _bits(cidr: str) -> list[int]:
    net = ipaddress.ip_network(cidr)
    value = int(net.network_address)
    width = 128 if net.version == 6 else 32
    return [(value >> (width - 1 - i)) & 1 for i in range(net.prefixlen)]


def _emit_tree(trie: _Trie, record_size: int, node_count: int) -> bytes:
    numbering = {id(n): i for i, n in enumerate(trie.nodes)}

    def value_of(slot) -> int:
        if slot is None:
            return node_count                       # the designated "not found" value
        if isinstance(slot, list):
            return numbering[id(slot)]
        kind, payload = slot
        if kind == "raw":
            return payload                          # for tests that need a bad record
        # +16 because the separator is folded into the record value by the WRITER, so
        # the reader must not add it again.
        return node_count + 16 + payload

    out = bytearray()
    for node in trie.nodes:
        left, right = value_of(node[0]), value_of(node[1])
        if record_size == 24:
            out += left.to_bytes(3, "big") + right.to_bytes(3, "big")
        elif record_size == 28:
            # b3 is SHARED: high nibble = bits 27..24 of LEFT, low = same of RIGHT.
            middle = (((left >> 24) & 0x0F) << 4) | ((right >> 24) & 0x0F)
            out += ((left & 0xFFFFFF).to_bytes(3, "big") + bytes([middle])
                    + (right & 0xFFFFFF).to_bytes(3, "big"))
        else:
            out += left.to_bytes(4, "big") + right.to_bytes(4, "big")
    return bytes(out)


def _metadata(node_count: int, record_size: int, ip_version: int, *,
              database_type: str = "Test-City", build_epoch: int = 1700000000,
              major: int = 2, minor: int = 0, dedup_key: bool = False) -> bytes:
    """The metadata map. `dedup_key` adds a POINTER inside the metadata.

    That pointer is the only thing in the file that proves the reader uses
    marker+14 as the metadata base rather than the marker position — MaxMind
    deduplicates repeated strings this way, so a real file will contain them.
    """
    pairs = [
        ("node_count", _uint(node_count, 6)),
        ("record_size", _uint(record_size, 5)),
        ("ip_version", _uint(ip_version, 5)),
        ("database_type", _str(database_type)),
        ("binary_format_major_version", _uint(major, 5)),
        ("binary_format_minor_version", _uint(minor, 5)),
        ("build_epoch", _uint(build_epoch, 9)),
        ("languages", _array([_str("en")])),
    ]
    out = bytearray(_ctrl(7, len(pairs) + (1 if dedup_key else 0)))
    type_value_at = None
    for key, value in pairs:
        out += _str(key)
        if key == "database_type":
            type_value_at = len(out)
        out += value
    if dedup_key:
        out += _str("description")
        out += _ctrl(7, 1) + _str("en") + _pointer(type_value_at)
    return bytes(out)


def build_db(*, record_size: int = 28, ip_version: int = 6, alias_v4: bool = True,
             dedup_key: bool = False, node_count_override: int | None = None,
             extra_networks=(), data_prefix: bytes = b"") -> tuple[bytes, dict]:
    """A small but complete database. Returns (bytes, offsets/info)."""
    data = bytearray(data_prefix)
    info: dict = {"pad": len(data_prefix)}

    info["a"] = len(data)
    data += _map({
        "country": _map({"iso_code": _str("US"), "is_eu": _bool(False)}),
        "autonomous_system_number": _uint(15169, 6),
        "location": _map({"latitude": _double(37.751), "accuracy": _uint(1000, 5)}),
    })
    info["b"] = len(data)
    data += _pointer(info["a"])                       # a record that IS a pointer
    info["c"] = len(data)
    data += _map({
        "country": _map({"iso_code": _str("AU"), "is_eu": _bool(True)}),
        "autonomous_system_number": _uint(13335, 6),
        "tags": _array([_str("anycast"), _int32(-42), _float(1.5), _bool(True),
                        _array([_str("nested"), _array([])])]),
        "raw": _blob(b"\x01\x02\xff"),
        "empty_bytes": _blob(b""),
        "empty_string": _str(""),
        "empty_map": _map({}),
        "empty_array": _array([]),
        "zero": _uint(0, 6),
        "big64": _uint((1 << 63) + 5, 9),
        "big128": _uint((1 << 100) + 7, 10),
        "positive_int32": _int32(7),
        "unicode": _str("Köln — \U0001f30d"),
    })
    info["d"] = len(data)
    data += _map({"country": _map({"iso_code": _str("SE")}),
                  "autonomous_system_number": _uint(1299, 6)})
    info["long"] = len(data)
    data += _map({"short": _str("y" * 100),           # size extension form 29
                  "medium": _str("x" * 300)})         # size extension form 30

    trie = _Trie()
    v4 = [0] * 96 if ip_version == 6 else []
    trie.insert(v4 + _bits("8.8.8.0/24"), ("data", info["a"]))
    trie.insert(v4 + _bits("1.1.1.0/24"), ("data", info["b"]))
    trie.insert(v4 + _bits("9.9.9.9/32"), ("data", info["long"]))
    if ip_version == 6:
        trie.insert(_bits("2001:4860::/32"), ("data", info["c"]))
        trie.insert(_bits("2606:4700::/32"), ("data", info["d"]))
    for cidr, leaf in extra_networks:
        trie.insert((v4 if ipaddress.ip_network(cidr).version == 4 else []) + _bits(cidr),
                    leaf)
    if ip_version == 6 and alias_v4:
        trie.alias(_bits("::ffff:0:0/96"), trie.walk([0] * 96))

    node_count = len(trie.nodes)
    info["node_count"] = node_count
    tree = _emit_tree(trie, record_size, node_count)
    declared = node_count if node_count_override is None else node_count_override
    meta = _metadata(declared, record_size, ip_version, dedup_key=dedup_key)
    info["tree_size"] = len(tree)
    info["data_size"] = len(data)
    return bytes(tree) + SEPARATOR + bytes(data) + MARKER + meta, info


def one_record_db(data: bytes, record_size: int = 28) -> bytes:
    """The smallest valid file whose record for 8.8.8.0/24 is exactly `data`.

    Most hostile-input tests are "what does the decoder do with THESE bytes", so this
    keeps the tree out of the way — and, importantly, keeps every such test looking
    at a file that is valid in every respect except the one under test.
    """
    trie = _Trie()
    trie.insert([0] * 96 + _bits("8.8.8.0/24"), ("data", 0))
    tree = _emit_tree(trie, record_size, len(trie.nodes))
    return (tree + SEPARATOR + bytes(data) + MARKER
            + _metadata(len(trie.nodes), record_size, 6))


def write_db(tmp_path, blob: bytes, name: str = "test.mmdb") -> str:
    path = os.path.join(str(tmp_path), name)
    with open(path, "wb") as fh:
        fh.write(blob)
    return path


def reader_for(tmp_path, blob: bytes, name: str = "test.mmdb") -> MMDBReader:
    return MMDBReader(write_db(tmp_path, blob, name))


RECORD_SIZES = (24, 28, 32)


# ═══════════════════════════════════════════════════════════════════════════════
# the writer itself — if these are wrong every test below is meaningless
# ═══════════════════════════════════════════════════════════════════════════════
def test_the_writer_emits_the_three_record_widths_at_the_right_stride():
    """A node is record_size/4 bytes with no header and no padding. If the writer
    disagreed with the reader about the stride, every lookup would still 'work' on a
    one-node file and fail on everything real."""
    for record_size, node_bytes in ((24, 6), (28, 7), (32, 8)):
        trie = _Trie()
        trie.insert([0, 1], ("data", 0))
        tree = _emit_tree(trie, record_size, len(trie.nodes))
        assert len(tree) == len(trie.nodes) * node_bytes


def test_the_writer_puts_the_high_nibble_of_the_left_record_in_the_high_nibble():
    """Pins the writer's half of the 28-bit contract independently of the reader, so
    a matching pair of swapped nibbles cannot round-trip green."""
    trie = _Trie()
    trie.root[0] = ("raw", 0x9000000)
    trie.root[1] = ("raw", 0xC000000)
    tree = _emit_tree(trie, 28, 1)
    assert tree[3] == 0x9C


# ═══════════════════════════════════════════════════════════════════════════════
# metadata
# ═══════════════════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("record_size", RECORD_SIZES)
def test_metadata_round_trips(tmp_path, record_size):
    blob, info = build_db(record_size=record_size)
    with reader_for(tmp_path, blob) as r:
        assert r.metadata["record_size"] == record_size
        assert r.metadata["node_count"] == info["node_count"]
        assert r.metadata["database_type"] == "Test-City"
        assert r.metadata["build_epoch"] == 1700000000
        assert r.metadata["languages"] == ["en"]
        assert r.record_size == record_size and r.ip_version == 6
        assert r.node_count == info["node_count"]


def test_a_pointer_inside_the_metadata_resolves_against_the_metadata_base(tmp_path):
    """The metadata's pointer base is the byte AFTER the 14-byte marker, not the
    marker position. Using the marker itself shifts every metadata pointer by exactly
    14 bytes, which decodes a neighbouring field rather than raising — so only a file
    that actually contains a metadata pointer can catch it, and real MaxMind files do
    (that is how repeated strings are deduplicated)."""
    blob, _ = build_db(dedup_key=True)
    with reader_for(tmp_path, blob) as r:
        assert r.metadata["description"] == {"en": "Test-City"}


def test_the_last_marker_wins_not_the_first(tmp_path):
    """The marker bytes can occur inside the data section — nothing forbids it — so
    the search is a REVERSE find. A forward find would treat that occurrence as the
    start of the metadata and read the record bytes after it as a map."""
    blob, _ = build_db(data_prefix=_blob(MARKER + b"\x00" * 8))
    with reader_for(tmp_path, blob) as r:
        assert r.metadata["database_type"] == "Test-City"
        assert r.get("8.8.8.8")["country"]["iso_code"] == "US"


def test_the_fingerprint_is_stable_across_reopens_and_moves_with_the_build(tmp_path):
    blob, _ = build_db()
    with reader_for(tmp_path, blob, "one.mmdb") as a, \
            reader_for(tmp_path, blob, "two.mmdb") as b:
        assert a.fingerprint == b.fingerprint and len(a.fingerprint) == 16

    tree, sep, rest = blob.partition(SEPARATOR)
    data = rest[:rest.rfind(MARKER)]
    newer = tree + sep + data + MARKER + _metadata(
        len(tree) // 7, 28, 6, build_epoch=1800000000)
    with reader_for(tmp_path, newer, "three.mmdb") as c:
        assert c.fingerprint != a.fingerprint


# ═══════════════════════════════════════════════════════════════════════════════
# lookups
# ═══════════════════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("record_size", RECORD_SIZES)
def test_an_ipv4_address_resolves_through_the_v6_tree(tmp_path, record_size):
    with reader_for(tmp_path, build_db(record_size=record_size)[0]) as r:
        rec = r.get("8.8.8.8")
        assert rec["country"]["iso_code"] == "US"
        assert rec["autonomous_system_number"] == 15169
        assert r.get("8.8.8.255")["country"]["iso_code"] == "US"


@pytest.mark.parametrize("record_size", RECORD_SIZES)
def test_every_data_type_round_trips(tmp_path, record_size):
    with reader_for(tmp_path, build_db(record_size=record_size)[0]) as r:
        us = r.get("8.8.8.8")
        assert us["country"]["is_eu"] is False           # boolean, size 0
        assert round(us["location"]["latitude"], 3) == 37.751       # double
        assert us["location"]["accuracy"] == 1000                   # uint16

        au = r.get("2001:4860:4860::8888")
        assert au["country"]["is_eu"] is True            # boolean, size 1
        assert au["tags"][0] == "anycast"                # array + utf8
        assert au["tags"][1] == -42                      # int32, full 4 bytes, signed
        assert au["tags"][2] == 1.5                      # float
        assert au["tags"][3] is True
        assert au["tags"][4] == ["nested", []]           # array in array, empty array
        assert au["raw"] == b"\x01\x02\xff"              # bytes
        assert au["empty_bytes"] == b"" and au["empty_string"] == ""
        assert au["empty_map"] == {} and au["empty_array"] == []
        assert au["zero"] == 0                           # zero-length uint payload
        assert au["big64"] == (1 << 63) + 5              # uint64
        assert au["big128"] == (1 << 100) + 7            # uint128
        assert au["positive_int32"] == 7                 # short int32 is positive
        assert au["unicode"] == "Köln — \U0001f30d"

        long = r.get("9.9.9.9")
        assert long["short"] == "y" * 100                # size extension form 29
        assert long["medium"] == "x" * 300               # size extension form 30


def test_the_three_byte_size_extension(tmp_path):
    """Form 31 needs a >=65821-byte payload, so it gets its own fixture rather than
    bloating every other test's file by 64KB."""
    huge = "z" * 70000
    blob, info = build_db(data_prefix=_map({"pad": _str(huge)}))
    with reader_for(tmp_path, blob) as r:
        assert r._decode(r._data_start, r._data_start, r._data_end, 0)[0] == {"pad": huge}


@pytest.mark.parametrize("record_size", RECORD_SIZES)
def test_a_record_that_is_a_pointer_dereferences_to_the_same_value(tmp_path,
                                                                   record_size):
    with reader_for(tmp_path, build_db(record_size=record_size)[0]) as r:
        assert r.get("1.1.1.1") == r.get("8.8.8.8")


@pytest.mark.parametrize("record_size", RECORD_SIZES)
def test_an_address_with_no_record_is_a_miss_not_an_error(tmp_path, record_size):
    with reader_for(tmp_path, build_db(record_size=record_size)[0]) as r:
        assert r.get("10.1.2.3") is None                 # falls off an empty branch
        assert r.get("2404:6800::1") is None
        assert r.get("255.255.255.255") is None


def test_the_28_bit_middle_byte_is_split_high_nibble_left_low_nibble_right(tmp_path):
    """THE test for the single most error-prone line in the reader.

    0x9C is chosen deliberately: its nibbles DIFFER. Sixteen middle-byte values
    (0x00, 0x11, ... 0xFF) have equal nibbles and make a left/right swap completely
    invisible — an exhaustive check during the format recon caught the swap on only
    240 of 256 values for exactly that reason. A fixture built solely from small
    databases has middle byte 0x00 everywhere and would pass with this code inverted.
    """
    with reader_for(tmp_path, build_db(record_size=28)[0]) as r:
        assert r._read_node is mmdb.MMDBReader._node28
        r._buf = bytes([0xAA, 0xBB, 0xCC, 0x9C, 0xDD, 0xEE, 0xFF])
        # left  = 0x9 prepended to AA BB CC ; right = 0xC prepended to DD EE FF
        assert r._read_node(r, 0, 0) == 0x9AABBCC
        assert r._read_node(r, 0, 1) == 0xCDDEEFF


@pytest.mark.parametrize("record_size,expect_left,expect_right", [
    (24, 0xAABBCC, 0x9CDDEE),
    (32, 0xAABBCC9C, 0xDDEEFF00),
])
def test_the_24_and_32_bit_records_are_plain_big_endian(tmp_path, record_size,
                                                        expect_left, expect_right):
    """The three widths share no code, so a suite built only from 28-bit fixtures
    passes with these two totally broken, and vice versa."""
    with reader_for(tmp_path, build_db(record_size=record_size)[0]) as r:
        r._buf = bytes([0xAA, 0xBB, 0xCC, 0x9C, 0xDD, 0xEE, 0xFF, 0x00])
        assert r._read_node(r, 0, 0) == expect_left
        assert r._read_node(r, 0, 1) == expect_right


# ═══════════════════════════════════════════════════════════════════════════════
# pointers — all four size classes
# ═══════════════════════════════════════════════════════════════════════════════
def _pointer_db(target_at_least: int, force_class=None, record_size: int = 28):
    """A database whose record for 8.8.8.0/24 is a pointer to a target placed at or
    beyond `target_at_least` bytes into the data section."""
    data = bytearray()
    if target_at_least:
        data += _blob(b"\x00" * target_at_least)
    target = len(data)
    data += _map({"country": _map({"iso_code": _str("ZZ")}),
                  "autonomous_system_number": _uint(64500, 6)})
    ptr_at = len(data)
    data += _pointer(target, force_class)

    trie = _Trie()
    trie.insert([0] * 96 + _bits("8.8.8.0/24"), ("data", ptr_at))
    node_count = len(trie.nodes)
    tree = _emit_tree(trie, record_size, node_count)
    meta = _metadata(node_count, record_size, 6)
    return bytes(tree) + SEPARATOR + bytes(data) + MARKER + meta, target


@pytest.mark.parametrize("name,target_at_least,force_class", [
    ("class 0 — 11 bits, no addend", 0, None),
    ("class 1 — 19 bits + 2048", 3000, None),
    ("class 2 — 27 bits + 526336", 600000, None),
    ("class 3 — full 32 bits, low control bits ignored", 0, 3),
])
def test_every_pointer_size_class_resolves(tmp_path, name, target_at_least,
                                           force_class):
    """The addends are individually testable and must be individually tested. A
    fixture whose pointers are all class 0 (any small database) never touches 2048 or
    526336, so both constants can be off by one and every test still passes.

    Class 2 needs a target past 526336 bytes, hence the ~600KB fixture — the cheapest
    honest way to exercise that branch end to end.
    """
    blob, target = _pointer_db(target_at_least, force_class)
    with reader_for(tmp_path, blob) as r:
        assert r.get("8.8.8.8") == {"country": {"iso_code": "ZZ"},
                                    "autonomous_system_number": 64500}
        if target_at_least:
            assert target >= target_at_least


@pytest.mark.parametrize("size_class,low3,payload,expected", [
    (0, 0b000, b"\x00", 0),
    (0, 0b111, b"\xff", 2047),                       # class 0 tops out at 2**11-1
    (1, 0b000, b"\x00\x00", 2048),                   # ... and class 1 picks up there
    (1, 0b111, b"\xff\xff", 526335),
    (2, 0b000, b"\x00\x00\x00", 526336),             # ... and class 2 there
    (2, 0b111, b"\xff\xff\xff", 134744063),
    (3, 0b000, b"\x00\x00\x00\x00", 0),              # class 3 ignores the low bits
    (3, 0b111, b"\x00\x00\x00\x2a", 42),
    (3, 0b000, b"\xff\xff\xff\xff", 4294967295),
])
def test_the_pointer_classes_tile_without_gap_or_overlap(tmp_path, size_class, low3,
                                                         payload, expected):
    """Boundary values per class, read straight out of `_pointer`. This is what makes
    a one-off mutation of either addend fail loudly instead of shifting a pointer into
    a neighbouring field that still decodes."""
    with reader_for(tmp_path, build_db()[0]) as r:
        r._buf = payload
        size = (size_class << 3) | low3
        target, end = r._pointer(size, 0, 0, len(payload))
        assert target == expected
        assert end == size_class + 1                 # the cursor advances past the
        #                                              pointer FIELD, not the target


def test_a_map_key_may_itself_be_a_pointer(tmp_path):
    """MaxMind deduplicates the ~40 key names that repeat in every one of millions of
    records by storing the key as a POINTER to one shared string. So a key must go
    through the FULL decode path — a string fast path reads the pointer's control byte
    as a length and shreds the remainder of the map.

    No small synthetic database produces one of these by accident, which is why it is
    written by hand: without this test a key fast path survives the whole suite.
    """
    data = bytearray()
    key_at = len(data)
    data += _str("country")
    map_at = len(data)
    data += (_ctrl(7, 2)
             + _pointer(key_at) + _str("NL")          # key BY POINTER
             + _str("plain") + _str("v"))             # key inline, same map

    trie = _Trie()
    trie.insert([0] * 96 + _bits("8.8.8.0/24"), ("data", map_at))
    tree = _emit_tree(trie, 28, len(trie.nodes))
    blob = tree + SEPARATOR + bytes(data) + MARKER + _metadata(len(trie.nodes), 28, 6)
    with reader_for(tmp_path, blob) as r:
        assert r.get("8.8.8.8") == {"country": "NL", "plain": "v"}


def test_a_pointer_advances_the_cursor_past_the_field_not_the_target(tmp_path):
    """If the caller's offset were advanced to the end of the pointed-AT value, the
    rest of the enclosing map would decode from the wrong place — silently, as a
    plausible map, not as an error."""
    data = bytearray()
    target = 0
    data += _str("shared")
    pair_at = len(data)
    data += _map({"first": _pointer(target), "second": _str("after")})

    trie = _Trie()
    trie.insert([0] * 96 + _bits("8.8.8.0/24"), ("data", pair_at))
    tree = _emit_tree(trie, 28, len(trie.nodes))
    blob = tree + SEPARATOR + bytes(data) + MARKER + _metadata(len(trie.nodes), 28, 6)
    with reader_for(tmp_path, blob) as r:
        assert r.get("8.8.8.8") == {"first": "shared", "second": "after"}


# ═══════════════════════════════════════════════════════════════════════════════
# IPv4 in IPv6, and IPv4-only databases
# ═══════════════════════════════════════════════════════════════════════════════
def test_an_ipv4_only_database_does_not_take_the_96_zero_bit_walk(tmp_path):
    """In an ip_version==4 database the tree ROOT is the IPv4 root. Applying the ::/96
    walk anyway drives the node number straight off the end of the tree, turning every
    IPv4 lookup into a miss or a read of an unrelated subtree."""
    with reader_for(tmp_path, build_db(ip_version=4)[0]) as r:
        assert r._ipv4_start == 0
        assert r.get("8.8.8.8")["country"]["iso_code"] == "US"
        assert r.get("1.1.1.1") == r.get("8.8.8.8")


def test_an_ipv6_address_in_an_ipv4_database_is_a_miss_not_a_truncation(tmp_path):
    """The one thing that must NOT happen is silently taking the low 32 bits.

    The fixture declares 0.0.0.0/8 so this can actually DISCRIMINATE: a 128-bit walk
    of `::` through a 32-bit tree runs off the leading zeros straight into that
    record. Without the declaration both the correct reader and one that walks anyway
    return None, and the test passes with the guard deleted (measured).
    """
    blob, _ = build_db(ip_version=4, extra_networks=[("0.0.0.0/8", ("data", 0))])
    with reader_for(tmp_path, blob) as r:
        assert r.get("0.1.2.3") is not None          # the trap is armed
        assert r.get("::") is None                   # ... and not sprung
        assert r.get("2001:4860::1") is None
        assert r.get("::ffff:8.8.8.8") is None


def test_the_v4_start_node_is_the_96_zero_bit_walk(tmp_path):
    with reader_for(tmp_path, build_db()[0]) as r:
        node = 0
        for _ in range(96):
            if node >= r.node_count:
                break
            node = r._read_node(r, node, 0)
        assert r._ipv4_start == node != 0


def test_an_ipv4_mapped_address_matches_the_bare_address(tmp_path):
    """MaxMind's own files alias ::ffff:0:0/96 onto the ::/96 subtree, so the walk
    finds it directly."""
    with reader_for(tmp_path, build_db(alias_v4=True)[0]) as r:
        assert r.get("::ffff:8.8.8.8") == r.get("8.8.8.8") is not None


def test_a_file_without_the_alias_still_answers_the_mapped_form(tmp_path):
    """A database built without tree aliases misses on ::ffff:8.8.8.8 while answering
    8.8.8.8 correctly (measured against a synthetic pair during the format recon).
    The reader retries the miss as a 32-bit lookup, which is a deliberate departure
    from the reference readers — they return nothing. On an aliased file the first
    walk hits and the retry never runs, so it costs nothing there."""
    with reader_for(tmp_path, build_db(alias_v4=False)[0]) as r:
        assert r.get("8.8.8.8")["country"]["iso_code"] == "US"
        assert r.get("::ffff:8.8.8.8") == r.get("8.8.8.8")
        assert r.get("::ffff:10.1.2.3") is None      # a real miss is still a miss


# ═══════════════════════════════════════════════════════════════════════════════
# hostile input — none of these may hang, recurse without bound, or read out of range
# ═══════════════════════════════════════════════════════════════════════════════
def test_a_file_with_no_metadata_marker_is_refused(tmp_path):
    with raises_mmdb("marker"):
        MMDBReader(write_db(tmp_path, b"\x00" * 4096))


def test_an_empty_file_is_refused_before_it_reaches_mmap(tmp_path):
    """mmap.mmap() on a zero-byte file raises ValueError, which is neither MMDBError
    nor a message an operator can act on."""
    with raises_mmdb("empty"):
        MMDBReader(write_db(tmp_path, b""))


def test_a_file_smaller_than_the_marker_is_refused(tmp_path):
    with raises_mmdb("too small"):
        MMDBReader(write_db(tmp_path, b"\xab\xcd\xef"))


def test_a_missing_file_is_an_mmdberror_not_an_oserror(tmp_path):
    with pytest.raises(MMDBError):
        MMDBReader(os.path.join(str(tmp_path), "nope.mmdb"))


def test_a_marker_beyond_the_128kib_window_is_not_found(tmp_path):
    """The window is a real limit, not a robustness tweak: scanning the whole file
    would let a hostile database plant a fake metadata map far from the end and have
    it win, because the marker bytes can occur legitimately in the data section."""
    blob, _ = build_db()
    with raises_mmdb("marker"):
        MMDBReader(write_db(tmp_path, blob + b"\x00" * (128 * 1024)))


def test_a_truncated_file_is_refused_rather_than_half_read(tmp_path):
    blob, _ = build_db()
    with pytest.raises(MMDBError):
        MMDBReader(write_db(tmp_path, blob[:len(blob) // 2]))


def test_a_node_count_that_would_run_past_eof_is_refused(tmp_path):
    """Without this gate the tree reads wander into the data section, the metadata, or
    off the end — and Python's silent slice truncation means they return numbers
    rather than raising."""
    blob, info = build_db(node_count_override=0xFFFFFFF0)
    with raises_mmdb("overruns"):
        MMDBReader(write_db(tmp_path, blob))


@pytest.mark.parametrize("field,value,match", [
    ("record_size", 26, "record_size"),
    ("ip_version", 5, "ip_version"),
    ("binary_format_major_version", 3, "major version"),
])
def test_the_three_metadata_gates(tmp_path, field, value, match):
    blob, info = build_db()
    kwargs = {"record_size": 28, "ip_version": 6, "major": 2}
    key = {"record_size": "record_size", "ip_version": "ip_version",
           "binary_format_major_version": "major"}[field]
    kwargs[key] = value
    body = blob[:blob.rfind(MARKER)]
    bad = body + MARKER + _metadata(info["node_count"], **kwargs)
    with raises_mmdb(match):
        MMDBReader(write_db(tmp_path, bad))


def test_a_self_referential_pointer_is_refused(tmp_path):
    """A pointer pointing at itself, and a mutual pair, are both killed by the spec's
    'a pointer may not point to a pointer' rule — one check for the whole class,
    instead of a visited-set that would cost an allocation per record."""
    data = bytearray()
    at = len(data)
    data += _pointer(at)                       # offset 0 of the data section: itself
    trie = _Trie()
    trie.insert([0] * 96 + _bits("8.8.8.0/24"), ("data", at))
    tree = _emit_tree(trie, 28, len(trie.nodes))
    blob = tree + SEPARATOR + bytes(data) + MARKER + _metadata(len(trie.nodes), 28, 6)
    with reader_for(tmp_path, blob) as r:
        with raises_mmdb("pointer"):
            r.get("8.8.8.8")


def test_a_mutual_pointer_pair_is_refused(tmp_path):
    data = bytearray()
    first = len(data)
    data += _pointer(2, force_class=0)         # -> second, which is 2 bytes along
    second = len(data)
    data += _pointer(first, force_class=0)     # -> back to first
    assert second == 2
    trie = _Trie()
    trie.insert([0] * 96 + _bits("8.8.8.0/24"), ("data", first))
    tree = _emit_tree(trie, 28, len(trie.nodes))
    blob = tree + SEPARATOR + bytes(data) + MARKER + _metadata(len(trie.nodes), 28, 6)
    with reader_for(tmp_path, blob) as r:
        with raises_mmdb("pointer"):
            r.get("8.8.8.8")


def test_a_pointer_outside_the_data_section_is_refused(tmp_path):
    """Arithmetically well-formed, semantic nonsense: it would decode search-tree
    bytes or metadata bytes as a record."""
    data = bytearray()
    at = len(data)
    data += _pointer(10_000_000, force_class=3)
    trie = _Trie()
    trie.insert([0] * 96 + _bits("8.8.8.0/24"), ("data", at))
    tree = _emit_tree(trie, 28, len(trie.nodes))
    blob = tree + SEPARATOR + bytes(data) + MARKER + _metadata(len(trie.nodes), 28, 6)
    with reader_for(tmp_path, blob) as r:
        # "pointer target", not just "outside": `_decode` also rejects an out-of-range
        # offset on entry, so a laxer match passes with this check deleted — the
        # second line of defence answers, with a worse message.
        with raises_mmdb("pointer target"):
            r.get("8.8.8.8")


def test_a_record_resolving_into_the_16_byte_separator_is_refused(tmp_path):
    """Record values node_count+1 .. node_count+15 land inside the separator. They are
    the arithmetic proof that the writer's +16 is real, and a reader that omitted the
    range check would decode zero bytes as an empty map and call it a country."""
    trie = _Trie()
    trie.insert([0] * 96 + _bits("8.8.8.0/24"), ("raw", 0))     # patched below
    node_count = len(trie.nodes)
    trie.walk([0] * 96 + _bits("8.8.8.0/24")[:-1])[
        _bits("8.8.8.0/24")[-1]] = ("raw", node_count + 5)
    tree = _emit_tree(trie, 28, node_count)
    blob = (tree + SEPARATOR + bytes(_map({"x": _str("y")})) + MARKER
            + _metadata(node_count, 28, 6))
    with reader_for(tmp_path, blob) as r:
        with raises_mmdb("outside the data section"):
            r.get("8.8.8.8")


def test_a_cyclic_search_tree_terminates_and_reports_corruption(tmp_path):
    """A node whose record points back at itself. The walk is bounded by the ADDRESS
    WIDTH, not by tree structure, so it cannot hang — it exits after 32 steps with
    node < node_count, which is corruption and must NOT be folded into the miss
    encoding, or a broken file looks like an empty one."""
    node_count = 2
    tree = b"\x00" * (node_count * 8)              # every record points at node 0
    blob = (tree + SEPARATOR + bytes(_map({"x": _str("y")})) + MARKER
            + _metadata(node_count, 32, 6))
    with reader_for(tmp_path, blob) as r:
        with raises_mmdb("invalid node"):
            r.get("8.8.8.8")


def test_a_deeply_nested_payload_is_stopped_by_the_depth_cap(tmp_path):
    """1000 nested arrays is 2002 bytes. Without a cap CPython raises RecursionError
    at its default limit — catchable, but anything that raises the limit converts it
    into a C-stack overflow, which is a crashed ingest worker rather than an
    exception. A real GeoLite2 record nests 3-4 deep."""
    nested = _str("x")
    for _ in range(1000):
        nested = _array([nested])
    with reader_for(tmp_path, one_record_db(nested)) as r:
        with raises_mmdb("nested deeper"):
            r.get("8.8.8.8")


@pytest.mark.parametrize("name,header", [
    # map, size 31 -> 65821 + 0xFFFFFF pairs
    ("~16M map pairs", bytes([(7 << 5) | 31]) + b"\xff\xff\xff"),
    # array is an EXTENDED type: control byte 0, then 11-7 == 4, then the size bytes
    ("~16M array elements", bytes([(0 << 5) | 31, 4]) + b"\xff\xff\xff"),
    ("20 pairs in a file with 8 bytes left", bytes([(7 << 5) | 20])),
])
def test_a_forged_container_count_is_bounded_against_the_bytes_that_remain(
        tmp_path, name, header):
    """Size is an ELEMENT count, not a byte count, so a 3-byte extension buys ~16
    million pairs and 32 million recursive decodes. A depth cap does not help — the
    work is breadth — so the count is checked against the bytes actually left."""
    with reader_for(tmp_path, one_record_db(header + b"\x00" * 8)) as r:
        with raises_mmdb("declares"):
            r.get("8.8.8.8")


def test_an_extended_type_byte_that_resolves_below_8_is_refused(tmp_path):
    """The extended byte is biased by 7, so anything under 8 names a type that has a
    one-byte encoding already — a file emitting it is either corrupt or probing."""
    with reader_for(tmp_path, one_record_db(b"\x00\x00" + b"\x00" * 8)) as r:
        with raises_mmdb("not an extended type"):
            r.get("8.8.8.8")


@pytest.mark.parametrize("ctrl_byte,payload,match", [
    ((3 << 5) | 3, b"\x00" * 3, "double"),           # double must be exactly 8
    ((3 << 5) | 9, b"\x00" * 9, "double"),
    ((0 << 5) | 5, b"\x08" + b"\x00" * 5, "float"),  # extended float, must be exactly 4
    ((5 << 5) | 5, b"\x00" * 5, "unsigned"),         # uint16 in 5 bytes
    ((6 << 5) | 7, b"\x00" * 7, "unsigned"),         # uint32 in 7 bytes
    ((0 << 5) | 6, b"\x01" + b"\x00" * 6, "int32"),  # extended int32 in 6 bytes
])
def test_a_scalar_with_an_impossible_declared_size_is_refused(tmp_path, ctrl_byte,
                                                              payload, match):
    """Without these, `struct.error` escapes as itself — neither MMDBError nor
    ValueError — and blows straight through the caller's except clause. That happened
    to a draft of this reader during development, which is why each width is asserted
    rather than trusted."""
    with reader_for(tmp_path, one_record_db(bytes([ctrl_byte]) + payload)) as r:
        with raises_mmdb(match):
            r.get("8.8.8.8")


def test_a_payload_running_past_the_data_section_is_refused(tmp_path):
    """Python slicing past the end returns a SHORT slice with no error and
    `int.from_bytes` on it returns a wrong number with no error — so a size field
    pointing past EOF yields a plausible wrong country rather than a failure. This is
    the check that turns that into a visible one."""
    data = bytes([(2 << 5) | 28]) + b"ab"          # 28-byte string, 2 bytes present
    with reader_for(tmp_path, one_record_db(data)) as r:
        with raises_mmdb("past"):
            r.get("8.8.8.8")


def test_invalid_utf8_is_refused_as_mmdberror_not_unicodedecodeerror(tmp_path):
    data = bytes([(2 << 5) | 2]) + b"\xff\xfe"
    with reader_for(tmp_path, one_record_db(data)) as r:
        with raises_mmdb("UTF-8"):
            r.get("8.8.8.8")


@pytest.mark.parametrize("type_num", [12, 13])
def test_the_deprecated_types_are_refused_rather_than_guessed_at(tmp_path, type_num):
    """12 (data cache container) and 13 (end marker) have never appeared in any known
    database. Guessing at a layout nothing can be tested against is worse than
    refusing the file."""
    data = _ctrl(type_num, 0) + b"\x00" * 4
    with reader_for(tmp_path, one_record_db(data)) as r:
        with raises_mmdb("unsupported data type"):
            r.get("8.8.8.8")


def test_metadata_that_is_not_a_map_is_refused(tmp_path):
    blob, _ = build_db()
    bad = blob[:blob.rfind(MARKER)] + MARKER + _str("not a map")
    with raises_mmdb("not a map"):
        MMDBReader(write_db(tmp_path, bad))


def test_metadata_with_a_non_integer_node_count_is_refused(tmp_path):
    blob, info = build_db()
    bad_meta = _map({"node_count": _str("lots"), "record_size": _uint(28, 5),
                     "ip_version": _uint(6, 5), "database_type": _str("x"),
                     "binary_format_major_version": _uint(2, 5)})
    bad = blob[:blob.rfind(MARKER)] + MARKER + bad_meta
    with raises_mmdb("node_count"):
        MMDBReader(write_db(tmp_path, bad))


def test_no_single_byte_corruption_escapes_as_another_exception_type(tmp_path):
    """The catch-all guarantee, measured rather than asserted: flip one byte anywhere
    in a valid file and the reader either works, misses, or raises MMDBError. Nothing
    else — no struct.error, no IndexError, no UnicodeDecodeError, no RecursionError,
    and no hang.

    Deterministically seeded so a failure is reproducible; the offsets cover the tree,
    the separator, the data section and the metadata.
    """
    blob, _ = build_db()
    rng = random.Random(20260805)
    path = os.path.join(str(tmp_path), "fuzz.mmdb")
    survived = corrupted = 0
    for _ in range(400):
        buf = bytearray(blob)
        at = rng.randrange(len(buf))
        buf[at] ^= 1 << rng.randrange(8)
        with open(path, "wb") as fh:
            fh.write(bytes(buf))
        try:
            with MMDBReader(path) as r:
                for ip in ("8.8.8.8", "1.1.1.1", "9.9.9.9", "10.0.0.1",
                           "2001:4860:4860::8888", "::ffff:8.8.8.8"):
                    r.get(ip)
            survived += 1
        except MMDBError:
            corrupted += 1
    # Both outcomes must actually occur, or the test is proving nothing: all-survive
    # would mean the mutations never reached anything load-bearing.
    assert survived + corrupted == 400
    assert survived > 20 and corrupted > 20, (survived, corrupted)


# ═══════════════════════════════════════════════════════════════════════════════
# address handling at the seam
# ═══════════════════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("value", ["", "not-an-ip", "10.1.2.3.4", "999.1.1.1",
                                   "010.1.1.1", "8.8.8.8 ", "10.0.0.0/8",
                                   "::ffff:junk"])
def test_an_unparseable_address_is_a_miss_not_an_exception(tmp_path, value):
    """A malformed src_ip in a log line is an address this database says nothing
    about. Paying an exception per bad field on the ingest path buys nothing, and the
    caller already has to handle None. Note `10.0.0.0/8` is in this list: an
    ip_interface is NOT silently reduced to its network address — guessing what a
    prefix means is a policy call, not a coercion."""
    with reader_for(tmp_path, build_db()[0]) as r:
        assert r.get(value) is None


def test_an_ipaddress_object_is_accepted_because_psycopg_returns_one(tmp_path):
    """`events.src_ip` is `inet` and psycopg loads it as an IPv4Address, so the
    backfill hands the reader an object rather than a string.

    MEASURED: this works with or without the str() coercion, because
    `IPv4Address.__init__` already does `str(address)` on anything that is not an int
    or bytes. The test is here to PIN that, not to prove the coercion — if a future
    Python tightened that constructor, the geo backfill would silently store nothing
    while reporting scanned=N, updated=0, which is indistinguishable from success.
    """
    with reader_for(tmp_path, build_db()[0]) as r:
        assert r.get(ipaddress.ip_address("8.8.8.8")) == r.get("8.8.8.8") is not None
        assert r.get(ipaddress.ip_address("2001:4860:4860::8888")) is not None


def test_an_integer_is_not_reinterpreted_as_an_address(tmp_path):
    """`ipaddress.ip_address(8)` is 0.0.0.8 — so an int arriving here by mistake would
    silently look up an unrelated address. THIS is what the str() coercion is for.

    The fixture declares 0.0.0.0/8 so the two readings give different answers; against
    a database with no record there, both return None and the test proves nothing.
    """
    blob, _ = build_db(extra_networks=[("0.0.0.0/8", ("data", 0))])
    with reader_for(tmp_path, blob) as r:
        assert r.get("0.0.0.8") is not None           # the address ip_address(8) names
        assert r.get(8) is None


# ═══════════════════════════════════════════════════════════════════════════════
# lifecycle — the Windows hot-reload hazard
# ═══════════════════════════════════════════════════════════════════════════════
def test_close_releases_the_file_so_it_can_be_replaced(tmp_path):
    """THE reason `close()` is part of the contract. While a .mmdb is mapped,
    os.replace() over it fails on Windows with WinError 5 — so an operator
    side-loading an updated GeoLite2 file while LogOcean runs gets a hard failure
    rather than a new database, unless `geo.reload()` closes first."""
    blob, _ = build_db()
    path = write_db(tmp_path, blob, "live.mmdb")
    other = write_db(tmp_path, build_db(ip_version=4)[0], "new.mmdb")

    reader = MMDBReader(path)
    if sys.platform == "win32":
        with pytest.raises(PermissionError):
            os.replace(other, path)
    reader.close()
    os.replace(other, path)                       # must succeed once released
    with MMDBReader(path) as r:
        assert r.ip_version == 4


def test_close_is_idempotent(tmp_path):
    r = reader_for(tmp_path, build_db()[0])
    r.close()
    r.close()
    assert r.closed


def test_a_lookup_after_close_raises_rather_than_reading_freed_memory(tmp_path):
    r = reader_for(tmp_path, build_db()[0])
    r.close()
    with raises_mmdb("closed"):
        r.get("8.8.8.8")


def test_the_context_manager_closes_on_the_way_out(tmp_path):
    with reader_for(tmp_path, build_db()[0]) as r:
        assert r.get("8.8.8.8") is not None
    assert r.closed


def test_repr_names_the_file_and_the_build(tmp_path):
    """The only diagnostic available for a binary blob is what the reader says about
    it, so /health and the logs need this to be informative."""
    with reader_for(tmp_path, build_db()[0]) as r:
        text = repr(r)
        assert "Test-City" in text and "ipv6" in text and "nodes=" in text
    assert "closed" in repr(r)


def test_the_reader_does_not_reference_itself_so_the_mapping_dies_promptly(tmp_path):
    """The record unpacker is stored UNBOUND and called as `read_node(self, ...)`.
    Storing the bound method would make the reader reference itself, so a dropped
    reader would keep its mapping — and therefore its Windows file lock — until a gc
    pass rather than until the last reference went away."""
    with reader_for(tmp_path, build_db()[0]) as r:
        assert r._read_node in (mmdb.MMDBReader._node24, mmdb.MMDBReader._node28,
                                mmdb.MMDBReader._node32)
        assert not hasattr(r._read_node, "__self__")


# ── pointer fan-out: the bound `_MAX_DEPTH` cannot provide ────────────────────
def _fanout_data(branching: int, levels: int) -> bytes:
    """A chain of maps, each holding `branching` pointers that ALL name the SAME next
    map. Tiny on disk, exponential to decode.

    This is not a shape a legitimate writer produces, which is why it is built by hand
    here rather than through `build_db`.
    """
    # `one_record_db` always points its record at data-section offset 0, and the chain
    # has to be built leaf-first — so offset 0 holds a two-byte class-0 pointer that is
    # patched to name the root once the root's offset is known.
    data = bytearray(bytes(2))
    leaf = len(data)
    data += _str("x")                    # the shared leaf every chain ends at
    child = leaf
    for _ in range(levels):
        off = len(data)
        blob = bytearray(_ctrl(7, branching))          # a map of N pairs
        for i in range(branching):
            blob += _str(chr(0x61 + i))                # one-character key
            blob += _pointer(child)                    # value -> the SHARED child
        data += blob
        child = off
        assert child < 2048, "fixture outgrew the class-0 pointer range"
    root = _pointer(child)
    assert len(root) == 2, "the placeholder reserved exactly two bytes"
    data[0:2] = root
    return bytes(data)


def test_pointer_fanout_is_bounded_by_total_work_not_just_depth(tmp_path):
    """DEPTH IS NOT THE BOUND. `_MAX_DEPTH` stops a deep record and the `in_pointer`
    rule stops a pointer CHAIN, but neither stops BREADTH REACHED THROUGH POINTERS —
    and `in_pointer` is cleared the moment a target turns out to be a map, because
    `_container` recurses without it.

    A pointer costs two bytes and its target is decoded afresh on every dereference,
    so a map of B pointers all naming one shared map of B pointers multiplies work by
    B per level while the file grows by ~3B bytes. A level costs two of the depth
    budget, so 32 levels fit under `_MAX_DEPTH`.

    MEASURED before the budget existed: this exact fixture at B=8, 20 levels is 851
    bytes and did not return in 30 seconds — on the ingest write path, where
    `IngestQueue._flush` discards the whole buffered group when a write never
    completes. With the budget it is refused in under a second.
    """
    blob = one_record_db(_fanout_data(branching=8, levels=20))
    assert len(blob) < 4096, "the point is that the attack is CHEAP to deliver"
    with reader_for(tmp_path, blob) as r:
        with raises_mmdb("decoded more than"):
            r.get("8.8.8.8")


def test_an_honest_record_is_nowhere_near_the_field_budget(tmp_path):
    """The budget must not be reachable by anything real. A GeoIP2 record is tens of
    values; this is a deliberately fat one."""
    fat = _map({f"k{i}": _map({"a": _str("x"), "b": _uint(i, 5),
                               "c": _array([_str("y"), _str("z")])})
                for i in range(40)})
    with reader_for(tmp_path, one_record_db(fat)) as r:
        rec = r.get("8.8.8.8")
    assert len(rec) == 40 and rec["k7"]["b"] == 7


def test_the_budget_is_per_lookup_not_per_reader(tmp_path):
    """One MMDBReader is shared by every ingest worker. A budget carried on the
    instance would be a data race, and would let one lookup's cost fail another's
    honest record — so repeated lookups must each get a full allowance."""
    blob, _ = build_db()
    with reader_for(tmp_path, blob) as r:
        first = r.get("8.8.8.8")
        assert first is not None, "the fixture must resolve, or this proves nothing"
        for _ in range(500):
            assert r.get("8.8.8.8") == first
