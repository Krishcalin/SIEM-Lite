# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""A MaxMind DB (.mmdb) reader written from the published binary format spec.

Pure stdlib — `struct`, `mmap`, `ipaddress`. That is the entire point: `maxminddb`
is not installed and never will be, because this project ships one dependency list
and a geo lookup is not worth adding to it. The format is stable, versioned in the
file itself (`binary_format_major_version`), and small enough to implement honestly
in ~400 lines.

WHAT THIS IS NOT. It is not a GeoIP policy layer. It returns whatever map the
database stores for an address and stops there; deciding that `country.iso_code`
beats `registered_country.iso_code`, or that an ASN of 0 means "unknown", belongs to
`app/enrich/geo.py`. Keeping that split is what lets this module be tested purely as
bytes-in / values-out.

THE FILE LAYOUT, since none of it is discoverable from a header:

    [search tree][16 zero bytes][data section][14-byte marker][metadata map]

Nothing states where anything ends. The metadata is the only self-locating structure
— found by scanning BACKWARDS from EOF for the marker — and it declares `node_count`
and `record_size`, from which the tree size, and therefore the data section start,
are derived. Get one of those wrong and the reader does not crash; it decodes a
different, plausible-looking field. Every offset formula here is commented with which
of the two bases it uses, because mixing them is off-by-exactly-16 and silent.

DEGRADATION CONTRACT. Everything that can go wrong with a file raises `MMDBError`
and nothing else — no `struct.error`, no `UnicodeDecodeError`, no `IndexError`. The
caller sits on the ingest path (`db._row`), so it needs one exception type to catch,
and a corrupt database must cost an event its geo CONTEXT, never the event. A lookup
that simply has no answer returns None instead, which is a different thing and is
deliberately not an error.

HOSTILE INPUT. A .mmdb is operator-supplied and may be corrupt or malicious. Python
slicing past EOF returns a SHORT slice with no error, and `int.from_bytes` on it
returns a wrong number with no error — so every payload read is bounds-checked before
the slice, not after. Recursion is capped. Declared element counts are bounded
against the bytes that actually remain. Pointers may not point at pointers, nor
outside the data section.

WINDOWS. While a file is mmap'd, `os.replace()` over it fails with WinError 5 and
`os.remove()` with WinError 32 (measured on this project's own platform). An operator
side-loading an updated database while LogOcean is running therefore CANNOT overwrite
the file in place — `close()` must run first. `geo.reload()` owns that sequencing.
"""
from __future__ import annotations

import hashlib
import ipaddress
import mmap
import os
import struct
from typing import Any, Optional

#: 3 binary bytes + "MaxMind.com". Not aligned, not length-prefixed — found by search.
METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"

#: "The maximum allowable size for the metadata section, including the marker that
#: starts the metadata, is 128KiB" — spec. The bound is load-bearing, not a
#: performance tweak: the marker bytes can legitimately occur inside the data section,
#: so scanning the whole file would let a hostile database plant a fake metadata map
#: far from the end and have it win.
_METADATA_WINDOW = 128 * 1024

#: The zero bytes between the search tree and the data section. Folded into every
#: data-section offset; see `_lookup` for the one formula where it is already folded
#: into the record value instead, which is the trap this constant exists to name.
_SEPARATOR_SIZE = 16

#: Recursion cap. libmaxminddb uses 512; real GeoLite2 records nest 3-4 deep, so this
#: is still ~15x more than any legitimate file needs. It is not optional: a 2002-byte
#: payload of 1000 nested arrays raises RecursionError at CPython's default limit
#: (measured), and anything that raises the recursion limit converts that catchable
#: exception into a C-stack overflow — a hard crash of the ingest worker.
_MAX_DEPTH = 64

#: Fields one lookup may decode before the reader gives up. A real GeoIP2 record is
#: tens of values; the richest Enterprise record is a few hundred. 100,000 is
#: enormously generous for anything MaxMind ships and still bounds a forged file to
#: microseconds.
_MAX_FIELDS = 100_000


class _Budget:
    """Total decode work for ONE lookup — the bound `_MAX_DEPTH` cannot provide.

    Depth stops a deep record and `in_pointer` stops a pointer chain, but neither
    stops BREADTH REACHED THROUGH POINTERS, and that is the cheap attack. A pointer
    costs two bytes and its target is decoded afresh on every dereference, so a map of
    B pointers all naming one shared map of B pointers multiplies work by B per level
    while the file grows by ~3B bytes. `in_pointer` does not help: it is cleared as
    soon as the target turns out to be a map, because `_container` recurses without
    it. A level costs two of the depth budget, so 32 levels fit under `_MAX_DEPTH` and
    a ~1.4 KB file expands to B**32 decodes — a permanent hang on the ingest write
    path, where `IngestQueue._flush` would then discard the whole buffered group.

    PER LOOKUP, NOT PER READER: one `MMDBReader` is shared by every ingest worker, so
    an instance counter would be a data race and would also let one thread's budget
    fail another thread's honest record.
    """

    __slots__ = ("left",)

    def __init__(self, limit: int = _MAX_FIELDS) -> None:
        self.left = limit

    def spend(self, path: str, off: int) -> None:
        self.left -= 1
        if self.left < 0:
            raise MMDBError(
                f"{path}: lookup decoded more than {_MAX_FIELDS} fields (at offset "
                f"{off}) — the file is forged or corrupt; a real record is tens of "
                "values")

#: Type numbers from the spec. Named because the dispatch below reads as arithmetic
#: otherwise, and a transposed pair of numbers decodes silently into the wrong type.
_T_POINTER, _T_UTF8, _T_DOUBLE, _T_BYTES, _T_UINT16 = 1, 2, 3, 4, 5
_T_UINT32, _T_MAP, _T_INT32, _T_UINT64, _T_UINT128 = 6, 7, 8, 9, 10
_T_ARRAY, _T_CONTAINER, _T_END_MARKER, _T_BOOL, _T_FLOAT = 11, 12, 13, 14, 15

#: Maximum payload width per unsigned type. A file declaring more is corrupt, and
#: without this check `int.from_bytes` would happily return a 40-byte integer.
_UINT_LIMIT = {_T_UINT16: 2, _T_UINT32: 4, _T_UINT64: 8, _T_UINT128: 16}

_VALID_RECORD_SIZES = (24, 28, 32)


class MMDBError(Exception):
    """Anything wrong with the database file: unopenable, not an MMDB, or corrupt.

    One type, because the caller is on the write path and catches by type. Message
    text names the offset or field, since the only diagnostic an operator gets for a
    binary blob is what this string says.
    """


class MMDBReader:
    """Read-only reader over one .mmdb file.

    Thread safe for concurrent `get()`: the buffer is never written, no file position
    is shared (only slicing and indexing are used, never `mmap.read()`), and nothing
    is memoized. That is what lets the ingest workers share one open reader without a
    lock on the hot path. `close()` concurrent with `get()` is the one unsafe pair and
    is converted into an MMDBError rather than a segfault, because CPython's mmap
    object validates itself.

    Usage:

        with MMDBReader("GeoLite2-Country.mmdb") as r:
            rec = r.get("8.8.8.8")          # dict, or None if not in the database
    """

    __slots__ = ("_path", "_fh", "_mm", "_buf", "_closed", "_metadata", "_size",
                 "_record_size", "_node_count", "_ip_version", "_node_byte_size",
                 "_tree_size", "_data_start", "_data_end", "_ipv4_start",
                 "_read_node", "_fingerprint")

    # ---- opening ---------------------------------------------------------- #
    def __init__(self, path: Any):
        self._path = os.fspath(path)
        self._fh = None
        self._mm = None
        self._buf: Any = b""
        self._closed = False
        try:
            self._open()
        except MMDBError:
            self.close()
            raise
        except Exception as exc:                        # noqa: BLE001
            # Everything reaches the caller as MMDBError. A bare OSError from open()
            # and a struct.error from a forged metadata map are the same event to the
            # geo loader: "this file is not usable".
            self.close()
            raise MMDBError(f"{self._path}: cannot open as a MaxMind DB: "
                            f"{type(exc).__name__}: {exc}") from exc

    def _open(self) -> None:
        size = os.path.getsize(self._path)
        if size == 0:
            # mmap.mmap() on a zero-byte file raises ValueError (measured), so the
            # empty case is rejected here where the message can say what happened.
            raise MMDBError(f"{self._path}: file is empty")
        if size < len(METADATA_MARKER) + 2:
            raise MMDBError(f"{self._path}: file is too small to be a MaxMind DB "
                            f"({size} bytes)")

        self._fh = open(self._path, "rb")
        try:
            self._mm = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ)
            self._buf = self._mm
        except (OSError, ValueError):
            # Fall back to a plain read. GeoLite2-City is ~70MB, so mmap is strongly
            # preferred — it costs address space per worker rather than RSS — but a
            # filesystem that will not map (some network mounts) should degrade to a
            # working reader, not to no geo at all.
            self._buf = self._fh.read()

        # The BUFFER is the authority on length from here on, not the stat above: an
        # operator copying a new database over this path can change the file between
        # the two calls, and every bound below is checked against `_size`. Taking the
        # mapped length closes that window instead of documenting it.
        self._size = len(self._buf)

        marker = self._buf.rfind(METADATA_MARKER, max(0, self._size - _METADATA_WINDOW))
        if marker < 0:
            raise MMDBError(f"{self._path}: no MaxMind metadata marker in the last "
                            f"{_METADATA_WINDOW} bytes — not a MaxMind DB file")

        # The metadata is an ordinary map decoded by the ordinary decoder, but its
        # pointers are relative to the first byte AFTER the marker — a DIFFERENT base
        # from the data section's. Using the marker position itself shifts every
        # metadata pointer by exactly 14 bytes.
        meta_start = marker + len(METADATA_MARKER)
        meta = self._decode(meta_start, meta_start, self._size, 0)[0]
        if not isinstance(meta, dict):
            raise MMDBError(f"{self._path}: metadata is a {type(meta).__name__}, "
                            f"not a map")
        self._metadata = meta

        self._record_size = self._meta_int("record_size")
        self._node_count = self._meta_int("node_count")
        self._ip_version = self._meta_int("ip_version")
        major = self._meta_int("binary_format_major_version")

        # The same three gates libmaxminddb applies, and for the same reason: the
        # layout above is only DEFINED for major version 2, and every offset formula
        # below assumes one of exactly three record widths.
        if self._record_size not in _VALID_RECORD_SIZES:
            raise MMDBError(f"{self._path}: record_size {self._record_size} is not "
                            f"one of {_VALID_RECORD_SIZES}")
        if self._ip_version not in (4, 6):
            raise MMDBError(f"{self._path}: ip_version {self._ip_version} is not 4 or 6")
        if major != 2:
            raise MMDBError(f"{self._path}: binary format major version {major} is "
                            f"not 2 — this reader implements version 2 only")
        if self._node_count < 0:
            raise MMDBError(f"{self._path}: negative node_count {self._node_count}")

        self._node_byte_size = self._record_size // 4
        self._tree_size = self._node_count * self._node_byte_size
        self._data_start = self._tree_size + _SEPARATOR_SIZE
        self._data_end = marker            # the data section ends where the marker begins

        # A forged node_count is the cheapest way to make tree reads wander into the
        # data section, the metadata, or off the end. Checking it ONCE here is what
        # lets `_node24/28/32` skip bounds checks entirely on the hot path.
        if self._data_start > self._data_end:
            raise MMDBError(
                f"{self._path}: declared search tree overruns the file — node_count "
                f"{self._node_count} x {self._node_byte_size} bytes + "
                f"{_SEPARATOR_SIZE} > {self._data_end} bytes before the metadata")

        # The UNBOUND function, called as `read_node(self, node, bit)`. Storing the
        # bound method would be tidier to read but would make the reader reference
        # itself, so the mapping would survive until a gc pass rather than dying with
        # the last reference — and on Windows a surviving mapping is a locked file
        # that `geo.reload()` cannot replace.
        self._read_node = {24: MMDBReader._node24, 28: MMDBReader._node28,
                           32: MMDBReader._node32}[self._record_size]
        self._ipv4_start = self._find_ipv4_start()
        self._fingerprint = self._compute_fingerprint()

    def _meta_int(self, key: str) -> int:
        value = self._metadata.get(key)
        if not isinstance(value, int) or isinstance(value, bool):
            raise MMDBError(f"{self._path}: metadata field {key!r} is "
                            f"{value!r}, expected an integer")
        return value

    def _compute_fingerprint(self) -> str:
        """A cheap stable identity for the loaded file, for `GeoIndex.fingerprint`.

        Deliberately NOT a digest of the file: hashing 70MB at every startup buys
        nothing here, because MaxMind stamps `build_epoch` on every rebuild and a
        hand-edited file changes `node_count` or its length long before it changes
        nothing at all. Size is included so a truncated copy of the same build is a
        different fingerprint.
        """
        parts = [str(self._metadata.get("database_type", "")),
                 str(self._metadata.get("build_epoch", "")),
                 str(self._node_count), str(self._record_size),
                 str(self._ip_version), str(self._size)]
        return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()[:16]

    def _find_ipv4_start(self) -> int:
        """The node where an IPv4 lookup begins in an IPv6 tree.

        IPv4 lives at ::/96, so the start node is found by walking 96 ZERO bits from
        the root — computed once here rather than per lookup, which is the single
        biggest win available in this module.

        The early break matters and is copied from the reference: if the zero walk
        falls out of the tree, the value is used AS-IS. `== node_count` then makes
        every IPv4 lookup a clean miss; `> node_count` makes them all return one
        record. Both are honest readings of a strange file, and neither is worth
        rejecting the whole database over.

        NOT applied to an ip_version==4 database: there the root IS the IPv4 root, and
        running the walk anyway drives the node number straight off the end of the
        tree (measured on a synthetic v4-only file: node 67 of 67 nodes).
        """
        if self._ip_version == 4:
            return 0
        node = 0
        for _ in range(96):
            if node >= self._node_count:
                break
            node = self._read_node(self, node, 0)
        return node

    # ---- the search tree -------------------------------------------------- #
    # Three unpackers instead of one branching function: the record width is fixed for
    # the life of the file, so the branch is resolved once at open (`self._read_node`)
    # rather than 32-128 times per lookup. No bounds checks here — `node < node_count`
    # is the loop condition and `node_count * node_byte_size <= data_end` was proven
    # at open, so every read below is inside the mapping by construction.

    def _node24(self, node: int, index: int) -> int:
        off = node * 6 + index * 3
        return int.from_bytes(self._buf[off:off + 3], "big")

    def _node28(self, node: int, index: int) -> int:
        """The split middle byte, which is the most error-prone code in this file.

        Node is 7 bytes b0..b6. b3 is SHARED: its HIGH nibble is bits 27..24 of the
        LEFT record, its LOW nibble is bits 27..24 of the RIGHT record. Swapping them
        is invisible on any test whose middle byte has two equal nibbles (0x00, 0x11,
        ... 0xFF), which is why the unit test for this uses 0x9C.

        `(b[3] & 0xF0) << 20` is deliberate, not a typo for `<< 24`: the nibble is
        already in the high half of the byte, so it needs 4 fewer shifts. It is
        exactly `((b[3] & 0xF0) >> 4) << 24`.
        """
        off = node * 7
        b = self._buf[off:off + 7]
        if index:
            return ((b[3] & 0x0F) << 24) | (b[4] << 16) | (b[5] << 8) | b[6]
        return ((b[3] & 0xF0) << 20) | (b[0] << 16) | (b[1] << 8) | b[2]

    def _node32(self, node: int, index: int) -> int:
        off = node * 8 + index * 4
        return int.from_bytes(self._buf[off:off + 4], "big")

    def _lookup(self, addr: Any) -> Optional[Any]:
        packed = addr.packed
        bit_count = len(packed) * 8
        node_count = self._node_count
        read_node = self._read_node

        # Start at the cached ::/96 node ONLY for a 4-byte address in a v6 tree.
        node = self._ipv4_start if (self._ip_version == 6 and bit_count == 32) else 0

        # Bounded by the ADDRESS WIDTH, never by tree structure. That is what makes a
        # cyclic tree impossible to hang on: a node pointing at itself simply exhausts
        # the 32 or 128 bits and falls out below (measured). A `while True` with a
        # break would reintroduce exactly the hang this loop cannot have.
        i = 0
        while i < bit_count and node < node_count:
            bit = 1 & (packed[i >> 3] >> (7 - (i & 7)))
            node = read_node(self, node, bit)
            i += 1

        if node == node_count:
            return None                     # the designated "not in the database" value
        if node < node_count:
            # Address bits exhausted while still inside the tree. This is corruption,
            # and it must NOT be folded into the miss above: a genuine miss has its own
            # encoding, so conflating them hides a broken file behind empty results.
            raise MMDBError(f"{self._path}: invalid node {node} in the search tree "
                            f"after {i} bits of {addr}")

        # TREE RECORD -> FILE OFFSET. The 16-byte separator is ALREADY folded into the
        # record value by the writer ("so a record can point at the first byte of the
        # data section"), so it is NOT added again here. The data-section POINTER
        # formula three methods down does add it, via `base`. Swapping the two is off
        # by exactly 16 bytes and decodes a plausible wrong field rather than failing.
        resolved = node - node_count + self._tree_size
        if not (self._data_start <= resolved < self._data_end):
            # Catches record values in node_count+1 .. node_count+15, which resolve
            # inside the separator, as well as anything past the data section.
            raise MMDBError(f"{self._path}: record for {addr} resolves to offset "
                            f"{resolved}, outside the data section "
                            f"[{self._data_start}, {self._data_end})")
        return self._decode(resolved, self._data_start, self._data_end, 0)[0]

    # ---- the data section ------------------------------------------------- #
    def _decode(self, off: int, base: int, limit: int, depth: int,
                in_pointer: bool = False,
                budget: Optional["_Budget"] = None) -> tuple[Any, int]:
        """Decode one field at `off`. Returns (value, offset just past the field).

        `base` is the pointer base — `data_start` in the data section, `meta_start`
        inside the metadata — and doubles as the lower bound, since a pointer value is
        unsigned and so can never resolve below it. `limit` is one past the last byte
        this field may touch.

        The returned offset is what makes maps and arrays work: for a POINTER it is
        the end of the pointer FIELD, not of the value it names. Returning the latter
        desynchronizes the rest of the enclosing map instead of failing loudly.
        """
        budget = budget if budget is not None else _Budget()
        budget.spend(self._path, off)
        if depth > _MAX_DEPTH:
            raise MMDBError(f"{self._path}: data nested deeper than {_MAX_DEPTH} at "
                            f"offset {off}")
        if not (base <= off < limit):
            raise MMDBError(f"{self._path}: field offset {off} outside "
                            f"[{base}, {limit})")

        ctrl = self._buf[off]
        off += 1
        type_num = ctrl >> 5
        if type_num == 0:
            # Extended type: the NEXT byte carries it, biased by 7. Byte order is
            # control, then extended type, then extended size, then payload.
            if off >= limit:
                raise MMDBError(f"{self._path}: truncated extended type at {off}")
            type_num = self._buf[off] + 7
            off += 1
            if type_num < 8:
                raise MMDBError(f"{self._path}: extended type resolves to "
                                f"{type_num}, which is not an extended type")

        size, off = self._size_of(ctrl, off, type_num, limit)

        if type_num == _T_POINTER:
            field_start = off - 1
            target, off = self._pointer(size, off, base, limit)
            if in_pointer:
                # "It is illegal for a pointer to point to another pointer." Enforcing
                # it collapses every possible pointer chain — including a self-pointer
                # and a mutual pair — into one dereference.
                raise MMDBError(f"{self._path}: pointer at {field_start} points to "
                                f"another pointer at {target}")
            if not (base <= target < limit):
                # A pointer into the search tree or the metadata is arithmetically
                # well-formed and semantic nonsense; it would decode tree bytes as a
                # record rather than fail.
                raise MMDBError(f"{self._path}: pointer target {target} outside "
                                f"[{base}, {limit})")
            return self._decode(target, base, limit, depth + 1, in_pointer=True,
                                budget=budget)[0], off

        if type_num == _T_BOOL:
            # The VALUE IS THE SIZE FIELD. No payload, and the cursor does not advance
            # past the control byte.
            return size != 0, off

        if type_num in (_T_MAP, _T_ARRAY):
            return self._container(type_num, size, off, base, limit, depth, budget)

        # Everything below has a byte payload, so bound it BEFORE slicing. Python
        # slicing past EOF truncates silently and `int.from_bytes` on the short slice
        # returns a wrong number with no error — this check is the difference between
        # a visible failure and a quietly wrong country code.
        end = off + size
        if end > limit:
            raise MMDBError(f"{self._path}: {size}-byte payload at {off} runs past "
                            f"{limit}")

        if type_num == _T_UTF8:
            try:
                return self._buf[off:end].decode("utf-8"), end
            except UnicodeDecodeError as exc:
                raise MMDBError(f"{self._path}: invalid UTF-8 at {off}: {exc}") from exc
        if type_num in _UINT_LIMIT:
            limit_bytes = _UINT_LIMIT[type_num]
            if size > limit_bytes:
                raise MMDBError(f"{self._path}: unsigned type {type_num} declares "
                                f"{size} bytes at {off}, max {limit_bytes}")
            # Leading zero bytes are omitted by the writer and a length of zero means
            # zero, both of which int.from_bytes already does — including uint128.
            return int.from_bytes(self._buf[off:end], "big"), end
        if type_num == _T_INT32:
            if size > 4:
                raise MMDBError(f"{self._path}: int32 declares {size} bytes at {off}")
            # Short fields are always positive; only a full 4-byte field carries a sign
            # bit. Left-padding with zeros preserves both readings.
            return struct.unpack("!i", bytes(self._buf[off:end]).rjust(4, b"\x00"))[0], end
        if type_num == _T_DOUBLE:
            if size != 8:
                raise MMDBError(f"{self._path}: double declares {size} bytes at {off}")
            return struct.unpack("!d", self._buf[off:end])[0], end
        if type_num == _T_FLOAT:
            if size != 4:
                raise MMDBError(f"{self._path}: float declares {size} bytes at {off}")
            return struct.unpack("!f", self._buf[off:end])[0], end
        if type_num == _T_BYTES:
            return bytes(self._buf[off:end]), end

        # 12 (data cache container) and 13 (end marker) are deprecated; the spec says
        # readers are not expected to support them and no known database emits either.
        # Refusing beats guessing at a layout nothing can be tested against.
        raise MMDBError(f"{self._path}: unsupported data type {type_num} at {off}")

    def _size_of(self, ctrl: int, off: int, type_num: int,
                 limit: int) -> tuple[int, int]:
        """The low 5 bits of the control byte, with the three extension forms.

        The extension does NOT apply to pointers: there the raw 5 bits are a size
        CLASS plus the top value bits, and re-reading them as a length would consume
        payload bytes that belong to the next field.
        """
        size = ctrl & 0x1F
        if type_num == _T_POINTER or size < 29:
            return size, off
        # The three bases tile exactly: 28+1 == 29, 29+255+1 == 285,
        # 285+65535+1 == 65821 — no gap, no overlap, so every length has one encoding.
        if size == 29:
            if off + 1 > limit:
                raise MMDBError(f"{self._path}: truncated size byte at {off}")
            return 29 + self._buf[off], off + 1
        if size == 30:
            if off + 2 > limit:
                raise MMDBError(f"{self._path}: truncated size bytes at {off}")
            return 285 + int.from_bytes(self._buf[off:off + 2], "big"), off + 2
        if off + 3 > limit:
            raise MMDBError(f"{self._path}: truncated size bytes at {off}")
        return 65821 + int.from_bytes(self._buf[off:off + 3], "big"), off + 3

    def _pointer(self, size: int, off: int, base: int,
                 limit: int) -> tuple[int, int]:
        """Resolve a pointer field. Returns (absolute target, offset past the field).

        Four size classes, from bits 4-3 of the 5-bit size field; the payload is
        class+1 bytes. The low 3 bits supply the value's HIGH bits for classes 0-2 and
        are ignored for class 3. The addends are what make the classes tile without
        overlap — class 0 reaches 0..2047, class 1 picks up at 2048 (== 2**11), class
        2 at 526336 (== 2048 + 2**19), class 3 covers the full 32 bits. Without them a
        class-1 pointer could not name any offset a class-0 pointer already could, and
        19 bits of range would be wasted.
        """
        size_class = (size >> 3) & 0x03
        width = size_class + 1
        if off + width > limit:
            raise MMDBError(f"{self._path}: truncated pointer at {off}")
        raw = int.from_bytes(self._buf[off:off + width], "big")
        if size_class == 0:
            value = ((size & 0x07) << 8) | raw
        elif size_class == 1:
            value = (((size & 0x07) << 16) | raw) + 2048
        elif size_class == 2:
            value = (((size & 0x07) << 24) | raw) + 526336
        else:
            value = raw
        return base + value, off + width

    def _container(self, type_num: int, size: int, off: int, base: int, limit: int,
                   depth: int, budget: "_Budget") -> tuple[Any, int]:
        """A map (size == pair count) or an array (size == element count).

        Neither size is a BYTE count, which is the whole hazard: a 3-byte size
        extension lets a forged map declare ~16 million pairs, each costing two
        recursive decodes. A depth cap does not help — the work is breadth, not depth —
        so the count is bounded against the bytes that actually remain. The smallest
        possible field is one byte (an empty string, or a boolean), so a pair needs at
        least two.
        """
        remaining = limit - off
        needed = size * 2 if type_num == _T_MAP else size
        if needed > remaining:
            raise MMDBError(
                f"{self._path}: {'map' if type_num == _T_MAP else 'array'} at {off} "
                f"declares {size} {'pair' if type_num == _T_MAP else 'element'}(s) "
                f"but only {remaining} byte(s) remain")

        if type_num == _T_ARRAY:
            items = []
            for _ in range(size):
                value, off = self._decode(off, base, limit, depth + 1, budget=budget)
                items.append(value)
            return items, off

        out: dict[Any, Any] = {}
        for _ in range(size):
            # Keys go through the FULL decode path, never a string fast path: a key may
            # itself be a pointer to a string, which is how MaxMind deduplicates the
            # ~40 key names that repeat in every one of millions of records.
            key, off = self._decode(off, base, limit, depth + 1, budget=budget)
            value, off = self._decode(off, base, limit, depth + 1, budget=budget)
            out[key] = value
        return out, off

    # ---- the public surface ----------------------------------------------- #
    def get(self, ip: Any) -> Optional[Any]:
        """The record stored for `ip`, or None if the database has no entry for it.

        None also covers two non-error cases that a caller on the ingest path should
        not have to branch on:

        * an unparseable address. The reference reader raises; here a malformed
          `src_ip` in a log line is simply an address this database says nothing about,
          and paying an exception per bad field on the write path buys nothing.
        * an IPv6 address in an ip_version==4 database. Explicitly a miss, never a
          truncation or a mapping — a v4-only database genuinely has no answer. The
          cost is that "all my IPv6 traffic is unenriched" looks like "no data", so
          `/health` should publish `ip_version` where an operator can see it.

        A CORRUPT file raises MMDBError instead, and the difference is deliberate.
        """
        if self._closed:
            raise MMDBError(f"{self._path}: reader is closed")
        if not isinstance(ip, str):
            # psycopg loads an `inet` column as an ipaddress object, so the backfill
            # hands one straight through. MEASURED: those already work without this,
            # because `IPv4Address.__init__` itself falls back to `str(address)`. What
            # this line actually prevents is an INT being reinterpreted —
            # `ipaddress.ip_address(8)` is 0.0.0.8, a real address belonging to
            # somebody else, and looking it up would be worse than a miss.
            #
            # It does NOT rescue an ip_interface ("10.0.0.1/32"), which stays a miss:
            # deciding that a prefix means its network address is a policy call, not a
            # coercion, and psycopg returns that shape whenever the stored text has a
            # `/`. The wire agent normalizes at the seam.
            ip = str(ip)
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if addr.version == 6 and self._ip_version == 4:
            return None

        try:
            record = self._lookup(addr)
            if record is None and addr.version == 6 and self._ip_version == 6:
                # MaxMind's own files carry tree ALIASES so ::ffff:0:0/96 and 2002::/16
                # point back at the ::/96 subtree, and the walk above finds them. A
                # file built WITHOUT aliases misses on the mapped form while answering
                # correctly for the bare v4 address (measured on a synthetic pair), so
                # one retry converts that into the answer the operator expects. On an
                # aliased file the first walk hits and this never runs.
                mapped = addr.ipv4_mapped
                if mapped is not None:
                    record = self._lookup(mapped)
            return record
        except MMDBError:
            raise
        except Exception as exc:                        # noqa: BLE001
            # struct.error and UnicodeDecodeError are the two that escaped a draft of
            # this reader during development. The size validations above should make
            # them unreachable; this exists so that if one is not, it still arrives at
            # the caller as the type they catch.
            raise MMDBError(f"{self._path}: corrupt record for {ip}: "
                            f"{type(exc).__name__}: {exc}") from exc

    @property
    def metadata(self) -> dict:
        """The decoded metadata map, exactly as stored. Not copied — a caller that
        mutates it corrupts this reader's view of its own file."""
        return self._metadata

    # Convenience readers over `metadata`. These are ADDITIONS to the frozen contract,
    # not changes: `geo.py` needs the fingerprint for staleness and `/health` needs the
    # rest to explain why a lookup returned nothing.
    @property
    def path(self) -> str:
        return self._path

    @property
    def fingerprint(self) -> str:
        return self._fingerprint

    @property
    def database_type(self) -> str:
        return str(self._metadata.get("database_type", ""))

    @property
    def build_epoch(self) -> int:
        value = self._metadata.get("build_epoch")
        return int(value) if isinstance(value, int) else 0

    @property
    def ip_version(self) -> int:
        return self._ip_version

    @property
    def node_count(self) -> int:
        return self._node_count

    @property
    def record_size(self) -> int:
        return self._record_size

    @property
    def file_size(self) -> int:
        return self._size

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        """Release the mapping and the file handle. Idempotent.

        REQUIRED before the file can be replaced on Windows: os.replace() over a
        mapped .mmdb fails with WinError 5 (measured). The mmap is closed before the
        handle, which is the only order CPython accepts.
        """
        if self._closed:
            return
        self._closed = True
        mm, fh = self._mm, self._fh
        self._mm = None
        self._fh = None
        self._buf = b""
        try:
            if mm is not None:
                mm.close()
        finally:
            if fh is not None:
                fh.close()

    def __enter__(self) -> "MMDBReader":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        if self._closed:
            return f"<MMDBReader {self._path!r} closed>"
        return (f"<MMDBReader {self._path!r} {self.database_type!r} "
                f"ipv{self._ip_version} nodes={self._node_count} "
                f"rs={self._record_size} fp={self._fingerprint}>")
