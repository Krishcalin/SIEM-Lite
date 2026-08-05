# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""A country/ASN range table read from CSV — the side-load path with no binary reader.

`mmdb.py` handles MaxMind's binary format. This module handles the OTHER half of what
operators actually have: the redistributable text tables. It exists because those
files are the ones an air-gapped site can realistically obtain and diff — a CSV can be
reviewed, trimmed to the ranges a site cares about, and committed next to the config,
which a 70 MB binary blob cannot.

WHAT LOADS DIRECTLY, AND WHAT DOES NOT
--------------------------------------
Stated plainly, because "supports MaxMind CSV" is the kind of claim that is half true
and wastes an afternoon:

  * DB-IP lite country/ASN CSV — WORKS. Headerless `start,end,value` triples.
  * iptoasn.com TSV — WORKS. Headerless `start<TAB>end<TAB>asn<TAB>cc<TAB>desc`.
    Its unrouted rows carry ASN `0` and country `None` literally; both are read as
    "absent" rather than stored, see `_country` / `_asn`.
  * MaxMind GeoLite2-ASN-Blocks-IPv{4,6}.csv — WORKS. `network,
    autonomous_system_number, autonomous_system_organization`; the org name is read
    and discarded, per the storage decision in `models.py`.
  * MaxMind GeoLite2-Country-Blocks-IPv{4,6}.csv — DOES **NOT** WORK, and cannot.
    That file carries `geoname_id`, not an ISO code; the codes live in a separate
    Locations CSV and the two must be joined first. Rather than half-load it, the
    loader refuses the file with a message saying so — a table that resolved every
    address to no country would otherwise look like a working install.

WHY BISECTION, NOT A SCAN
-------------------------
A full ASN table is ~400,000 rows and this is the ingest path, twice per event. The
table is therefore held as three parallel sorted lists per address family and searched
with `bisect` — O(log n), MEASURED at 17 integer comparisons against a 200,000-row
table (log2 200000 = 17.6), which `test_enrich_sources.py` asserts DETERMINISTICALLY
by counting comparisons through a counting-int needle rather than by timing anything.
Parallel lists rather than a list of tuples, and an interned payload per distinct
(country, asn) pair, because a country-only table has ~250 distinct payloads across
those 400,000 rows and storing a tuple per row is pure waste.

THE PRECONDITION BISECTION HAS, AND HOW IT IS MET
-------------------------------------------------
`bisect_right(starts, x) - 1` finds the last range starting at or below `x`. That is
the answer ONLY IF no two ranges overlap — otherwise a narrow range can hide a wider
one that also contains the address, and the lookup silently returns a miss for an
address the file covers. Vendor tables are disjoint; files that have been concatenated,
hand-edited or merged are not, and this module does not get to assume which it was
handed. So `load` MEASURES disjointness in one O(n) pass and, only if it fails,
flattens the ranges into disjoint segments with a sweep in which the NARROWEST range
wins — the same "most specific first" rule `assets/index.py` already applies to
declared CIDRs, so an operator who appends a corrected /24 over a vendor /16 gets the
answer they intended.

The rejected alternative was to REFUSE an overlapping file outright with a
line-numbered error. It is simpler and it is louder, and it was rejected because the
failure it produces is total: one bad pair of rows in a 400,000-row table would cost
the site every country code it has. Flattening keeps the other 399,998 rows working
and reports the overlap count through `stats()` so the condition is still visible.
"""
from __future__ import annotations

import csv
import itertools
import hashlib
import heapq
import io
import ipaddress
from bisect import bisect_right
from typing import Any, Iterable, Optional

from .ranges import parse_ip


#: Rows sampled to infer a headerless file's column layout. Enough to step over a
#: block of leading unrouted ranges (iptoasn sorts them first) without reading a
#: 400,000-row table into memory twice.
_INFER_SAMPLE_ROWS = 50


class RangeTableError(ValueError):
    """A file that cannot be loaded at all — as opposed to a row that is skipped.

    The split matters on the ingest path: a bad ROW costs one range, and the loader
    keeps going; a bad FILE means every lookup would silently answer None, which is
    indistinguishable from "no database configured" and must be reported to the
    operator instead.
    """


# --------------------------------------------------------------------------- #
#  Header vocabulary                                                           #
# --------------------------------------------------------------------------- #
# Liberal on purpose: every vendor spells these differently and none of the spellings
# is ambiguous, so accepting all of them costs nothing. A name not listed here is
# IGNORED rather than rejected — the opposite of `assets/csvio.py`, which errors on
# unknown columns. The reason for the divergence is that an asset import is written by
# the operator (an unknown column there is a typo worth catching), whereas these files
# are vendor output carrying half a dozen columns this product has no use for.
_START_NAMES = ("start_ip", "start", "ip_from", "from", "first_ip", "begin",
                "start_address", "startip", "ip_start", "range_start",
                "network_start_ip", "min_ip", "low", "ip_range_start")
_END_NAMES = ("end_ip", "end", "ip_to", "to", "last_ip", "end_address", "endip",
              "ip_end", "range_end", "network_last_ip", "max_ip", "high",
              "ip_range_end")
_CIDR_NAMES = ("cidr", "network", "net", "prefix", "subnet", "range", "ip_range",
               "ip_prefix", "block")
_COUNTRY_NAMES = ("country", "country_iso_code", "iso_code", "country_code", "cc",
                  "country_iso", "countrycode", "registered_country_iso_code",
                  "country_name")
_ASN_NAMES = ("asn", "as", "as_number", "autonomous_system_number", "asnum",
              "as_num", "asn_number", "autonomous_system")

#: Delimiters tried, most likely first. `csv.Sniffer` is deliberately not used: it
#: guesses from a sample and gets tab-separated files with commas inside a description
#: column wrong, which would shift every column by one and produce a table full of
#: plausible nonsense. Counting candidate characters on the first line is dumber and
#: has no failure mode that is not obvious.
_DELIMITERS = (",", "\t", ";", "|")

#: Values vendors write to mean "unknown", not a real country. iptoasn writes the
#: literal string `None` in its unrouted rows.
_NULL_TEXT = frozenset({"", "-", "none", "null", "n/a", "na", "unknown", "??", "zz"})

#: How many per-row complaints are retained. A file whose every row is malformed
#: should not be able to hold a 400,000-entry error list in memory on a SIEM.
_MAX_ERRORS = 100


def _norm_header(name: object) -> str:
    """`  Country ISO Code ` / `country-iso-code` -> `country_iso_code`."""
    s = str(name or "").strip().lstrip("﻿").lower()
    for ch in (" ", "-", "."):
        s = s.replace(ch, "_")
    return s.strip("_")


def _country(value: object) -> Optional[str]:
    """A cell -> a 2-char upper ISO code, or None.

    Anything that is not exactly two ASCII letters is treated as ABSENT rather than as
    an error, because that is what vendors write for unallocated space (`-`, `None`,
    `ZZ`, empty). `ZZ` is in the null set deliberately: it is the ISO user-assigned
    "unknown" code, so storing it would put a fake country on the event.
    """
    s = str(value or "").strip()
    if s.lower() in _NULL_TEXT:
        return None
    return s.upper() if len(s) == 2 and s.isascii() and s.isalpha() else None


def _asn(value: object, line: int) -> Optional[int]:
    """A cell -> a positive AS number, or None. Raises `RangeTableError` on junk.

    `AS13335` and `13335` both parse — whois output and RIR exports use the prefixed
    form. AS 0 becomes None: RFC 7607 reserves it and iptoasn uses it for "not
    routed", so it is an absence, not a number worth storing. Junk RAISES rather than
    returning None, because a non-numeric ASN column means the column mapping is
    wrong, and silently zeroing it would hide that.
    """
    s = str(value or "").strip()
    if s.lower() in _NULL_TEXT:
        return None
    if s[:2].lower() == "as":
        s = s[2:].strip()
    if not s:
        return None
    try:
        n = int(s)
    except ValueError:
        raise RangeTableError(f"row {line}: {value!r} is not an AS number") from None
    if n == 0:
        return None
    if not 0 < n <= 0xFFFFFFFF:
        raise RangeTableError(f"row {line}: AS number {n} is out of range")
    return n


# --------------------------------------------------------------------------- #
#  Overlap handling                                                            #
# --------------------------------------------------------------------------- #
def _count_overlaps(rows: list[tuple[int, int, Any]]) -> int:
    """How many rows start inside a range already seen. O(n), one pass over sorted
    rows — cheap enough to run on every load so the expensive flatten below is only
    entered when it is actually needed."""
    n = 0
    high = -1
    for start, end, _ in rows:
        if start <= high:
            n += 1
        if end > high:
            high = end
    return n


def _flatten(rows: list[tuple[int, int, Any]]) -> list[tuple[int, int, Any]]:
    """Overlapping ranges -> disjoint segments, narrowest range winning.

    A sweep over every boundary point, holding the ranges covering the current point
    in a min-heap keyed by width. The heap top is therefore the narrowest range
    covering that point, which is the segment's answer. Expired ranges are removed
    lazily — one under the top can only matter once it becomes the top, and it is
    popped then.

    Ties (two ranges with identical width covering one point) are broken by FILE
    ORDER, via the row index in the heap key. That makes an exact duplicate range with
    a different country deterministic — first occurrence wins — rather than dependent
    on sort stability.

    Adjacent segments with an identical payload are merged as they are emitted, so a
    file whose overlaps were redundant does not inflate the table.
    """
    points = sorted({p for start, end, _ in rows for p in (start, end + 1)})
    ordered = sorted(range(len(rows)), key=lambda i: rows[i][0])
    out: list[tuple[int, int, Any]] = []
    heap: list[tuple[int, int, int, Any]] = []
    nxt = 0
    for k in range(len(points) - 1):
        point, stop = points[k], points[k + 1] - 1
        while nxt < len(ordered):
            start, end, payload = rows[ordered[nxt]]
            if start > point:
                break
            # The row index is the second key on purpose, and it is what makes the
            # heap total-order-safe: it is unique, so `heapq` never falls through to
            # comparing the payloads — and comparing `(None, 5)` against `('US', None)`
            # would raise TypeError rather than pick a winner.
            heapq.heappush(heap, (end - start, ordered[nxt], end, payload))
            nxt += 1
        while heap and heap[0][2] < point:
            heapq.heappop(heap)
        if not heap:
            continue                        # a gap between ranges — no coverage
        payload = heap[0][3]
        if out and out[-1][2] == payload and out[-1][1] == point - 1:
            out[-1] = (out[-1][0], stop, payload)
        else:
            out.append((point, stop, payload))
    return out


# --------------------------------------------------------------------------- #
#  The table                                                                   #
# --------------------------------------------------------------------------- #
class RangeTable:
    """Sorted country/ASN ranges, searched by bisection, IPv4 and IPv6 kept apart.

    THE TWO FAMILIES ARE SEPARATE SEARCHES AND THAT IS LOAD-BEARING, not tidiness.
    Both are stored as plain integers, and the ranges collide: `::a00:1` is integer
    167772161, which is byte-identical to IPv4 `10.0.0.1`. One combined list would
    resolve an IPv6 address against an IPv4 row and hand back a confident, wrong
    country. `test_enrich_sources.py` pins exactly that address pair.
    """

    __slots__ = ("_fam", "path", "errors", "skipped", "blank", "overlaps",
                 "source_rows", "fingerprint")

    def __init__(self) -> None:
        # version -> (starts, ends, payloads); payload is an interned (country, asn).
        self._fam: dict[int, tuple[list[int], list[int], list[tuple]]] = {
            4: ([], [], []), 6: ([], [], [])}
        self.path: Optional[str] = None
        self.errors: list[str] = []
        self.skipped = 0        # rows refused, with a reason in `errors`
        self.blank = 0          # rows parsed fine but carrying neither country nor ASN
        self.overlaps = 0       # rows that overlapped an earlier range
        self.source_rows = 0    # rows accepted from the file
        self.fingerprint: Optional[str] = None

    # ---- lookup ----------------------------------------------------------- #
    def lookup(self, ip: object) -> Optional[dict]:
        """Address -> ``{'country': str|None, 'asn': int|None}``, or None if no range
        covers it.

        BOTH KEYS ARE ALWAYS PRESENT when a range matches, one of them possibly None.
        A caller reading a country-only table gets `{'country': 'DE', 'asn': None}`
        rather than a `KeyError`, so the resolver needs no per-table conditionals and
        a table that gains an ASN column later changes no calling code.

        Returning None for "no range covers this" rather than an empty dict keeps the
        distinction the resolver needs: a miss must leave the column NULL, which is
        not the same as a range that covers the address and declares no country.
        """
        addr = parse_ip(ip)
        if addr is None:
            return None
        return self._find(addr.version, int(addr))

    def _find(self, version: int, value: int) -> Optional[dict]:
        """The bisection, separated from parsing so a test can drive it with a
        comparison-counting integer and prove the search is logarithmic."""
        starts, ends, payloads = self._fam[version]
        i = bisect_right(starts, value) - 1
        if i < 0 or value > ends[i]:
            return None
        country, asn = payloads[i]
        return {"country": country, "asn": asn}

    # ---- bookkeeping ------------------------------------------------------ #
    def __len__(self) -> int:
        """SEARCHABLE SEGMENTS, both families — not source rows.

        The two differ only when overlaps were flattened; `source_rows` reports what
        the file contained. Segments is the honest answer for "how big is the thing
        being searched", which is what a health page is asking.
        """
        return len(self._fam[4][0]) + len(self._fam[6][0])

    def is_empty(self) -> bool:
        return not len(self)

    def stats(self) -> dict:
        """For `/health`. Includes the RESOLVED path, because a relative geo path that
        silently resolved against a different working directory is the documented
        failure mode this project has already been bitten by once."""
        return {"path": self.path, "segments": len(self),
                "ipv4": len(self._fam[4][0]), "ipv6": len(self._fam[6][0]),
                "source_rows": self.source_rows, "skipped": self.skipped,
                "blank": self.blank, "overlaps": self.overlaps,
                "errors": list(self.errors), "fingerprint": self.fingerprint}

    # ---- loading ---------------------------------------------------------- #
    @classmethod
    def load(cls, path) -> "RangeTable":
        """Read a CSV/TSV range table from disk.

        Raises `RangeTableError` for a file that cannot yield a usable table at all;
        individual malformed rows are skipped and recorded in `errors` with their
        1-based ROW number, the way `assets/csvio.py` reports them. Row rather than
        physical line, and the distinction is only visible on a file that quotes a
        newline inside a field — which none of the range tables this module targets
        does, but saying "line" would still be a claim this counter does not make.
        """
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
        except OSError as exc:
            raise RangeTableError(f"{path}: {exc.strerror or exc}") from None
        return cls.loads(raw, path=str(path))

    @classmethod
    def loads(cls, data, *, path: Optional[str] = None) -> "RangeTable":
        """The pure half of `load` — bytes or text in, table out, nothing touched on
        disk. Separated so every parsing rule below is testable from a literal."""
        if isinstance(data, str):
            blob = data.encode("utf-8")
        else:
            blob = bytes(data)
        # `utf-8-sig` strips the BOM Excel writes; `replace` because one mangled byte
        # in a description column this module discards anyway must not cost the file.
        text = blob.decode("utf-8-sig", errors="replace")

        self = cls()
        self.path = path
        self.fingerprint = hashlib.sha256(blob).hexdigest()[:32]

        if not text.strip():
            raise RangeTableError(f"{path or 'the file'} is empty")

        delim = _sniff(text)
        reader = csv.reader(io.StringIO(text, newline=""), delimiter=delim)
        try:
            first = next(reader)
        except StopIteration:
            raise RangeTableError(f"{path or 'the file'} is empty") from None

        # SAMPLE, DO NOT TRUST ROW 1 ALONE. The column layout of a headerless file
        # used to be inferred from the first data row only, and the country column is
        # located by "does this cell parse as a country code?" — so a first row whose
        # country is one of the vendor 'unknown' spellings ('', '-', 'ZZ', 'None')
        # left `layout["country"]` unset and DISCARDED THE COUNTRY FOR THE WHOLE FILE.
        # That is not a corner case: iptoasn and several RIR exports sort unrouted
        # ranges first, and 0.0.0.0's row is exactly that shape. The ASN position is
        # still found (its '0' is a digit), so the file loads, reports a plausible
        # row count, and answers every country query with None.
        sample = [first]
        for extra in reader:                       # bounded — see _INFER_SAMPLE_ROWS
            sample.append(extra)
            if len(sample) >= _INFER_SAMPLE_ROWS:
                break
        layout, line0 = _layout(sample)
        # Replay the SAMPLED-BUT-NOT-YET-PARSED rows. `first` is deliberately excluded:
        # the `pending` line below already re-chains it when it was data (line0 == 1),
        # and chaining it here as well would parse row 1 twice — inflating source_rows
        # and double-counting a malformed row's error.
        reader = itertools.chain(sample[1:], reader)
        rows: dict[int, list[tuple[int, int, Any]]] = {4: [], 6: []}
        payloads: dict[tuple, tuple] = {}       # intern (country, asn)

        # `line0` is the 1-based number of the row `first` came from AND tells us
        # whether it was a header: 2 means row 1 was consumed as a header, 1 means it
        # was data and must be replayed through the same parser as everything else.
        pending: Iterable[list[str]] = reader if line0 == 2 else _chain(first, reader)
        for line, raw_row in enumerate(pending, start=line0):
            if not raw_row or not any(str(c or "").strip() for c in raw_row):
                continue                                    # a blank line
            try:
                parsed = _parse_row(raw_row, layout, line)
            except RangeTableError as exc:
                self.skipped += 1
                if len(self.errors) < _MAX_ERRORS:
                    self.errors.append(str(exc))
                continue
            if parsed is None:
                continue
            start, end, country, asn = parsed
            if country is None and asn is None:
                # An unrouted / unknown range. Kept out of the table entirely rather
                # than stored as a hit with two None values: a covered-but-empty
                # segment and a miss produce the same NULL columns, and dropping it
                # keeps the table (and every bisection over it) smaller.
                self.blank += 1
                continue
            key = (country, asn)
            payload = payloads.setdefault(key, key)
            rows[4 if start.version == 4 else 6].append(
                (int(start), int(end), payload))
            self.source_rows += 1

        if not self.source_rows:
            if self.errors:
                raise RangeTableError(
                    f"{path or 'the file'}: no usable rows — "
                    f"{'; '.join(self.errors[:3])}")
            if self.blank:
                # Every row parsed as a range and none carried a value. That is a
                # COLUMN MAPPING error, not an empty file, and it is refused rather
                # than served: a table that answers None for everything is
                # indistinguishable from "no database configured".
                #
                # Note this is the only guard needed for the mapping case. An earlier
                # draft also refused a file where a NAMED country column yielded no
                # code on any row, and that was wrong — it rejected a legitimate ASN
                # table whose country cells are all `ZZ`/unrouted, which is a real
                # shape iptoasn produces. The rows there are usable; only a file with
                # NO usable row at all is a mapping error.
                raise RangeTableError(
                    f"{path or 'the file'}: {self.blank} row(s) parsed as ranges but "
                    "none carried a country code or an AS number — check the column "
                    "mapping (GeoLite2 country blocks carry geoname_id rather than "
                    "an ISO code, and must be joined against the Locations CSV)")
            raise RangeTableError(
                f"{path or 'the file'} has a valid header but no data rows")

        for version, family in rows.items():
            if not family:
                continue
            family.sort(key=lambda r: (r[0], r[1]))
            overlaps = _count_overlaps(family)
            self.overlaps += overlaps
            # The fast path is the one real files take: already disjoint, so the sweep
            # is skipped entirely and load stays a sort.
            segments = _flatten(family) if overlaps else family
            starts, ends, pays = self._fam[version]
            for start, end, payload in segments:
                starts.append(start)
                ends.append(end)
                pays.append(payload)
        return self


def _chain(first: list[str], rest) -> Iterable[list[str]]:
    yield first
    yield from rest


def _sniff(text: str) -> str:
    """Pick the delimiter by counting candidates on the first non-blank line."""
    for line in text.splitlines():
        if line.strip():
            counts = {d: line.count(d) for d in _DELIMITERS}
            best = max(_DELIMITERS, key=lambda d: counts[d])
            return best if counts[best] else ","
    return ","


def _looks_like_address(cell: object) -> bool:
    s = str(cell or "").strip()
    if not s:
        return False
    if "/" in s:
        try:
            ipaddress.ip_network(s, strict=False)
            return True
        except ValueError:
            return False
    return parse_ip(s) is not None


def _layout(sample: list[list[str]]) -> tuple[dict, int]:
    """Decide how to read this file: named columns, or positional inference.

    The header test is a single unambiguous question — DOES THE FIRST CELL PARSE AS AN
    ADDRESS OR A CIDR? If it does, there is no header and row 1 is data; if it does
    not, row 1 is a header. Nothing else is consulted, because the alternative (does
    any cell match a known column name?) misfires on a headerless file whose first
    data row happens to contain the text `net`, and produces a silent off-by-one-row
    table rather than an error.

    Returns `(layout, first_data_line)` where `first_data_line` is 2 for a header'd
    file and 1 for a headerless one.
    """
    first = sample[0] if sample else []
    if _looks_like_address(first[0] if first else ""):
        return _infer_positions(sample), 1

    header = [_norm_header(h) for h in first]
    index = {name: i for i, name in enumerate(header) if name}
    layout: dict[str, Optional[int]] = {
        "cidr": _first_of(index, _CIDR_NAMES),
        "start": _first_of(index, _START_NAMES),
        "end": _first_of(index, _END_NAMES),
        "country": _first_of(index, _COUNTRY_NAMES),
        "asn": _first_of(index, _ASN_NAMES),
    }
    if layout["cidr"] is None and (layout["start"] is None or layout["end"] is None):
        raise RangeTableError(
            "the header names neither a CIDR column nor a start/end pair "
            f"(found: {', '.join(h for h in header if h) or 'nothing'}) — expected "
            f"one of {', '.join(_CIDR_NAMES[:4])}... or "
            f"{', '.join(_START_NAMES[:3])}... with {', '.join(_END_NAMES[:3])}...")
    if layout["country"] is None and layout["asn"] is None:
        # Named specially because it is the file operators reach for first, and the
        # generic "no country column" message would send them looking for a typo that
        # is not there. GeoLite2 country blocks genuinely do not contain ISO codes.
        if "geoname_id" in index:
            raise RangeTableError(
                "this looks like a GeoLite2 country blocks CSV, which carries "
                "geoname_id rather than an ISO country code — join it against the "
                "GeoLite2-Country-Locations CSV first, or side-load the .mmdb "
                "instead")
        raise RangeTableError(
            "the header names neither a country nor an ASN column "
            f"(found: {', '.join(h for h in header if h) or 'nothing'})")
    return layout, 2


def _first_of(index: dict[str, int], names: tuple[str, ...]) -> Optional[int]:
    """First matching spelling wins, in the order the vocabulary lists them — so a
    file carrying both `country_iso_code` and `country_name` picks the code."""
    for name in names:
        if name in index:
            return index[name]
    return None


def _infer_positions(sample: list[list[str]]) -> dict:
    """Headerless file -> column positions, inferred from the shape of row 1.

    Two forms are recognised, and between them they cover the redistributable tables
    named in the module docstring: `cidr, …` and `start, end, …`. After the addresses,
    the first cell that is exactly two letters is taken as the country and the first
    that is a bare integer as the ASN.

    TWO LIMITATIONS, stated rather than papered over. In a headerless file with several
    numeric columns the FIRST integer is assumed to be the AS number; and a two-letter
    cell is assumed to be a country code, so an AS organisation literally named `BT`
    would be read as Bhutan. No redistributable table this module targets has either
    shape, and a file WITH a header is never guessed at — so the fix in both cases is
    to give the file a header row.
    """
    row = sample[0]
    layout: dict[str, Optional[int]] = {"cidr": None, "start": None, "end": None,
                                        "country": None, "asn": None}
    rest_from = 0
    if "/" in str(row[0] or ""):
        layout["cidr"] = 0
        rest_from = 1
    elif len(row) >= 2 and _looks_like_address(row[1]):
        layout["start"], layout["end"] = 0, 1
        rest_from = 2
    else:
        raise RangeTableError(
            "row 1 is neither a header nor a usable range: expected a CIDR, or a "
            f"start and end address, but found {str(row[0] or '')!r}"
            + (f" and {str(row[1])!r}" if len(row) > 1 else ""))

    # Scan EVERY sampled row, not just the first: a column is located as soon as ANY
    # sampled row carries a recognisable value there. An unrouted leading row therefore
    # costs nothing, because the next routed row finds the column.
    for candidate in sample:
        for i in range(rest_from, len(candidate)):
            cell = str(candidate[i] or "").strip()
            if layout["country"] is None and _country(cell) is not None:
                layout["country"] = i
                continue
            if layout["asn"] is None and cell.isdigit() and i != layout["country"]:
                layout["asn"] = i
        if layout["country"] is not None and layout["asn"] is not None:
            break
    if layout["country"] is None and layout["asn"] is None:
        raise RangeTableError(
            f"the first {len(sample)} row(s) carry a range but neither a 2-letter "
            f"country code nor an AS number: {row!r}")
    return layout


def _parse_row(row: list[str], layout: dict, line: int):
    """One row -> `(start_addr, end_addr, country, asn)`, or None to skip it."""
    def cell(key: str) -> str:
        i = layout.get(key)
        if i is None or i >= len(row):
            return ""
        return str(row[i] or "").strip()

    if layout.get("cidr") is not None:
        text = cell("cidr")
        if not text:
            raise RangeTableError(f"row {line}: the network column is empty")
        try:
            # strict=False so `10.1.1.5/24` is accepted as its network, matching
            # `assets/normalize.py:norm_cidr` — refusing it would be pedantry that
            # costs a declared range.
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            raise RangeTableError(f"row {line}: {text!r} is not a network") from None
        start, end = net.network_address, net.broadcast_address
    else:
        s_text, e_text = cell("start"), cell("end")
        if not s_text or not e_text:
            raise RangeTableError(
                f"row {line}: the range is incomplete (start={s_text!r}, "
                f"end={e_text!r})")
        start = parse_ip(s_text)
        end = parse_ip(e_text)
        if start is None:
            raise RangeTableError(f"row {line}: {s_text!r} is not an IP address")
        if end is None:
            raise RangeTableError(f"row {line}: {e_text!r} is not an IP address")
        if start.version != end.version:
            # Refused rather than dropped into one of the two families: the row is
            # ambiguous, and guessing would put a range in a table it does not belong
            # to where it would answer for addresses it knows nothing about.
            raise RangeTableError(
                f"row {line}: {s_text!r} is IPv{start.version} but {e_text!r} is "
                f"IPv{end.version}")
        if int(end) < int(start):
            # NOT silently swapped. A reversed pair means the file was generated or
            # edited wrongly, and a swap would hide that while inventing a range the
            # operator never wrote.
            raise RangeTableError(
                f"row {line}: the range ends before it starts ({s_text} > {e_text})")

    country = _country(cell("country")) if layout.get("country") is not None else None
    asn = _asn(cell("asn"), line) if layout.get("asn") is not None else None
    return start, end, country, asn
