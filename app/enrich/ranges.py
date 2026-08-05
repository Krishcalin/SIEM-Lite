# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Special-purpose address classification — the geo layer that needs NO data file.

This is the piece an operator meets first. A fresh install has no GeoLite2 database
and no side-loaded CSV, so `country` and `asn` stay NULL — but `scope()` still answers
"is this address internal, carrier-NAT, multicast or genuinely routable?" from the
RFCs alone, and that answer is what makes the first useful detections possible:
*inbound from a public address to a critical asset*, *outbound to a public address
from a segment that should never egress*, *RFC 1918 traffic arriving on an internet-
facing collector*.

WHY AN EXPLICIT TABLE INSTEAD OF `ipaddress`'s OWN PROPERTIES
------------------------------------------------------------
The obvious implementation is `if addr.is_private: return 'private'`, and it is
wrong in two ways that a test would only catch if it happened to be written on the
right Python build. Both were MEASURED on this machine (CPython 3.12.10):

  * `is_private` LUMPS TOGETHER things this product must keep apart. `192.0.2.5`
    (TEST-NET-1 documentation), `240.0.0.1` (reserved), `127.0.0.1` (loopback),
    `169.254.1.1` (link-local) and `::1` all report `is_private == True`. A
    private-first branch therefore labels documentation and reserved space as
    "private", which is precisely the distinction an egress rule cares about.
  * THE STDLIB'S ANSWERS MOVE BETWEEN PATCH RELEASES. `100.64.0.1` (CGNAT) reports
    `is_private == False` AND `is_global == False` here — it is in neither table,
    because gh-113171 moved it out of `_private_networks` into a `_public_network`
    exception consulted only by `is_global`. This build also carries RFC 9637's
    `3fff::/20` and a `_private_networks_exceptions` list that older 3.12 patch
    releases do not have. Deriving stored, backfilled columns from a vocabulary that
    shifts under a Python upgrade would mean an upgrade silently reclassifies
    history, and nothing would flag it — `geo_meta`'s fingerprint covers the DATA
    FILE, not the interpreter.

So the vocabulary below is spelled out as CIDRs from the RFCs and the IANA
special-purpose registries. It is deterministic, it is the same on every interpreter,
and it is diffable in review.

PRECEDENCE, AND WHY THERE ISN'T ANY
-----------------------------------
Overlapping classifications are the classic source of order-dependent bugs here
("is 192.0.2.5 documentation or private?"), and the usual fix is to fix an order and
hope nobody reshuffles the list. This module removes the question instead: the two
tables are PAIRWISE DISJOINT by construction, so no address matches two entries and
the result cannot depend on ordering at all. `test_enrich_sources.py` proves the
disjointness rather than assuming it, and separately pins the answer for every
address where the stdlib would have disagreed — so a future "simplification" back to
`is_private` fails loudly instead of quietly relabelling half the reserved space.

Because the table is disjoint it can be searched by bisection over integers instead
of by `addr in net` over objects. MEASURED, per call: 12.1 us for a linear scan of 20
networks, 0.097 us for the bisection, 5.6 us for the `ipaddress` parse that precedes
either, and 0.028 us for a memo hit. Those numbers set the whole design — the parse
dominates, which is why the memo keys on the ORIGINAL TEXT and short-circuits before
parsing, exactly as `assets/index.py` memoizes CIDR containment and for the same
reason: network traffic revisits the same addresses relentlessly.
"""
from __future__ import annotations

import ipaddress
from bisect import bisect_right
from typing import Optional, Union

_Address = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

#: The closed vocabulary `scope()` can return. Published so the resolver can build
#: context tags without re-deriving the list, and so a test can assert every label is
#: actually reachable — a label nothing produces is a rule nobody can write.
SCOPE_LABELS: tuple[str, ...] = (
    "private", "loopback", "link-local", "cgnat", "multicast",
    "documentation", "reserved", "public",
)

#: The label for everything that matches no special-purpose range. Named because it
#: is the answer for the overwhelming majority of interesting traffic and the one a
#: detection is most likely to gate on.
PUBLIC = "public"

# --------------------------------------------------------------------------- #
#  The tables. Disjoint by construction — see the module docstring.            #
# --------------------------------------------------------------------------- #
# IPv4, from RFC 6890 / the IANA IPv4 Special-Purpose Address Registry.
_V4_RANGES: tuple[tuple[str, str], ...] = (
    ("0.0.0.0/8",        "reserved"),      # "this network"; contains 0.0.0.0 itself
    ("10.0.0.0/8",       "private"),       # RFC 1918
    ("100.64.0.0/10",    "cgnat"),         # RFC 6598 carrier-grade NAT
    ("127.0.0.0/8",      "loopback"),
    ("169.254.0.0/16",   "link-local"),    # RFC 3927 (and cloud metadata at .169.254)
    ("172.16.0.0/12",    "private"),       # RFC 1918
    ("192.0.0.0/24",     "reserved"),      # IETF protocol assignments
    ("192.0.2.0/24",     "documentation"), # TEST-NET-1
    ("192.88.99.0/24",   "reserved"),      # deprecated 6to4 relay anycast, RFC 7526
    ("192.168.0.0/16",   "private"),       # RFC 1918
    ("198.18.0.0/15",    "reserved"),      # benchmarking, RFC 2544
    ("198.51.100.0/24",  "documentation"), # TEST-NET-2
    ("203.0.113.0/24",   "documentation"), # TEST-NET-3
    ("224.0.0.0/4",      "multicast"),
    ("240.0.0.0/4",      "reserved"),      # future use; contains 255.255.255.255
)

# IPv6. `2001::/23` is used whole rather than enumerating Teredo, benchmarking and
# ORCHID separately: they are all "reserved" here, and one entry cannot overlap its
# own children. Note 2001:db8::/32 sits OUTSIDE that /23 (0x0db8 > 0x01ff), so
# documentation is not swallowed by it.
_V6_RANGES: tuple[tuple[str, str], ...] = (
    ("::/128",           "reserved"),      # unspecified
    ("::1/128",          "loopback"),
    ("64:ff9b::/96",     "reserved"),      # NAT64 well-known prefix, RFC 6052
    ("64:ff9b:1::/48",   "reserved"),      # local-use NAT64, RFC 8215
    ("100::/64",         "reserved"),      # discard-only, RFC 6666
    ("2001::/23",        "reserved"),      # IETF protocol assignments (incl. Teredo)
    ("2001:db8::/32",    "documentation"),
    ("2002::/16",        "reserved"),      # 6to4 — see the tunnel note below
    ("3fff::/20",        "documentation"), # RFC 9637
    ("fc00::/7",         "private"),       # ULA, contains fd00::/8
    ("fe80::/10",        "link-local"),
    ("fec0::/10",        "private"),       # deprecated site-local, RFC 3879
    ("ff00::/8",         "multicast"),
)


def _build(spec: tuple[tuple[str, str], ...]) -> tuple[list[int], list[int], list[str]]:
    """CIDR text -> three parallel sorted lists, the form `bisect` searches.

    Parallel lists rather than a list of tuples so the bisection compares bare ints
    with no tuple unpacking per probe; the arrays are tiny and built once at import.
    """
    rows = []
    for cidr, label in spec:
        net = ipaddress.ip_network(cidr)
        rows.append((int(net.network_address), int(net.broadcast_address), label))
    rows.sort()
    return [r[0] for r in rows], [r[1] for r in rows], [r[2] for r in rows]


_V4_STARTS, _V4_ENDS, _V4_LABELS = _build(_V4_RANGES)
_V6_STARTS, _V6_ENDS, _V6_LABELS = _build(_V6_RANGES)

#: Bound on the text -> label memo. Cleared wholesale rather than evicted LRU, for the
#: reason `assets/index.py:_MEMO_MAX` gives: this is a lookaside for repeated
#: addresses inside one ingest window, every entry is re-derivable from immutable
#: data, and a dict clear is O(1) against the bookkeeping an LRU would cost on every
#: event. Thread-safe by the same argument — `dict` get/set/clear are individually
#: atomic under the GIL and nothing here reads-then-writes across a yield point, so a
#: racing worker can duplicate work but never produce a wrong label.
_MEMO_MAX = 8192
_memo: dict[str, Optional[str]] = {}

#: Sentinel distinguishing "not memoized" from "memoized as None". `dict.get(s)`
#: alone cannot: a genuine None answer would be re-derived on every event.
_MISS = object()


def parse_ip(value: object) -> Optional[_Address]:
    """Text (or an `ipaddress` object) -> an address, or None if it is not one.

    Shared with `csvdb.py` so the CSV side and the built-in side agree on what an
    address is, character for character.

    TWO PIECES OF DELIBERATE LENIENCY, both closing a real failure mode:

    * AN IPv4-MAPPED IPv6 ADDRESS IS UNWRAPPED, matching `assets/normalize.py:norm_ip`
      exactly. `::ffff:10.1.1.1` is scoped as `10.1.1.1` — private, not "reserved
      IPv6 space". Dual-stack listeners and JVM servers log the mapped form for
      plainly IPv4 traffic, and classifying half a host's traffic differently from the
      other half by transport accident is worse than useless. Divergence from
      `norm_ip` here would be a silent one: the asset registry would resolve the host
      and geo would not.
    * A PREFIX IS TOLERATED ON A HOST ADDRESS. `events.src_ip` is a Postgres `inet`,
      and psycopg loads `inet` as `IPv4Interface` when the wire text contains a `/`.
      The backfill hands this function whatever the column produced. `str()` of an
      interface is `10.0.0.1/32`, which `ip_address` refuses — so without this branch
      the geo backfill would report `scanned=N, updated=0` and look exactly like
      success while doing nothing at all.

    6to4 (`2002::/16`) and Teredo (`2001::/32`) are NOT unwrapped, and that is a
    choice with a cost. Both embed an IPv4 address, so unwrapping would yield a
    country. But the embedded address is the TUNNEL ENDPOINT rather than the peer,
    and Teredo's is bitwise-inverted — a naive read of those bits is not merely
    unhelpful, it is a different address. Reporting the tunnel honestly as reserved
    beats attributing traffic to whoever owns the relay.
    """
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        addr: _Address = value
    else:
        s = str(value or "").strip()
        if not s:
            return None
        try:
            addr = ipaddress.ip_address(s)
        except ValueError:
            # Only reached for text `ip_address` rejected; the `inet`-with-prefix case
            # above, and genuine junk, which still ends at None.
            try:
                addr = ipaddress.ip_interface(s).ip
            except ValueError:
                return None
    mapped = getattr(addr, "ipv4_mapped", None)
    return mapped if mapped is not None else addr


def scope(ip: object) -> Optional[str]:
    """Classify one address: a `SCOPE_LABELS` member, or None if it is not an address.

    None and `'public'` are DIFFERENT ANSWERS and callers must keep them apart. None
    means "this field held something that is not an address" — an empty column, a
    hostname, a truncated log line — and must produce no tag at all. `'public'` is a
    positive finding about real routable space and is exactly what an egress rule
    keys on. Collapsing None into `'public'` would tag every event with an
    unparseable address as internet-facing.

    The annotation is `object` rather than `str`: the frozen contract says `str`, and
    every string caller behaves identically, but widening the input is what stops the
    backfill's `IPv4Address`/`IPv4Interface` objects from failing silently (see
    `parse_ip`). Widening an accepted type breaks no caller.
    """
    s = str(ip or "").strip()
    if not s:
        return None
    memo = _memo
    hit = memo.get(s, _MISS)
    if hit is not _MISS:
        return hit                      # 0.028 us; the parse below is 5.6 us

    addr = parse_ip(s)
    if addr is None:
        label = None
    elif addr.version == 4:
        label = _search(int(addr), _V4_STARTS, _V4_ENDS, _V4_LABELS)
    else:
        label = _search(int(addr), _V6_STARTS, _V6_ENDS, _V6_LABELS)

    # Unparseable input is memoized too, and on purpose: a broken parser emitting the
    # same junk on every line is exactly the case where the 5.6 us parse would
    # otherwise be paid forever.
    if len(memo) >= _MEMO_MAX:
        memo.clear()
    memo[s] = label
    return label


def _search(value: int, starts: list[int], ends: list[int],
            labels: list[str]) -> str:
    """The bisection. Exact because the table is disjoint.

    `bisect_right - 1` gives the last range whose START is at or below the address;
    since no two ranges overlap, that is the ONLY range that can contain it, so one
    end-check decides the answer. On an overlapping table this shape would be wrong
    (a narrow range could hide a wider one that also contains the address) — which is
    why `csvdb.py`, whose input is a file it does not control, flattens to disjoint
    segments before reusing this same primitive.
    """
    i = bisect_right(starts, value) - 1
    if i >= 0 and value <= ends[i]:
        return labels[i]
    return PUBLIC


def reset_memo() -> None:
    """Drop the lookaside. For tests that want to measure the cold path; the answers
    are identical either way, so nothing in production needs to call it."""
    _memo.clear()


def memo_size() -> int:
    """Entries currently memoized — for `/health`, so an operator can see the cache is
    doing something rather than take it on faith."""
    return len(_memo)
