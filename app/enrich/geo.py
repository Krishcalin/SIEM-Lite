# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""The geo index and the resolver: one event -> one :class:`GeoResult`.

OFFLINE. There is no socket anywhere below this line — no reverse DNS, no WHOIS, no
"just this once" HTTP fetch of a database. Every answer comes from a file the operator
side-loaded, or from arithmetic over the address itself. That is not a stylistic
preference: this runs inside the ingest write path, and a network call there converts
a slow resolver into unbounded backpressure on the queue that feeds it.

TWO LAYERS, AND THEY ARE INDEPENDENT
------------------------------------
1. SCOPE — RFC 1918 / CGNAT / loopback / link-local / multicast / documentation /
   reserved / public. Pure arithmetic over the address, so it works WITH NO DATA FILE
   AT ALL and is the layer every install gets. It produces `context_tags` only.
2. COUNTRY + ASN — needs a side-loaded database (a MaxMind-format .mmdb read by
   `app/enrich/mmdb.py`, or a CSV range table read by `app/enrich/csvdb.py`). Absent
   on a fresh install; the four columns simply stay NULL.

Layer 1 does NOT depend on layer 2, and `resolve` is written so that an empty index
still emits scope labels. Short-circuiting the whole resolver on `index.is_empty()` —
which is what the asset resolver does, and what a reader coming from that file will
reach for — would silently delete layer 1 on every install that never side-loads a
database, i.e. almost all of them. There is a test pinning this.

PURE, AND WHY THAT IS LOAD-BEARING
----------------------------------
`resolve` runs in two places: `db._row` when an event is first stored, and
`db.backfill_geo` when history is re-derived after a database is side-loaded. If those
two disagreed, a corrected row would differ from an identically-shaped fresh one for
no reason an operator could see. `app/assets/resolve.py` documents the same rule and
is why `_field` below accepts both a `NormalizedEvent` and a stored row.

CACHING — see `get_index`/`reload`. The discipline is copied from
`app/assets/registry.py` (flag and value are ONE global published under one lock; a
failed reload keeps the previous index), with ONE deliberate divergence documented at
`load`: a broken FILE is cached as a value, because unlike a transient database outage
it will fail identically on every single event.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import threading
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Optional

from .models import EMPTY_GEO, GeoResult

log = logging.getLogger("logocean")

# --------------------------------------------------------------------------- #
#  The scope layer, imported defensively                                       #
# --------------------------------------------------------------------------- #
# `ranges.scope` is the ONE thing on the hot path that comes from a sibling module, so
# it is the one import that can take the whole application down: `app/db.py` imports
# this module at top level, so an ImportError here would propagate through db into
# main and stop ingest dead. That is precisely the failure the degrade discipline
# exists to prevent — geo must cost an event its CONTEXT, never the event — so the
# import is guarded and the stub is loud rather than silent: `_SCOPE_AVAILABLE` is
# published in `stats()`, so /health says "scope classification unavailable" instead
# of every row quietly losing its labels.
try:
    from .ranges import scope as _scope           # noqa: F401  (rebound by tests)
    _SCOPE_AVAILABLE = True
except Exception as _exc:                          # noqa: BLE001 — see above
    _SCOPE_AVAILABLE = False
    log.error("app/enrich/ranges.py is unavailable (%s); events will carry NO network "
              "scope labels until it imports cleanly", _exc)

    def _scope(ip: str) -> Optional[str]:          # type: ignore[misc]
        return None


#: Bound on the per-index address memo, and the same number the asset index uses for
#: the same reason: this is a lookaside for repeated addresses inside one ingest
#: window, not a cache anything depends on, so it is cleared wholesale rather than
#: evicted LRU — a dict clear is O(1) against per-event bookkeeping.
_MEMO_MAX = 8192

#: Bumped when a change in THIS module would make stored history disagree with a fresh
#: resolution — the scope vocabulary, the role prefixes, the precedence rule. It is
#: part of the fingerprint, so bumping it makes every deployment correctly report a
#: backfill owed even though no database file changed. Nothing else can express that:
#: the files on disk are byte-identical across such a release.
_DERIVATION_VERSION = "geo1"

#: Sentinel for "not in the memo", so a memoized (None, None) is not re-looked-up.
_MISS = object()


# --------------------------------------------------------------------------- #
#  Normalization — the boundary where another module's data becomes ours       #
# --------------------------------------------------------------------------- #
def _ip_text(value: Any) -> str:
    """One event address as text `scope()`/`lookup()` can actually parse.

    Three real inputs arrive here, and only the first is the obvious one:

    * a plain string from `NormalizedEvent`;
    * an `ipaddress.IPv4Address`/`IPv6Address` OBJECT, because `db.backfill_geo`
      re-derives from `SELECT`ed rows and psycopg loads an `inet` column as an
      address object, not a string. Without the `str()` here the backfill would quietly
      resolve nothing at all while reporting `scanned=N, updated=0` — indistinguishable
      from success;
    * an `IPv4Interface` (``10.1.1.1/32``), which is what psycopg returns when the
      wire text carries a prefix — `inet` accepts one even though we never write one.

    An IPv4-MAPPED IPv6 address is unwrapped to its IPv4 form, the same rule (and for
    the same reason) as `assets.normalize.norm_ip`: dual-stack servers log
    ``::ffff:10.1.1.1`` for what is plainly ``10.1.1.1``, and a MaxMind file built
    without tree aliases answers only the IPv4 form. Unwrapping here fixes both the
    scope layer and the database layer in one place.

    REJECTED: importing `assets.normalize.norm_ip` instead of restating it. It is the
    same six lines, but it would make `app/enrich` depend on `app/assets`, and this
    package is deliberately standalone — and the contracts differ: `norm_ip` returns
    None for anything it cannot parse, whereas this passes unparseable text THROUGH so
    that the single decision about what is unparseable stays in `ranges.scope`.
    """
    s = str(value or "").strip()
    if not s:
        return ""
    if "/" in s:                       # an inet loaded as an interface: drop the prefix
        s = s.split("/", 1)[0]
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return s                       # hand it on unchanged; the callee rejects it
    mapped = getattr(addr, "ipv4_mapped", None)
    return str(mapped if mapped is not None else addr)


def norm_country(value: Any) -> Optional[str]:
    """A country code as exactly two upper-case ASCII letters, or None.

    Anything else is DROPPED rather than stored verbatim. A three-letter code, a
    country name, or an empty string that survived into the column would sit there
    forever as its own value and never match a dashboard filtering on ``'CN'`` — the
    same argument `assets.normalize_level` makes for coercing an unknown criticality
    to ``unknown`` instead of keeping the typo.

    `isascii()` as well as `isalpha()`: ``'ÉÉ'.isalpha()`` is True, and a non-ASCII
    pair is not an ISO 3166-1 alpha-2 code.
    """
    s = str(value or "").strip().upper()
    return s if len(s) == 2 and s.isalpha() and s.isascii() else None


def canonical_tags(tags: Iterable[Any]) -> tuple[str, ...]:
    """Sorted, de-duplicated, lower-cased, blank-free. The canonical form of
    ``events.context_tags``.

    EXPORTED ON PURPOSE, because that column has FOUR writers: `db._row` merges the
    asset labels with these at ingest, and `backfill_assets` and `backfill_geo` each
    re-derive the merged array afterwards. If any two of them ordered or cased the
    array differently, a no-op backfill would see `new != current` on every row and
    rewrite the entire heap — the failure `assets.resolve` already guards against with
    the same `tuple(sorted(set(...)))` one package over. One implementation shared by
    all four is the cheapest way to make that unrepresentable.

    SORTING IS NOT TIDINESS HERE. `tuple(set(...))` would ORDER BY HASH, and Python
    randomizes string hashes per process — so the array an ingest worker wrote and the
    array the backfill process re-derived from the same inputs would differ, and the
    difference would appear only in production, only across a restart.
    """
    out: set[str] = set()
    for tag in tags:
        # `None` is special-cased rather than left to `str()`, which would turn it into
        # the literal label "none" — a plausible-looking tag that no query would ever
        # be written for. A test caught exactly that.
        s = "" if tag is None else str(tag).strip().lower()
        if s:
            out.add(s)
    return tuple(sorted(out))


def norm_asn(value: Any) -> Optional[int]:
    """An AS number as a positive 32-bit int, or None.

    `bool` is rejected explicitly because `isinstance(True, int)` is True in Python and
    `int(True)` is 1 — a source that returned a boolean by mistake would otherwise
    stamp every matching event with AS 1 (Level 3), which is a plausible-looking wrong
    answer rather than a visible failure.

    A leading ``AS`` is stripped. That is deliberate leniency at the boundary, not
    sloppiness: ``AS15169`` is the ordinary spelling in every hand-maintained CSV, and
    the alternative is losing every ASN in the file silently.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, str):
        v = value.strip()
        if v[:2].upper() == "AS":
            v = v[2:]
        value = v
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    # AS 0 is reserved (RFC 7607) and 2^32-1 is the last representable value.
    return n if 1 <= n <= 4294967295 else None


# --------------------------------------------------------------------------- #
#  Sources: one loaded layer, whatever it was loaded from                      #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class GeoSource:
    """One layer the index can ask about an address.

    A thin adapter rather than a base class, because the two real implementations are
    owned by other modules and have different shapes: `mmdb.MMDBReader.get` returns a
    decoded MaxMind record, `csvdb.RangeTable.lookup` returns
    ``{'country': ..., 'asn': ...}`` already. Both become a callable of one string
    here, so `GeoIndex` has exactly one thing to iterate and a test can supply a
    literal without either class existing.

    `lookup` is an INSTANCE attribute holding a plain function, so `self.lookup(ip)`
    calls it unbound — a class-level function would bind `self` as the address.
    """

    name: str                                   # 'country' | 'asn' | 'ranges' | ...
    kind: str                                   # 'mmdb' | 'csv' | 'literal'
    lookup: Callable[[str], Optional[Mapping[str, Any]]]
    configured: str = ""                        # the path as the operator wrote it
    path: str = ""                              # ...resolved to an absolute path
    size: int = 0
    mtime_ns: int = 0
    rows: int = 0                               # csv rows / mmdb node count
    build: str = ""                             # database_type + build epoch, if known
    handle: Any = None                          # the underlying reader, for close()

    def describe(self) -> dict[str, Any]:
        """The /health view of this layer.

        Reports BOTH the configured string and the absolute path it resolved to. That
        pair is the whole diagnosis for the failure `app/main.py` already documents for
        `ingest_actions_dir`: a relative path verified at the repo root loads nothing
        under a service unit with a different WorkingDirectory, and every prescribed
        check still says ok. An operator staring at NULL country columns needs to see
        which file was actually opened.
        """
        return {"name": self.name, "kind": self.kind, "configured": self.configured,
                "path": self.path, "size": self.size, "mtime_ns": self.mtime_ns,
                "rows": self.rows, "build": self.build}

    def close(self) -> None:
        closer = getattr(self.handle, "close", None)
        if callable(closer):
            closer()


def _from_mmdb_record(rec: Any) -> Optional[dict[str, Any]]:
    """A decoded MaxMind record -> ``{'country': ..., 'asn': ...}``.

    Pure, and separate from the reader so it can be tested against literal dicts with
    no database file — which matters, because there is no real GeoLite2 file in this
    repository to test against.

    Handles the three shipped shapes in one function since they do not collide:
    GeoLite2-Country and -City carry ``country.iso_code``, GeoLite2-ASN carries
    ``autonomous_system_number``, and DB-IP's country-lite uses the Country shape.

    ``registered_country`` is the fallback: an anonymous-proxy or satellite record has
    no ``country`` key at all, and the registered country is the only answer available.
    It is a WEAKER fact (where the block is registered, not where it is used), which is
    why it is second rather than merged.
    """
    if not isinstance(rec, Mapping):
        return None
    country = None
    for key in ("country", "registered_country"):
        block = rec.get(key)
        if isinstance(block, Mapping):
            country = norm_country(block.get("iso_code"))
            if country:
                break
    asn = norm_asn(rec.get("autonomous_system_number"))
    if country is None and asn is None:
        return None
    return {"country": country, "asn": asn}


def mmdb_source(reader: Any, name: str, *, configured: str = "", path: str = "",
                size: int = 0, mtime_ns: int = 0) -> GeoSource:
    """Wrap anything with ``.get(ip) -> record`` — i.e. `mmdb.MMDBReader`, or a fake.

    The reader's exceptions are NOT caught here; `GeoIndex.lookup` catches per source
    so that one corrupt database costs an address its answer and the other layers still
    get consulted.
    """
    meta = getattr(reader, "metadata", None)
    meta = meta if isinstance(meta, Mapping) else {}
    build = f"{meta.get('database_type', '')}@{meta.get('build_epoch', '')}".strip("@")
    return GeoSource(
        name=name, kind="mmdb",
        lookup=lambda ip: _from_mmdb_record(reader.get(ip)),
        configured=configured, path=path, size=size, mtime_ns=mtime_ns,
        rows=int(meta.get("node_count") or 0), build=build, handle=reader)


def range_source(table: Any, name: str = "ranges", *, configured: str = "",
                 path: str = "", size: int = 0, mtime_ns: int = 0) -> GeoSource:
    """Wrap anything with ``.lookup(ip) -> {'country','asn'}`` — `csvdb.RangeTable`."""
    try:
        rows = len(table)
    except Exception:                            # noqa: BLE001 — cosmetic only
        rows = 0
    return GeoSource(name=name, kind="csv", lookup=table.lookup, configured=configured,
                     path=path, size=size, mtime_ns=mtime_ns, rows=rows, handle=table)


def literal_source(rows: Mapping[str, Mapping[str, Any]],
                   name: str = "literal") -> GeoSource:
    """An exact-address table from literals — for tests and for a fixture index.

    Deliberately exact-match only: containment belongs to `csvdb.RangeTable`, and a
    second implementation of it here would be a second thing to keep correct.
    """
    table = dict(rows)
    return GeoSource(name=name, kind="literal", lookup=table.get,
                     rows=len(table), handle=None)


# --------------------------------------------------------------------------- #
#  The index                                                                   #
# --------------------------------------------------------------------------- #
class GeoIndex:
    """The loaded sources, in PRECEDENCE order, plus the address memo.

    PRECEDENCE, decided here and stated once so nothing else has to guess:

    * Sources are consulted IN ORDER, and each FIELD is filled independently by the
      first source that answers it. Country and ASN routinely come from DIFFERENT
      files — MaxMind ships GeoLite2-Country and GeoLite2-ASN as separate databases —
      so "first source with a country wins, first source with an ASN wins" is the
      normal path, not an edge case.
    * A CSV range table is placed BEFORE the .mmdb files by `load`. An operator can
      edit a CSV; they cannot edit a binary database they downloaded. If the binary
      won there would be no way to correct a wrong or missing answer short of building
      an .mmdb, so the CSV is the override layer. The cost of that choice is real and
      is why `stats()` reports each layer's row count and mtime: a stale CSV left
      behind will quietly outrank a fresh GeoLite2, and the operator needs to be able
      to see it.

    THREAD SAFETY, and it is the same argument `assets.AssetIndex` makes: everything
    here is immutable after construction except `_memo` and `_state`, both of which are
    pure lookasides — every entry is re-derivable, so a racing writer can only
    duplicate work, never produce a wrong answer. `dict` get/set/clear are individually
    atomic under the GIL and nothing does a read-modify-write across a yield point.
    That is what lets the ingest workers share one index with no lock on the hot path.
    """

    __slots__ = ("sources", "errors", "fingerprint", "_memo", "_state")

    def __init__(self, sources: Iterable[GeoSource] = (),
                 errors: Iterable[str] = ()):
        self.sources: tuple[GeoSource, ...] = tuple(sources)
        #: Human-readable reasons a CONFIGURED source did not load. Carried on the
        #: index rather than raised, so `load` can return a usable partial index and
        #: /health can still say what is missing. See `load`.
        self.errors: tuple[str, ...] = tuple(errors)
        self.fingerprint = _fingerprint(self.sources)
        self._memo: dict[str, tuple[Optional[str], Optional[int]]] = {}
        self._state: dict[str, Any] = {"failures": 0, "error": None}

    # ---- lookups ---------------------------------------------------------- #
    def lookup(self, ip: str) -> tuple[Optional[str], Optional[int]]:
        """``(country, asn)`` for one already-normalized address. Never raises.

        A source that throws costs THIS ADDRESS its answer from THAT layer and nothing
        more: the loop continues to the next source, and the event keeps its scope
        labels. A corrupt .mmdb is a static file, so it will throw on every event —
        hence the rate-limited counter rather than a log line per row.

        The result is memoized including the misses, which is the point: network
        traffic revisits the same addresses constantly, and a MaxMind lookup is a
        128-step tree walk plus a record decode. A memoized failure is also NOT
        retried, which is correct for the failure that actually happens here (a broken
        file) and is the reason the memo is dropped wholesale on reload.
        """
        if not ip or not self.sources:
            return (None, None)
        memo = self._memo
        hit = memo.get(ip, _MISS)
        if hit is not _MISS:
            return hit                                    # type: ignore[return-value]

        country: Optional[str] = None
        asn: Optional[int] = None
        for src in self.sources:
            if country is not None and asn is not None:
                break
            try:
                rec = src.lookup(ip)
            except Exception as exc:                       # noqa: BLE001
                self._note_failure(src, exc)
                continue
            if not isinstance(rec, Mapping):
                continue
            if country is None:
                country = norm_country(rec.get("country"))
            if asn is None:
                asn = norm_asn(rec.get("asn"))

        if len(memo) >= _MEMO_MAX:
            memo.clear()
        out = (country, asn)
        memo[ip] = out
        return out

    def _note_failure(self, src: GeoSource, exc: Exception) -> None:
        first = self._state["failures"] == 0
        self._state["failures"] += 1
        self._state["error"] = f"{src.name}: {type(exc).__name__}: {exc}"
        if first:
            log.exception("geo source %r failed on lookup; events are being STORED "
                          "WITHOUT country/ASN rather than dropped. Re-run "
                          "db.backfill_geo() once the database file is repaired",
                          src.name)
        elif self._state["failures"] % 1000 == 0:
            log.error("geo source still failing: %d lookup(s) degraded (%s)",
                      self._state["failures"], self._state["error"])

    # ---- bookkeeping ------------------------------------------------------ #
    def __len__(self) -> int:
        return len(self.sources)

    def is_empty(self) -> bool:
        """True when NO country/ASN source is loaded.

        Read this carefully before using it as a short-circuit: it does NOT mean the
        resolver has nothing to say. Scope classification needs no file, so an empty
        index still produces `context_tags`. `resolve` gates only the country/ASN
        lookups on this.
        """
        return not self.sources

    def failures(self) -> dict[str, Any]:
        return dict(self._state)

    def close(self) -> None:
        """Release the underlying file handles.

        NOT called by `reload`, deliberately. A worker thread can be mid-lookup on an
        index it fetched a moment ago, and closing an `mmap` under it raises — costing
        exactly the events the reload was meant to improve. Refcounting already does
        the right thing: when the last in-flight lookup drops the old index, the mmap
        is unmapped. This exists for tests and for an explicit shutdown.

        ON WINDOWS a mapped file cannot be replaced in place — `os.replace` over it
        fails with WinError 5 and `os.remove` with WinError 32. Since the CURRENT index
        must keep its mapping open regardless, that constraint is inherent, not
        something closing the previous index could fix: an operator side-loading an
        update must write a NEW file and point the setting at it, or restart.
        """
        for src in self.sources:
            try:
                src.close()
            except Exception:                              # noqa: BLE001
                log.warning("geo source %r did not close cleanly", src.name,
                            exc_info=True)


def _fingerprint(sources: Iterable[GeoSource]) -> str:
    """A stable hash of everything that can change a resolution.

    `db.backfill_geo` compares this against `geo_meta.backfill_hash` to answer "has the
    database an operator side-loaded reached stored history yet?", so it must cover
    exactly what feeds an answer: which sources, in which ORDER (order is precedence,
    and reordering changes results), each one's absolute path, size, mtime and build
    string — plus `_DERIVATION_VERSION`, so a change to the label vocabulary in THIS
    file also demands a backfill even though no file on disk moved.

    SIZE + MTIME RATHER THAN A CONTENT HASH, and it is a real trade. GeoLite2-City is
    ~70 MB; hashing it costs a full read on every startup and on every reload, on the
    critical path of the application lifespan, to produce a number whose only job is
    "did the inputs change?". A new GeoLite2 build is a different file with a different
    size and mtime, so the cheap version answers that correctly for every real
    side-load. The accepted false NEGATIVE is a file swapped for one of identical size
    with its mtime preserved — a `cp -p` or a restore-in-place. That is rare, it is
    detectable by an operator (the build string in /health comes from the file's own
    metadata, so it moves even when mtime does not), and the remedy is to run the
    backfill explicitly rather than to pay 70 MB of I/O on every restart.

    NOT sorted: the sequence IS the precedence order.
    """
    h = hashlib.sha256()
    h.update(_DERIVATION_VERSION.encode("utf-8"))
    for s in sources:
        h.update(f"{s.name}\x00{s.kind}\x00{s.path}\x00{s.size}\x00{s.mtime_ns}"
                 f"\x00{s.rows}\x00{s.build}\x00".encode("utf-8"))
    return h.hexdigest()[:32]


#: The "no database side-loaded" index. Its fingerprint is a PERFECTLY VALID
#: fingerprint, not a null one, because scope labels are derived with no file at all —
#: rows written before this slice genuinely need a backfill even on an install that
#: never side-loads anything. `db.geo_status` must NOT copy the asset registry's
#: `bool(idx.assets or idx.identities)` guard, which exists there because an empty
#: registry really does derive nothing.
EMPTY_INDEX = GeoIndex()


# --------------------------------------------------------------------------- #
#  The resolver                                                                #
# --------------------------------------------------------------------------- #
def _field(evt: Any, name: str) -> Any:
    """One field of an event-like object.

    Accepts BOTH a `NormalizedEvent` and a stored row (a mapping), because
    `db.backfill_geo` re-derives straight from `SELECT`ed rows and must go through this
    same function — the whole reason this module is pure. `assets.resolve._field` and
    `cim.match` take the identical dual shape for the identical reason.
    """
    if isinstance(evt, Mapping):
        return evt.get(name)
    return getattr(evt, name, None)


def resolve(evt: Any, index: GeoIndex) -> GeoResult:
    """Geo context for one event. PURE, and never raises on a malformed event.

    Layer 1 (scope) runs unconditionally; layer 2 (country/ASN) runs only when a
    database is loaded. See the module docstring for why that split is not an
    optimization but the feature.

    NOT skipped for private addresses, and that is a deliberate cost. Gating the
    database lookup on ``scope == 'public'`` would save a tree walk on the RFC 1918
    traffic that dominates most stores — but it would also make an operator's CSV
    mapping their internal ranges to site countries unreachable, which is a legitimate
    and common use of the override layer. The memo absorbs most of the cost instead.
    """
    src = _ip_text(_field(evt, "src_ip"))
    dst = _ip_text(_field(evt, "dst_ip"))
    if not src and not dst:
        return EMPTY_GEO

    # ---- layer 1: scope labels, no data file required --------------------- #
    tags: list[str] = []
    for value, role in ((src, "src"), (dst, "dst")):
        if not value:
            continue
        try:
            label = _scope(value)
        except Exception:                                  # noqa: BLE001
            label = None                                   # never cost the event
        if label:
            # Stripped BEFORE the prefix goes on, because `canonical_tags` below can
            # only trim the ends of the finished label — a scope of "  private  " would
            # otherwise survive as "src:  private". The lower-casing is left to
            # `canonical_tags` so there is exactly one place that decides case.
            tags.append(f"{role}:{str(label).strip()}")

    # ---- layer 2: country + ASN, only when something is loaded ------------ #
    src_country = dst_country = None
    src_asn = dst_asn = None
    if not index.is_empty():
        if src:
            src_country, src_asn = index.lookup(src)
        if dst:
            dst_country, dst_asn = index.lookup(dst)

    if not tags and src_country is None and dst_country is None \
            and src_asn is None and dst_asn is None:
        return EMPTY_GEO

    # Canonical, so a row re-derived by `db.backfill_geo` is byte-identical to the same
    # row written at ingest — and so the merge in `db._row` against the asset labels
    # starts from a clean set on both sides. See `canonical_tags`.
    return GeoResult(src_country=src_country, dst_country=dst_country,
                     src_asn=src_asn, dst_asn=dst_asn,
                     context_tags=canonical_tags(tags))


# --------------------------------------------------------------------------- #
#  Loading and caching                                                         #
# --------------------------------------------------------------------------- #
_lock = threading.Lock()
_cache: Optional[GeoIndex] = None
#: Bumped on every successful install. Lets a caller notice a reload happened under it
#: without comparing whole indexes.
_generation = 0


def _stat(path: str) -> tuple[int, int]:
    try:
        st = os.stat(path)
        return st.st_size, st.st_mtime_ns
    except OSError:
        return 0, 0


#: The `Settings` fields this module reads, in PRECEDENCE order — the override layer
#: first. `load` iterates this, so the order is stated exactly once.
_GEO_SETTINGS = ("geo_ranges_csv", "geo_country_db", "geo_asn_db")


def _settings() -> Any:
    """`app.config.settings`, or None if it cannot be imported."""
    try:
        from ..config import settings
    except Exception:                                      # noqa: BLE001
        return None
    return settings


def _setting(name: str) -> str:
    """One geo path from `app.config.settings`.

    Through `getattr` with a default because the settings fields are added by the
    wiring change, not by this module.

    Deliberately NOT `os.getenv`: `tests/test_wiring.py` extracts every env var from
    the source of `app/config.py` alone and asserts the set matches `.env.example`
    both ways, so a variable read here would fail that check from the documented side.
    """
    cfg = _settings()
    return str(getattr(cfg, name, "") or "").strip() if cfg is not None else ""


def _settings_wired() -> bool:
    """Whether `Settings` carries the geo fields at all.

    `getattr(settings, name, "")` cannot tell "the operator configured nothing" from
    "the field was never added, or was added under a different name" — both are the
    empty string, and both look exactly like a healthy install whose country columns
    happen to be NULL. That is the same shape as the `ingest_actions_dir` incident this
    repository already documents: every prescribed check said ok while the feature was
    silently doing nothing. So the two are distinguished here and `load` records the
    mis-wired case as an error /health can show.
    """
    cfg = _settings()
    return cfg is not None and any(hasattr(cfg, n) for n in _GEO_SETTINGS)


def _open_mmdb(raw: str, name: str) -> GeoSource:
    """Open one MaxMind-format database. Raises; `load` catches per source."""
    from .mmdb import MMDBReader                           # Group A's module
    path = os.path.abspath(os.path.expanduser(raw))
    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"{path} (configured as {raw!r}, resolved against cwd {os.getcwd()!r})")
    size, mtime_ns = _stat(path)
    reader = MMDBReader(path)
    return mmdb_source(reader, name, configured=raw, path=path, size=size,
                       mtime_ns=mtime_ns)


def _open_csv(raw: str, name: str = "ranges") -> GeoSource:
    """Open one CSV range table. Raises; `load` catches per source."""
    from .csvdb import RangeTable                          # Group B's module
    path = os.path.abspath(os.path.expanduser(raw))
    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"{path} (configured as {raw!r}, resolved against cwd {os.getcwd()!r})")
    size, mtime_ns = _stat(path)
    table = RangeTable.load(path)
    return range_source(table, name, configured=raw, path=path, size=size,
                        mtime_ns=mtime_ns)


def load() -> GeoIndex:
    """Open every configured source, in precedence order.

    DOES NOT RAISE FOR A BAD FILE, and this is the one place the discipline diverges
    from `app/assets/registry.py`. There, failure is not cached because it means the
    DATABASE is unreachable — transient, and memoizing would keep the registry dark
    after it came back. Here a failure means a FILE will not parse: it is static, it
    will fail identically on every single event, and not caching it would re-open and
    re-parse a 70 MB database per row while logging at full ingest rate. So a per-source
    failure becomes a VALUE — an entry in `index.errors` — and the index is built and
    cached from whatever did load. /health reports the errors; the events keep their
    scope labels.

    The order is the precedence order: the CSV override layer first, then country, then
    ASN. See `GeoIndex`.
    """
    openers = {"geo_ranges_csv": ("ranges", _open_csv),
               "geo_country_db": ("country", _open_mmdb),
               "geo_asn_db": ("asn", _open_mmdb)}

    sources: list[GeoSource] = []
    errors: list[str] = []
    configured = False
    for setting_name in _GEO_SETTINGS:                     # precedence order
        raw = _setting(setting_name)
        if not raw:
            continue
        configured = True
        name, opener = openers[setting_name]
        try:
            sources.append(opener(raw, name))
        except Exception as exc:                           # noqa: BLE001 — see docstring
            errors.append(f"{name}: {type(exc).__name__}: {exc}")
            log.error("geo source %r could not be loaded from %r: %s", name, raw, exc)

    if not configured and not _settings_wired():
        # NOT the same as "the operator side-loaded nothing", which is the ordinary
        # state and carries no error at all. This says the settings fields are absent
        # from `Settings` — a wiring defect that is otherwise indistinguishable from a
        # healthy install with NULL country columns, forever.
        msg = ("config: app.config.Settings declares none of "
               f"{', '.join(_GEO_SETTINGS)} — a side-loaded geo database can never be "
               "found until those fields exist")
        log.error(msg)
        errors.append(msg)
    return GeoIndex(sources, errors)


def get_index() -> GeoIndex:
    """The cached index. Degrades to an EMPTY index rather than raising.

    Never propagating is the rule `assets.get_index` and `db._cim_tags` both follow,
    for the same reason: this runs inside the write path, so a geo layer that cannot be
    built must cost an event its CONTEXT, never the event itself.

    Because `load` turns a bad FILE into a value, the `except` below only fires on a
    genuine defect in this module — which is exactly the case where NOT caching (retry
    next call) is right, since a fixed deployment recovers without a restart.
    """
    global _cache
    if _cache is not None:
        return _cache
    with _lock:
        if _cache is not None:
            return _cache
        try:
            _cache = load()
        except Exception as exc:                           # noqa: BLE001 — see docstring
            log.warning("geo index unavailable, events will store no country/ASN "
                        "until it loads: %s", exc)
            return EMPTY_INDEX                             # NOT cached — retry next call
        return _cache


def reload() -> GeoIndex:
    """Rebuild from the configured files. Called at startup and after a side-load.

    A FAILED RELOAD KEEPS THE PREVIOUS INDEX — including the shape `load` produces
    instead of an exception. If every configured source failed while the previous index
    had working ones, installing the new empty index would silently strip country and
    ASN from every event ingested afterwards, and those rows would look
    resolved-to-nothing rather than unresolved: an empty index's fingerprint is a
    perfectly valid fingerprint, so no staleness check would ever flag them.

    A reload that loads nothing and reports NO errors is an operator deliberately
    unconfiguring the paths, and that is honoured.

    A PARTIAL failure (country loaded, ASN did not) IS installed, with the error
    published. REJECTED: carrying the previous index's working sources forward
    per-layer. It would mix two generations of files under one fingerprint, so
    `backfill_geo` could not say what history was derived under — a worse failure than
    a visibly missing layer.
    """
    global _cache, _generation
    with _lock:
        try:
            index = load()
        except Exception as exc:                           # noqa: BLE001
            log.error("geo reload failed, keeping the previous index (%d source(s)): %s",
                      len(_cache.sources) if _cache else 0, exc)
            return _cache if _cache is not None else EMPTY_INDEX
        if index.is_empty() and index.errors and _cache is not None \
                and not _cache.is_empty():
            log.error("geo reload produced no usable source (%s); keeping the previous "
                      "index (%d source(s), fingerprint %s)",
                      "; ".join(index.errors), len(_cache.sources), _cache.fingerprint)
            return _cache
        _cache = index
        _generation += 1
        log.info("geo index loaded: %d source(s) [%s], %d error(s), fingerprint %s",
                 len(index.sources), ", ".join(s.name for s in index.sources) or "none",
                 len(index.errors), index.fingerprint)
        return index


def generation() -> int:
    return _generation


def set_index(index: Optional[GeoIndex]) -> None:
    """Install an index directly — for tests, and for `db.backfill_geo`, which pins one
    index for the whole run so a concurrent reload cannot make the first half of a
    backfill disagree with the second."""
    global _cache, _generation
    with _lock:
        _cache = index
        _generation += 1


def stats() -> dict[str, Any]:
    """What is loaded, from where, and what is degraded — for /health and the console.

    `mode` is the field an operator actually needs: ``scope-only`` says the four
    columns will stay NULL by configuration rather than by fault, which is the answer
    to "why is src_country empty?" on every install that has not side-loaded a
    database. `scope_available` is False only when `app/enrich/ranges.py` failed to
    import, which would silently cost every row its labels — see the guarded import at
    the top of this file.
    """
    index = _cache
    if index is None:
        return {"loaded": False, "mode": "unloaded", "sources": [], "errors": [],
                "fingerprint": None, "scope_available": _SCOPE_AVAILABLE,
                "generation": _generation, "lookup_failures": 0, "lookup_error": None}
    state = index.failures()
    return {"loaded": True,
            "mode": "scope-only" if index.is_empty() else "scope+country/asn",
            "sources": [s.describe() for s in index.sources],
            "errors": list(index.errors),
            "fingerprint": index.fingerprint,
            "scope_available": _SCOPE_AVAILABLE,
            "generation": _generation,
            "lookup_failures": state["failures"],
            "lookup_error": state["error"]}
