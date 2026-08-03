# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Sigma-compatible detection engine — a native subset evaluator.

Loads YAML detection rules (a practical subset of the Sigma format) and matches
them against a flattened event dict in pure Python, so detection runs inline in
the ingest pipeline (real-time) and is fully unit-testable without a database or
query backend.

Supported subset
----------------
- ``logsource``: matched against our normalized ``vendor`` / ``product`` /
  ``log_type`` (Sigma ``product``/``service`` are mapped; our own ``vendor`` /
  ``log_type`` keys may be used directly for precise control).
- ``datamodels`` (LogOcean extension): bind the rule to CIM data models
  (:mod:`app.cim`) instead of to a vendor — ``datamodels: web`` fires on every
  event the registry calls Web, whatever product emitted it. A string or a list;
  several models mean ANY of them; omitted means unbound, i.e. match-all.
- ``detection`` selections: a map (AND of field:value), a list of maps (OR), or a
  list of bare strings (keywords searched across all fields).
- value lists = OR (any); the ``|all`` modifier turns a list into AND.
- field modifiers: ``contains`` / ``startswith`` / ``endswith`` / ``re``
  (with ``i`` / ``m`` / ``s`` flags) / ``cased``; ``*`` and ``?`` glob in plain
  values; ``null`` for absent/empty.
- comparison & set modifiers: ``cidr`` (IP-in-network), ``lt`` / ``lte`` /
  ``gt`` / ``gte`` (numeric), ``exists`` (field present, bool), ``fieldref``
  (compare to another field's value).
- encoding modifiers (for command-line obfuscation): ``base64`` /
  ``base64offset`` and ``windash`` (``-flag`` ↔ ``/flag`` / unicode dashes),
  typically chained with ``|contains``.
- ``condition``: ``and`` / ``or`` / ``not`` / parentheses, plus ``1 of`` /
  ``all of`` / ``N of`` over ``them`` or a ``selection_*`` wildcard.
- ``tags``: ``attack.tNNNN[.NNN]`` → techniques, ``attack.<tactic>`` → tactics.
"""
from __future__ import annotations

import base64
import ipaddress
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

import yaml

from ..models import NormalizedEvent

log = logging.getLogger("logocean")

# Sigma field name (lowercased) -> our normalized field, used as a lookup fallback.
_FIELD_ALIASES = {
    "sourceip": "src_ip", "srcip": "src_ip", "source_ip": "src_ip", "src": "src_ip",
    "destinationip": "dst_ip", "dstip": "dst_ip", "destination_ip": "dst_ip", "dst": "dst_ip",
    "sourceport": "src_port", "srcport": "src_port",
    "destinationport": "dst_port", "dstport": "dst_port",
    "user": "user_name", "username": "user_name", "account": "user_name",
    "computername": "host_name", "hostname": "host_name", "host": "host_name",
    "msg": "message",
}

# Sigma logsource.product -> acceptable values of our `vendor`.
_PRODUCT_VENDOR = {
    "windows": {"microsoft"}, "linux": {"linux", "syslog"},
    "aws": {"aws"}, "gcp": {"gcp"}, "azure": {"microsoft"},
}

_TECH_RE = re.compile(r"t\d{4}(?:\.\d{3})?$", re.IGNORECASE)
# MITRE ATLAS technique tag: `atlas.aml.tNNNN[.NNN]`.
_ATLAS_RE = re.compile(r"aml\.t\d{4}(?:\.\d{3})?$", re.IGNORECASE)
_FIDELITY = {"high", "medium", "hunt"}


# --------------------------------------------------------------------------- #
#  Event flattening + field lookup                                            #
# --------------------------------------------------------------------------- #
_NORMALIZED_FIELDS = (
    "vendor", "product", "log_type", "severity", "action", "src_ip", "dst_ip",
    "src_port", "dst_port", "protocol", "app", "user_name", "host_name",
    "rule_name", "bytes_total", "message",
)


def flatten_event(evt: NormalizedEvent) -> dict[str, Any]:
    """One lowercased dict of the normalized fields plus the (flattened) raw
    record. Normalized fields win on key clashes; list values are preserved so a
    modifier can match any element."""
    flat: dict[str, Any] = {}
    for k in _NORMALIZED_FIELDS:
        v = getattr(evt, k)
        if v is not None:
            flat[k] = v
    _flatten_raw(evt.raw, "", flat)
    return flat


def _flatten_raw(obj: Any, prefix: str, out: dict, depth: int = 0) -> None:
    if depth > 16 or not isinstance(obj, dict):
        return
    for k, v in obj.items():
        key = (prefix + str(k)).lower()
        if isinstance(v, dict):
            _flatten_raw(v, key + ".", out, depth + 1)
        else:
            out.setdefault(key, v)  # don't clobber a normalized field


def _lookup(flat: dict, name: str) -> Any:
    n = name.lower()
    if n in flat:
        return flat[n]
    alias = _FIELD_ALIASES.get(n)
    return flat.get(alias) if alias else None


# --------------------------------------------------------------------------- #
#  Value / selection matching                                                 #
# --------------------------------------------------------------------------- #
def _glob_to_re(e: str) -> str:
    out = []
    for ch in e:
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
    return "".join(out)


def _as_bool(v: Any) -> bool:
    return v if isinstance(v, bool) else str(v).strip().lower() in ("true", "1", "yes")


def _to_num(v: Any) -> Optional[float]:
    try:
        return float(str(v).strip())
    except (TypeError, ValueError):
        return None


def _match_numeric(x: Any, expected: Any, op: str) -> bool:
    a, b = _to_num(x), _to_num(expected)
    if a is None or b is None:
        return False
    return {"lt": a < b, "lte": a <= b, "gt": a > b, "gte": a >= b}[op]


def _match_cidr(x: Any, network: Any) -> bool:
    try:
        return ipaddress.ip_address(str(x).strip()) in \
            ipaddress.ip_network(str(network).strip(), strict=False)
    except ValueError:
        return False


def _re_flags(mods: list[str], cased: bool) -> int:
    flags = 0 if cased else re.IGNORECASE       # plain matching is case-insensitive
    if "i" in mods:
        flags |= re.IGNORECASE
    if "m" in mods:
        flags |= re.MULTILINE
    if "s" in mods:
        flags |= re.DOTALL
    return flags


def _base64offset(s: str) -> list[str]:
    """The three base64 encodings of `s` at byte offsets 0/1/2, so a `contains`
    match catches the value embedded anywhere in a larger base64 blob (the same
    scheme pysigma uses)."""
    raw = s.encode("utf-8", "ignore")
    starts, ends = (0, 2, 3), (None, -3, -2)
    return [base64.b64encode(b" " * i + raw)[starts[i]:ends[i]].decode("ascii", "ignore")
            for i in range(3)]


_DASHES = ("-", "/", "–", "—", "―")


def _windash(s: str) -> list[str]:
    """Variants of `s` with every ``-`` replaced by each Windows dash alias
    (so a rule written with ``-flag`` also matches ``/flag``)."""
    if "-" not in s:
        return [s]
    return [s.replace("-", d) for d in _DASHES]


def _expand_expected(e: Any, mods: list[str]) -> list[Any]:
    """Apply encoding modifiers to one expected value, yielding match candidates."""
    if e is None:
        return [None]
    vals = [str(e)]
    if "base64offset" in mods:
        vals = _base64offset(str(e))
    elif "base64" in mods:
        vals = [base64.b64encode(str(e).encode("utf-8", "ignore")).decode("ascii")]
    if "windash" in mods:
        vals = [w for v in vals for w in _windash(v)]
    return vals


def _match_scalar(x: Any, expected: Any, op: Optional[str], cased: bool,
                  re_flags: int = re.IGNORECASE, cidr: bool = False) -> bool:
    if cidr:
        return _match_cidr(x, expected)
    if expected is None:
        return x is None or x == ""
    if x is None:
        return False
    s, e = str(x), str(expected)
    if op == "re":
        try:
            return re.search(e, s, re_flags) is not None
        except re.error:                       # an invalid rule pattern never matches
            return False
    if not cased:
        s, e = s.lower(), e.lower()
    if op == "contains":
        return e in s
    if op == "startswith":
        return s.startswith(e)
    if op == "endswith":
        return s.endswith(e)
    if "*" in e or "?" in e:
        return re.fullmatch(_glob_to_re(e), s, re.DOTALL) is not None
    return s == e


def _match_value(val: Any, expected: Any, op: Optional[str], cased: bool,
                 re_flags: int = re.IGNORECASE, cidr: bool = False) -> bool:
    vals = val if isinstance(val, list) else [val]
    return any(_match_scalar(x, expected, op, cased, re_flags, cidr) for x in vals)


def _eval_field(flat: dict, fieldspec: str, expected: Any) -> bool:
    parts = fieldspec.split("|")
    mods = [m.lower() for m in parts[1:]]
    val = _lookup(flat, parts[0])
    cased = "cased" in mods

    # boolean / relational modifiers handled outside the string-match path
    if "exists" in mods:
        return (val not in (None, "")) == _as_bool(expected)
    if "fieldref" in mods:
        refs = expected if isinstance(expected, list) else [expected]
        return any(_match_value(val, _lookup(flat, str(r)), None, cased) for r in refs)

    num = next((m for m in mods if m in ("lt", "lte", "gt", "gte")), None)
    if num:
        es = expected if isinstance(expected, list) else [expected]
        res = [_match_numeric(val, e, num) for e in es]
        return all(res) if "all" in mods else any(res)

    cidr = "cidr" in mods
    re_flags = _re_flags(mods, cased)
    op = ("re" if "re" in mods else
          next((m for m in mods if m in ("contains", "startswith", "endswith")), None))

    expecteds = expected if isinstance(expected, list) else [expected]
    results = []
    for e in expecteds:
        cands = _expand_expected(e, mods)
        results.append(any(_match_value(val, c, op, cased, re_flags, cidr) for c in cands))
    return all(results) if "all" in mods else any(results)


def _keyword_match(flat: dict, kw: Any) -> bool:
    k = str(kw).lower()
    for v in flat.values():
        for x in (v if isinstance(v, list) else [v]):
            if x is not None and k in str(x).lower():
                return True
    return False


def _eval_selection(flat: dict, sel: Any) -> bool:
    if isinstance(sel, dict):
        return all(_eval_field(flat, k, v) for k, v in sel.items())
    if isinstance(sel, list):
        return any(_eval_selection(flat, item) if isinstance(item, dict)
                   else _keyword_match(flat, item) for item in sel)
    return False


# --------------------------------------------------------------------------- #
#  Condition grammar (recursive descent over the selection results)           #
# --------------------------------------------------------------------------- #
class _Cond:
    def __init__(self, tokens: list[str], sel: dict[str, bool]):
        self.toks, self.i, self.sel = tokens, 0, sel

    def _peek(self) -> Optional[str]:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def _next(self) -> Optional[str]:
        t = self._peek()
        self.i += 1
        return t

    def parse(self) -> bool:
        return self._or()

    def _or(self) -> bool:
        v = self._and()
        while (t := self._peek()) and t.lower() == "or":
            self._next()
            v = self._and() or v
        return v

    def _and(self) -> bool:
        v = self._not()
        while (t := self._peek()) and t.lower() == "and":
            self._next()
            v = self._not() and v
        return v

    def _not(self) -> bool:
        if (t := self._peek()) and t.lower() == "not":
            self._next()
            return not self._not()
        return self._atom()

    def _atom(self) -> bool:
        t = self._peek()
        if t == "(":
            self._next()
            v = self._or()
            if self._peek() == ")":
                self._next()
            return v
        if t and (t.lower() == "all" or t.isdigit()) and \
                self.i + 1 < len(self.toks) and self.toks[self.i + 1].lower() == "of":
            qty = self._next()
            self._next()                       # consume 'of'
            return self._quantify(qty, self._next())
        self._next()
        return self.sel.get(t, False)

    def _quantify(self, qty: str, pattern: Optional[str]) -> bool:
        if pattern == "them":
            names = list(self.sel)
        elif pattern and pattern.endswith("*"):
            names = [n for n in self.sel if n.startswith(pattern[:-1])]
        else:
            names = [pattern] if pattern else []
        hits = sum(1 for n in names if self.sel.get(n, False))
        if qty.lower() == "all":
            return bool(names) and hits == len(names)
        return hits >= int(qty)


def _eval_condition(condition: str, sel: dict[str, bool]) -> bool:
    tokens = condition.replace("(", " ( ").replace(")", " ) ").split()
    if not tokens:
        return bool(sel) and all(sel.values())
    return _Cond(tokens, sel).parse()


# --------------------------------------------------------------------------- #
#  Logsource matching                                                         #
# --------------------------------------------------------------------------- #
def _logsource_matches(ls: dict, flat: dict) -> bool:
    if not ls:
        return True

    def ok(field_name: str, want: Any) -> bool:
        got = flat.get(field_name)
        return got is not None and str(got).lower() == str(want).lower()

    if "vendor" in ls and not ok("vendor", ls["vendor"]):
        return False
    if "log_type" in ls and not ok("log_type", ls["log_type"]):
        return False
    if "service" in ls and not ok("log_type", ls["service"]):
        return False
    if "product" in ls:
        want = str(ls["product"]).lower()
        mapped = _PRODUCT_VENDOR.get(want, set())
        gv = flat.get("vendor")
        if not (ok("product", ls["product"]) or (gv and str(gv).lower() in mapped)):
            return False
    return True


# --------------------------------------------------------------------------- #
#  CIM data-model gate                                                        #
# --------------------------------------------------------------------------- #
# `logsource:` names the source that produced an event; `datamodels:` names what the
# event *is*. Binding to the second is the point of the CIM layer: one Web rule
# covers Apache, nginx, Zeek http, a PAN URL-filtering log and a proxy, and onboarding
# the next web source is a registry edit rather than an edit to every web rule.
#
# Membership is evaluated in Python against the event itself, never read back from
# `events.cim_models`: detection runs INLINE in `pipeline.write_stream`, which
# evaluates each event as it streams and only INSERTs in chunks — the row does not
# exist yet. `app.cim.match` is the single evaluator for both paths.
_GATE_CACHE_MAX = 512
_LOG_KEYS_MAX = 512

# How long a FAILED resolution is honoured before the next caller tries again — see
# `_cim`, which owns the argument for why failure is retried at all and why on a clock.
_CIM_RETRY_SECONDS = 30.0
_CIM_UNAVAILABLE = "cim-unavailable"      # `_log_once` key, dropped again on recovery
_clock = time.monotonic                   # the retry clock, swapped out by tests.
                                          # MONOTONIC: a wall-clock step (ntp, a VM
                                          # resume) must not park the retry in the
                                          # far future or fire it in a tight loop.

_cim_lock = threading.Lock()              # guards the six globals below, together
_cim_resolved = False                     # resolved SUCCESSFULLY — the (registry,
_cim_registry: Any = None                 # tags_for) handle is then reused for every
_cim_tags_for: Any = None                 # event: never per event, never per rule.
_cim_retry_at: Optional[float] = None     # `_clock()` deadline for the next attempt
_cim_generation = 0                       # bumped by `reset_cim_cache` — see `_gate`
_gate_cache: dict[tuple, "_Gate"] = {}    # (rule id, names) -> resolved binding
_logged: set[str] = set()                 # keys already reported by `_log_once` — the
                                          # ONE global here that is NOT lock-guarded


def _log_once(key: str, msg: str, *args, exc_info: bool = False) -> None:
    """Log ``msg`` the first time ``key`` is seen, and never again.

    The gate runs per event, so a rule bound to a misspelled model would otherwise
    emit one identical line for every event in the stream — a broken rule must be
    loud once, not a denial of service on the log.

    Bounded for the same reason ``_gate_cache`` is: the keys carry ``rule.id``, which
    arrives straight from pasted YAML via ``main.rules_test`` and ``workbench.evaluate``,
    so an unbounded set here is a slow leak driven by whatever an analyst pastes. Past
    the cap the whole set is dropped — a key that recurs afterwards costs one extra
    line, which is the cheap side of the trade.

    ``_logged`` is the one CIM global NOT guarded by ``_cim_lock``, deliberately. Every
    operation used on it — ``in``, ``add``, ``len``, ``clear``, ``discard`` — is a single
    atomic operation on a builtin set, so a race here cannot corrupt it; it can only
    duplicate or drop ONE log line. That is not worth a critical section on a path that
    runs per event per rule, and taking the lock here would deadlock anyway: ``_cim``
    reports its own failure through this function while holding it.
    """
    if key in _logged:
        return
    if len(_logged) >= _LOG_KEYS_MAX:
        _logged.clear()
    _logged.add(key)
    log.error(msg, *args, exc_info=exc_info)


def _cim() -> tuple[Any, Any]:
    """``(registry, tags_for)`` for the CIM layer, resolved once — ``(None, None)``
    if it is unavailable.

    Imported lazily and defensively on purpose. ``app.cim.match`` runs a contract
    self-check at import and ``registry.load()`` parses ``models.yaml``; either can
    raise, and neither may be allowed to stop ingest. A CIM failure must cost exactly
    the rules that bind to a data model, so it is caught here and turned into "no
    registry" — every other rule keeps firing.

    SUCCESS is permanent; FAILURE is not.
        ``_cim_resolved`` is set only on the success path, so a resolution that failed
        is not process-lifetime state. It used to be — the flag was set after the
        ``except`` arm too — which meant one unlucky moment (a ``models.yaml`` caught
        mid-write, a failed ``registry.reload()`` leaving the singleton empty, a
        transient ``MemoryError``) switched every datamodel-bound rule off until
        someone restarted the process. Nothing in the app calls
        :func:`reset_cim_cache`, so "until someone restarts" was literal.

    Why a clock, and why 30 s.
        The obvious alternative — retry on every call — is the trap on the other side:
        ``registry.load()`` measures ~200 ms on the shipped 11-model ``models.yaml``,
        and it runs UNDER this lock, so a permanently broken registry would stall the
        whole detection path for 200 ms per event. A retry budget counted in CALLS
        avoids that but is rate-dependent in both directions: the same budget is
        seconds of recovery latency at 10k events/s and hours of it on a quiet box.
        A flat wall of ``_CIM_RETRY_SECONDS`` is rate-INdependent on both axes — it
        bounds the cost of a broken registry at one attempt per 30 s, whatever the
        event rate. Not exponential: there is nothing here to overload by retrying, so
        the only thing a growing interval would buy is a longer outage after the cause
        has cleared.

        TWO WALLS IN SERIES, so read the recovery latency as their sum.
        ``registry.get_registry()`` keeps a negative cache of its own on the same
        ``_FAILURE_TTL_SECONDS = 30`` idea, for the same reason at a different layer
        (its caller on the degraded write path is ``db._cim_tags``, i.e. one call per
        EVENT). The two are independent and neither knows about the other, so an attempt
        from here usually does NOT reach ``registry.load()`` at all — it is answered
        from that negative entry in O(1), which makes the cost claim above conservative
        rather than optimistic. The recovery latency is what compounds: this wall is
        armed a few hundred ms BEFORE the registry's (``now`` is sampled before the
        load), so the first retry past 30 s lands while the registry's entry is still
        warm, is refused, and re-arms this one. A fixed ``models.yaml`` is therefore
        picked up in **30–60 s**, not 30. That is bounded and self-correcting, and
        collapsing it would mean one module reaching into the other's private cache
        across a lock boundary — see :func:`reset_cim_cache`, which is the supported way
        to skip the wait and which only works when paired with ``registry.reload()``.

    Both transitions are logged, once each: the failure through :func:`_log_once` (it
    repeats every 30 s, and one line is the point), the recovery at WARNING because
    "the bound rules are live again" is exactly what the operator watching the first
    line is waiting for. The key is dropped on recovery so a SECOND outage is loud too.

    Thread safety. Concurrent FIRST callers are the normal case, not an exotic one:
    ingest runs ``INGEST_WORKERS`` writers that each reach this through
    ``pipeline.write_stream`` -> ``evaluate_event`` -> :func:`cim_tags`, alongside
    ``/upload``, ``/api/ingest``, ``/rules/test`` and the workbench. In a SERVED process
    the window is small: ``main._require_cim_registry()`` — which runs first in the
    lifespan, before the database is touched, and is not gated by ``CIM_ENABLED``
    (that flag gates ``main._init_cim``'s ``cim_<tag>`` views only) — has already forced
    ``db.validate_cim_registry()`` -> ``registry.get_registry()``, the one eager load in
    the process, and refuses to boot if it raises. So ``get_registry()`` below is a cache
    hit and only the lazy import is cold. The processes that pay a whole
    ``registry.load()`` here are the ones that never run that lifespan: the test suite,
    and anything importing the engine directly.

    The check, the resolution and the publication of ``_cim_resolved`` therefore all
    happen INSIDE ``_cim_lock``, and the flag is set LAST. Not double-checked outside
    the lock: the flag and the two handles are three separate globals, so a fast path
    that reads the flag unlocked has to argue about which stores a concurrent writer
    has already made visible — and the failure mode of getting that wrong is not a slow
    path, it is ``(None, None)``, which :func:`_gate` turns into a dead gate. This
    construction has nothing to argue about. An uncontended lock is ~100 ns against a
    per-event evaluation orders of magnitude larger, and a contended one blocks the
    caller for exactly the load it was about to need.
    """
    global _cim_resolved, _cim_registry, _cim_tags_for, _cim_retry_at
    with _cim_lock:
        if _cim_resolved:
            return _cim_registry, _cim_tags_for
        now = _clock()
        if _cim_retry_at is not None and now < _cim_retry_at:
            return None, None             # still inside the wall from the last failure
        try:
            from ..cim.match import tags_for
            from ..cim.registry import get_registry
            reg, tags_fn = get_registry(), tags_for
        except Exception:  # noqa: BLE001 — a broken registry is a dead gate, not a
            _cim_registry = _cim_tags_for = None                    # dead pipeline
            _cim_retry_at = now + _CIM_RETRY_SECONDS
            _log_once(_CIM_UNAVAILABLE,
                      "CIM registry unavailable - every datamodel-bound detection rule "
                      "is disabled; retrying in %.0fs", _CIM_RETRY_SECONDS, exc_info=True)
            return None, None
        if _cim_retry_at is not None:     # this attempt was a RETRY, and it worked
            _logged.discard(_CIM_UNAVAILABLE)          # ...so say so if it breaks again
            log.warning("CIM registry resolved after an earlier failure - "
                        "datamodel-bound detection rules are live again")
            _cim_retry_at = None
        _cim_registry, _cim_tags_for = reg, tags_fn
        # Published only now: until this line every other thread waits on the lock
        # rather than reading half-resolved state. Deliberately NOT in a `finally` —
        # a BaseException (KeyboardInterrupt, MemoryError) is not "the registry is
        # broken", so it leaves the flag unset and the next caller tries again.
        _cim_resolved = True
        return _cim_registry, _cim_tags_for


def reset_cim_cache() -> None:
    """Forget the resolved registry, the per-rule gates and the once-only log keys.

    Call after ``app.cim.registry.reload()``: a SUCCESSFUL resolution above is permanent
    (a failed one is retried on a clock), so an edited ``models.yaml`` is otherwise
    invisible until restart. Tests use it to swap registries between cases.

    AFTER ``reload()``, and not instead of it. This clears THIS module's half of the
    state — the resolved handles, the gates, and ``_cim_retry_at``, so the next call
    re-resolves immediately instead of waiting out the wall. It cannot clear the
    registry's own negative cache, which is private to ``app.cim.registry`` and is what
    ``get_registry()`` will answer the re-resolution from. Called ALONE against a
    registry that is currently failing, this therefore buys nothing: the immediate
    retry is served the remembered exception and simply re-arms the wall.
    ``registry.reload()`` is the call that drops that entry and re-reads the file, which
    is why it comes first and why "reload, then reset" is the whole sequence.

    Everything the reset invalidates is dropped in ONE critical section, under the lock
    :func:`_cim` and :func:`_gate` write through. ``_gate_cache`` in particular MUST be
    cleared in here rather than after: a gate resolved against the pre-reset registry can
    be in flight while this runs, and clearing outside the lock let that thread write it
    back AFTER the clear — the stale binding then outlives the registry it was resolved
    against, which is the permanent-state failure this whole reset exists to prevent.
    ``_cim_generation`` is what makes that write recognisable to the thread holding it.

    ``clear_plan_cache()`` stays outside: it is another module's own cache, guarded by
    nothing of ours, and holding ``_cim_lock`` across an import to reach it would invert
    the lock order this file is careful about.
    """
    global _cim_resolved, _cim_registry, _cim_tags_for, _cim_retry_at, _cim_generation
    with _cim_lock:                       # same lock as `_cim`, for the same reason
        _cim_resolved, _cim_registry, _cim_tags_for = False, None, None
        _cim_retry_at = None              # "try again NOW" — of OUR wall; the registry's
                                          # own negative entry is dropped by `reload()`
        _cim_generation += 1              # invalidates gates already in flight
        _gate_cache.clear()
        _logged.clear()
    try:
        from ..cim.match import clear_plan_cache
        clear_plan_cache()
    except Exception:  # noqa: BLE001 — nothing to clear if the layer never loaded
        pass


def cim_tags(evt: Any) -> frozenset[str]:
    """The CIM model tags ``evt`` belongs to — ``app.cim.match.tags_for`` in a box
    that never raises.

    ``evt`` is a :class:`~app.models.NormalizedEvent` or a stored ``events`` row read
    back as a mapping (both carry the nine membership columns and ``raw``). Resolve it
    ONCE per event and hand the result to :func:`match_rule`; walking the registry per
    rule would repeat the same work for every rule in the pack.
    """
    reg, tags_for = _cim()
    if reg is None:
        return frozenset()
    try:
        return frozenset(tags_for(evt, reg))
    except Exception:  # noqa: BLE001 — see `_cim`: bound rules die, the rest run
        _log_once("cim-eval-failed",
                  "CIM membership evaluation failed - every datamodel-bound detection "
                  "rule is disabled", exc_info=True)
        return frozenset()


@dataclass(frozen=True)
class _Gate:
    """One rule's ``datamodels:`` binding, resolved against the registry.

    ``dead`` is the failure mode that matters: a name that resolves to no model is a
    rule defect, and the rule is switched off rather than allowed to fall through to
    match-all — a typo must never silently widen a detection to every event.
    """
    tags: frozenset[str]
    dead: bool


def _gate(rule: "Rule") -> _Gate:
    """``rule``'s binding, resolved once and memoized (names -> model tags).

    ``_gate_cache`` is read and written under ``_cim_lock`` — the same lock as the
    resolution it is derived from, and for the same reason. The generation stamp is what
    the two short critical sections buy: a reset can land in the UNLOCKED middle of this
    function, between the registry this gate was resolved against and the write below,
    and without the stamp that write puts a binding from a discarded registry back into a
    cache that nothing but a restart will clear again.

    The stamp is read BEFORE :func:`_cim`, never after, so it can only be too strict: a
    reset anywhere in the window makes this call skip its memoization and resolve once
    more next time. Two uncontended acquisitions (~100 ns each) against a registry walk
    is the right side of that trade, and the hit path takes only one.
    """
    key = (rule.id, tuple(rule.datamodels))
    with _cim_lock:
        hit = _gate_cache.get(key)
        if hit is not None:
            return hit
        generation = _cim_generation
    reg, _ = _cim()                       # takes `_cim_lock` itself — never held here
    if reg is None:
        # There is no registry to resolve against, so this is not an answer about the
        # rule — it is the absence of one, and `_cim` has already logged why. Return
        # the dead gate WITHOUT memoizing it: `_gate_cache` is only ever written from a
        # real registry, so nothing about a failed resolution can outlive the failure.
        # Memoizing here is what turns a transient outage into permanent state, because
        # the cache is otherwise cleared only by `reset_cim_cache()` or by overflow.
        return _Gate(frozenset(), True)
    resolved, unknown = [], []
    for name in rule.datamodels:
        model = reg.by_name(name)                      # display name OR tag
        (resolved.append(model.tag) if model is not None else unknown.append(name))
    if unknown:
        _log_once(f"unknown-datamodel:{key}",
                  "detection rule %s binds to unknown CIM data model(s) %s - the "
                  "rule is disabled (known models: %s)",
                  rule.id, ", ".join(unknown), ", ".join(reg.tags))
    gate = _Gate(frozenset(), True) if unknown else _Gate(frozenset(resolved), False)
    with _cim_lock:
        if generation == _cim_generation:              # nothing reset underneath us
            # A rule pack contributes one entry per rule; only the workbench, where
            # every edit is a fresh (id, names) pair, can grow this without bound.
            if len(_gate_cache) >= _GATE_CACHE_MAX:
                _gate_cache.clear()
            _gate_cache[key] = gate
    return gate


def datamodels_match(rule: "Rule", tags: Iterable[str]) -> bool:
    """Does ``rule``'s ``datamodels:`` binding admit an event carrying ``tags``?

    * **No binding** -> ``True``. An unbound rule is match-all, which is what keeps
      every rule written before this gate existed behaving exactly as it did.
    * **Several models** -> ANY of them, following the engine's own convention that a
      value list is an OR. ``datamodels: [web, ids]`` reads "this fires on web *or*
      IDS events"; requiring both is not a thing an analyst asks for.
    * **An unresolvable name** -> ``False``, for this rule only (see :class:`_Gate`).
    """
    if not rule.datamodels:
        return True
    gate = _gate(rule)
    return not gate.dead and not gate.tags.isdisjoint(tags)


# --------------------------------------------------------------------------- #
#  Rule model + loading                                                       #
# --------------------------------------------------------------------------- #
@dataclass
class Rule:
    id: str
    title: str
    level: str
    description: str
    logsource: dict
    detection: dict
    # The CIM binding — model names or tags this rule reads (`datamodels_match`).
    # EMPTY means unbound, i.e. match-all, so a rule that predates the gate is
    # unaffected by it and pays nothing for it.
    datamodels: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    atlas_techniques: list[str] = field(default_factory=list)
    fidelity: str = "medium"
    data_source: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    source: str = ""
    enabled: bool = True


def _parse_tags(tags) -> tuple[list[str], list[str]]:
    tactics, techniques = [], []
    for t in tags or []:
        t = str(t).strip()
        if t.lower().startswith("attack."):
            v = t.split(".", 1)[1]
            if _TECH_RE.fullmatch(v):
                techniques.append(v.upper())
            else:
                tactics.append(v.replace("_", " ").lower())
    return tactics, techniques


def parse_atlas_tags(tags) -> list[str]:
    """MITRE ATLAS technique tags ``atlas.aml.tNNNN[.NNN]`` → ``AML.TNNNN``."""
    out = []
    for t in tags or []:
        t = str(t).strip()
        if t.lower().startswith("atlas."):
            v = t.split(".", 1)[1]
            if _ATLAS_RE.fullmatch(v):
                out.append(v.upper())
    return out


def norm_fidelity(value) -> str:
    """Coerce a rule's fidelity to one of high/medium/hunt (default medium)."""
    v = str(value or "").strip().lower()
    return v if v in _FIDELITY else "medium"


def as_str_list(value) -> list[str]:
    """A rule metadata field that may be a list or a comma-string → list[str]."""
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple)):
        return [str(x).strip() for x in value if str(x).strip()]
    return [s.strip() for s in str(value).split(",") if s.strip()]


def rule_from_dict(d: dict, source: str) -> Rule:
    tactics, techniques = _parse_tags(d.get("tags"))
    return Rule(
        id=str(d.get("id") or d.get("title") or source),
        title=str(d.get("title") or "untitled"),
        level=str(d.get("level") or "medium").lower(),
        description=str(d.get("description") or ""),
        logsource=d.get("logsource") or {},
        detection=d.get("detection") or {},
        # `datamodel:` (singular) is accepted because binding to ONE model is the
        # common case and reads better; `datamodels:` is canonical.
        datamodels=as_str_list(d.get("datamodels") or d.get("datamodel")),
        tactics=tactics, techniques=techniques,
        atlas_techniques=parse_atlas_tags(d.get("tags")),
        fidelity=norm_fidelity(d.get("fidelity")),
        data_source=as_str_list(d.get("data_source") or d.get("data_sources")),
        references=as_str_list(d.get("references")),
        source=source,
    )


def _rule_files(rules_dir) -> list[Path]:
    """*.yml / *.yaml under `rules_dir` and its `imported/` subdir (Sigma imports)."""
    base = Path(rules_dir)
    files: list[Path] = []
    for d in (base, base / "imported"):
        if d.is_dir():
            files += sorted(list(d.glob("*.yml")) + list(d.glob("*.yaml")))
    return files


def load_rules(rules_dir) -> list[Rule]:
    """Load every *.yml / *.yaml document under `rules_dir` (+ `imported/`) with a
    detection block. Imported SigmaHQ rules land in `rules_dir/imported/`."""
    rules: list[Rule] = []
    for path in _rule_files(rules_dir):
        text = path.read_text(encoding="utf-8")
        for doc in yaml.safe_load_all(text):
            if isinstance(doc, dict) and doc.get("detection"):
                rules.append(rule_from_dict(doc, path.name))
    return rules


def match_rule(rule: Rule, flat: dict, evt: Any = None,
               tags: Optional[Iterable[str]] = None) -> bool:
    """Does ``rule`` fire on this event? Both source gates, then the condition.

    ``flat`` is the Sigma view of the event (:func:`flatten_event`). ``evt`` is the
    event ITSELF — a ``NormalizedEvent`` or a stored ``events`` row — which the CIM
    gate needs because membership reads jsonb keys byte-exact while ``flat`` has
    lower-cased and dot-joined them. ``tags`` is that event's already-resolved
    membership (:func:`cim_tags`); pass it when evaluating many rules against one
    event so the registry is walked once instead of once per rule.

    ``logsource`` and ``datamodels`` are ANDed: both are narrowing filters, and a rule
    that declares both means "this kind of event, from that source". Logsource is
    tested first only because it is the cheaper of the two.

    With neither ``evt`` nor ``tags``, ``flat`` stands in for the event: its nine
    normalized columns resolve, but no ``raw:`` membership term can, so a bound rule
    may under-match. Every caller inside LogOcean passes one of them.
    """
    if not _logsource_matches(rule.logsource, flat):
        return False
    if rule.datamodels:
        if tags is None:
            tags = cim_tags(evt if evt is not None else flat)
        if not datamodels_match(rule, tags):
            return False
    det = rule.detection
    sel = {name: _eval_selection(flat, body)
           for name, body in det.items() if name != "condition"}
    return _eval_condition(det.get("condition", ""), sel)


def alert_from_match(rule: Rule, evt: NormalizedEvent, dedup_hash: str,
                     batch_id: Optional[int] = None) -> dict:
    """Build the alert row for `rule` matching `evt`. `dedup_hash` is the event's
    identity (links the alert back to the stored event); pure — DB-free."""
    return {
        "event_time": evt.event_time,
        "rule_id": rule.id, "rule_title": rule.title, "level": rule.level,
        "tactics": rule.tactics, "techniques": rule.techniques,
        "vendor": evt.vendor, "src_ip": evt.src_ip, "dst_ip": evt.dst_ip,
        "user_name": evt.user_name, "host_name": evt.host_name,
        "message": str(evt.message)[:1000] if evt.message else None,
        "dedup_hash": dedup_hash, "batch_id": batch_id, "status": "open",
    }


class DetectionEngine:
    """Holds the loaded rules and evaluates events against the enabled ones."""

    def __init__(self, rules: Optional[list[Rule]] = None):
        self.rules: list[Rule] = rules or []

    def evaluate_event(self, evt: NormalizedEvent,
                       tags: Optional[frozenset[str]] = None) -> list[Rule]:
        """Every enabled rule that fires on ``evt``.

        ``tags`` is the event's already-resolved CIM membership. It exists because the
        same walk is wanted twice per ingested event — here for the ``datamodels:`` gate
        as the event streams, and again in ``db._row`` when the chunk flushes — so
        ``pipeline.write_stream`` resolves it once and threads it to both consumers.

        Omitting it keeps the original behaviour exactly: membership is resolved lazily
        below, at most once per event, and not at all when no enabled rule binds to a data
        model — so a rule pack that uses none of this still pays nothing.

        The threaded value is resolved against the DEFAULT cached registry, which is the
        same object :func:`_cim` holds in any production process. The two can only differ
        after a ``registry.reload()`` without a matching ``reset_cim_cache()``, and then
        the caller's value is the fresher of the two.
        """
        flat = flatten_event(evt)
        out: list[Rule] = []
        for r in self.rules:
            if not r.enabled:
                continue
            try:
                if r.datamodels and tags is None:
                    tags = cim_tags(evt)
                if match_rule(r, flat, evt, tags):
                    out.append(r)
            except Exception:  # noqa: BLE001 — one bad rule must not sink the rest
                log.warning("detection rule %s failed to evaluate", r.id, exc_info=True)
        return out
