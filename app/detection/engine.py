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
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from ..models import NormalizedEvent

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
        return re.search(e, s, re_flags) is not None
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
    tactics: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
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


def rule_from_dict(d: dict, source: str) -> Rule:
    tactics, techniques = _parse_tags(d.get("tags"))
    return Rule(
        id=str(d.get("id") or d.get("title") or source),
        title=str(d.get("title") or "untitled"),
        level=str(d.get("level") or "medium").lower(),
        description=str(d.get("description") or ""),
        logsource=d.get("logsource") or {},
        detection=d.get("detection") or {},
        tactics=tactics, techniques=techniques, source=source,
    )


def load_rules(rules_dir) -> list[Rule]:
    """Load every *.yml / *.yaml document under `rules_dir` that has a detection."""
    rules: list[Rule] = []
    base = Path(rules_dir)
    if not base.is_dir():
        return rules
    for path in sorted(list(base.glob("*.yml")) + list(base.glob("*.yaml"))):
        text = path.read_text(encoding="utf-8")
        for doc in yaml.safe_load_all(text):
            if isinstance(doc, dict) and doc.get("detection"):
                rules.append(rule_from_dict(doc, path.name))
    return rules


def match_rule(rule: Rule, flat: dict) -> bool:
    if not _logsource_matches(rule.logsource, flat):
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
        "dedup_hash": dedup_hash, "batch_id": batch_id,
    }


class DetectionEngine:
    """Holds the loaded rules and evaluates events against the enabled ones."""

    def __init__(self, rules: Optional[list[Rule]] = None):
        self.rules: list[Rule] = rules or []

    def evaluate_event(self, evt: NormalizedEvent) -> list[Rule]:
        flat = flatten_event(evt)
        return [r for r in self.rules if r.enabled and match_rule(r, flat)]
