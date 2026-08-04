# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Content Packs — one versioned bundle that onboards a source without a release.

Splunk's equivalent is a TA / Splunkbase app: the unit that makes "yes, we support your
stack" shippable *between* releases. A LogOcean pack carries everything a source needs to
land end-to-end, as DATA:

  * ``parsers:``    — console field-mapper definitions (:mod:`app.custom_parser` rows)
  * ``rules:``      — Sigma-subset detection rules (``custom_rules`` rows)
  * ``cim:``        — membership CLAUSES added to EXISTING data models
  * ``compliance:`` — technique -> framework -> control mappings

Nothing in a pack is code. Every section is interpreted by an engine that already exists
(``custom_parser.apply``, ``detection.engine``, ``cim.match``, ``compliance.build_report``),
so importing a pack can never introduce a new execution path. There is no ``eval``, no
``exec``, no import hook and no template rendering anywhere in this module.

Why ONE FILE and not a directory
--------------------------------
A pack is a single YAML document (JSON is accepted too — ``yaml.safe_load`` reads it).
The alternative, a directory or an archive, was rejected on three counts:

  * **Signing.** One document is one canonical byte string, so ``digest``/``sign``/
    ``verify`` cover the whole pack with one hash. A tree needs a manifest of per-file
    hashes, and the manifest itself becomes the thing you forget to check.
  * **Attack surface.** A directory has to travel as a zip/tar, which brings zip-slip and
    tar path traversal, symlink escape, and decompression bombs — real CVE classes, all
    for zero expressive gain, since every section here is already structured data.
  * **Air-gap ergonomics.** A pack is a file you can e-mail, put on a USB stick, paste
    into a ticket, diff in a PR, and store verbatim as one DB row. No extraction step,
    no temp directory, no cleanup path that can fail half-way.

Detection rules are carried as VERBATIM TEXT in a block scalar rather than as re-emitted
mappings, so a rule survives the round trip byte-for-byte — comments, key order and
``falsepositives`` included — and can still be diffed against its upstream source.

Purity
------
Export, validation and planning are pure transforms over data structures:

    parse(text) -> Pack                       # text  -> contract
    dumps(pack) -> text                       # contract -> text   (round-trips)
    export_pack(...) -> Pack                  # DB ROWS (plain dicts) -> contract
    plan_install(pack, existing) -> ImportPlan  # contract + snapshot -> the dry run
    merge_cim(registry, entries) -> CimRegistry
    merge_compliance(base, entries) -> dict

The database appears only in :class:`DbWriter` and :func:`snapshot`, and even those are
substitutable: :func:`apply_plan` takes any :class:`PackWriter`, so the whole import path
is exercised in unit tests with :class:`RecordingWriter` and no database at all.

A pack is untrusted input
-------------------------
The threat model is "someone downloaded this from the internet". Defences, all at PARSE
time, before any value reaches an engine:

  * **Size cap** on the document (:data:`MAX_DOCUMENT_BYTES`) and per-section item caps.
  * **No YAML aliases.** :class:`_PackLoader` refuses ``&anchor``/``*alias`` outright,
    which removes the billion-laughs expansion bomb rather than trying to bound it.
  * **No duplicate mapping keys.** Two ``rules:`` keys in one document would let a pack
    show one set of rules to a reviewer and install another — PyYAML keeps the last
    silently. Same defence ``app/cim/registry.py`` applies to ``models.yaml``.
  * **Depth cap** (:data:`MAX_DEPTH`) so canonicalization cannot be driven into recursion.
  * **Unknown keys are rejected**, at the top level and inside every section item, with a
    "did you mean" suggestion — a typo'd key that imports as a no-op is how content
    silently does nothing.
  * **Every rule must compile**: the condition may only reference selections the rule
    defines, ``engine.rule_from_dict`` must accept it, and a ``datamodels:`` binding must
    resolve against the CIM registry (an unknown binding disables a rule *invisibly*).
  * **Every regex is ReDoS-guarded** — see :func:`redos_risk`.
  * **CIM clauses are validated by the registry's own parser**, so a pack cannot express a
    membership clause ``models.yaml`` itself would reject (bad column, unsafe jsonb key).
  * **A pack may not define a new data model, nor change an existing clause or field.**
    Only additions. A model tag is what detections bind to; letting a pack mint or
    redefine one lets it capture rules bound to that name.

Import is planned before it is applied. :func:`plan_install` reports every create /
update / delete / conflict *and* every validation problem with zero writes; ``apply``
refuses a plan that has problems or unresolved conflicts, and :func:`plan_uninstall`
removes exactly the objects the pack installed.

Wiring
------
Four sections, three of which reach existing machinery unchanged:

  * ``parsers:`` / ``rules:`` — written to ``custom_parsers`` / ``custom_rules`` by
    :class:`DbWriter` through ONE ``db.apply_content_pack`` call, so a pack cannot land
    half-installed. The staged row dicts use the exact keyword names of
    ``db.upsert_custom_parser`` / ``db.upsert_custom_rule``.
  * ``cim:`` — :func:`overlay_registry` is the single call ``app/cim/registry.py`` makes
    after loading ``models.yaml``; membership then takes effect on the next start (the
    registry is compiled once per process and cached), followed by ``db.backfill_cim()``
    to re-derive history — in that order, never the other way round.
  * ``compliance:`` — :func:`merge_compliance` produces a ``compliance.MAP``-shaped dict
    for ``build_report`` to consume.

The pack document itself is stored verbatim in one row, which is what makes ownership
(who installed this rule?), upgrade (what did the new version drop?) and uninstall
(remove exactly what I added) answerable without a second bookkeeping table.
"""
from __future__ import annotations

import difflib
import hashlib
import hmac
import json
import logging
import re
from dataclasses import dataclass, field, replace
from typing import Any, Mapping, Optional, Sequence

import yaml

from . import compliance as compliance_module
from .cim import registry as cim_registry
from .cim.spec import CimError, CimField, CimModel, CimRegistry
from .detection import engine as detection_engine

log = logging.getLogger("logocean")

# --------------------------------------------------------------------------- #
#  Limits (a pack is untrusted; every one of these is a refusal, not a clamp)  #
# --------------------------------------------------------------------------- #
PACK_FORMAT = 1                     # the envelope schema version this module speaks

MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 32
MAX_SECTION_ITEMS = 500
MAX_TEXT_CHARS = 4096
MAX_NAME_CHARS = 64
MAX_RULE_CHARS = 64 * 1024
MAX_FIELD_MAP_ENTRIES = 200
MAX_PATTERN_CHARS = 512
MAX_REPEAT = 1000                   # `x{1001}` is a denial of service with no upside

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
# Rule and parser ids come from upstream too (SigmaHQ uses UUIDs), so they are wider than
# a pack name — but still a closed character set, because they reach SQL as keys.
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_VERSION_RE = re.compile(r"^\d+(\.\d+){0,3}(?:[-+][A-Za-z0-9.\-]+)?$")
_TECHNIQUE_RE = re.compile(r"^(?:T\d{4}(?:\.\d{3})?|AML\.T\d{4}(?:\.\d{3})?)$", re.I)
_CONSTRAINT_RE = re.compile(r"^(>=|<=|==|=|>|<)?\s*(\d+(?:\.\d+){0,3})$")

_TOP_KEYS = ("pack", "name", "version", "description", "author", "license", "homepage",
             "labels", "requires", "parsers", "rules", "cim", "compliance", "signature")
_PARSER_KEYS = ("id", "title", "match_key", "match_value", "field_map", "vendor",
                "product", "kv_source", "kv_sep", "enabled")
_RULE_KEYS = ("id", "title", "yaml", "rule", "enabled")
_CIM_KEYS = ("model", "membership", "fields", "note")
_COMPLIANCE_KEYS = ("technique", "framework", "controls")
_CONTROL_KEYS = ("id", "name")
_REQUIRES_KEYS = ("logocean", "cim")
_SIGNATURE_KEYS = ("algorithm", "key_id", "value")

SIGNATURE_ALGORITHM = "hmac-sha256"

# Columns a pack's field_map may target. Deliberately RESTATED rather than imported:
# `app.custom_parser` pulls in `app.db` (and psycopg) at import time, and this module is
# DB-free by construction. `test_the_parser_column_whitelist_tracks_custom_parser` fails
# the moment the two drift.
PARSER_COLUMNS = frozenset({"vendor", "product", "log_type", "severity", "action",
                            "src_ip", "dst_ip", "protocol", "app", "user_name",
                            "host_name", "rule_name", "message"})

_RULE_LEVELS = frozenset({"informational", "low", "medium", "high", "critical"})
# Condition words the grammar consumes itself (`app/detection/engine.py:_Cond`); anything
# else in a condition has to name a selection the rule defines.
_CONDITION_WORDS = frozenset({"and", "or", "not", "of", "them", "all", "(", ")", "|"})

# Keys people reach for that this format deliberately does not have. difflib finds a near
# miss for a typo; it cannot explain a wrong mental model, so these are spelled out.
_KEY_HINTS = {
    "tags": "use `labels:` for pack labels; a pack's CIM TAGS come from its `cim:` "
            "membership additions, which is what stamps events.cim_models",
    "eventtypes": "the addressable tag/eventtype layer does not exist yet; express "
                  "membership under `cim:`",
    "parser": "the section is `parsers:` (a list)",
    "rule": "the section is `rules:` (a list)",
    "detections": "the section is `rules:`",
    "models": "a pack extends existing models under `cim:`; it cannot define one",
    "collectors": "collectors are code, not data — a pack carries no collector",
    "dashboards": "not a pack section in format 1",
}


class PackError(ValueError):
    """A malformed, unsafe or incompatible content pack. Raised at PARSE time."""


# --------------------------------------------------------------------------- #
#  The contract                                                               #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ParserEntry:
    """One console field-mapper definition — a ``custom_parsers`` row, as data."""
    id: str
    title: str
    match_key: str
    match_value: str
    field_map: tuple[tuple[str, str], ...] = ()     # tuple-of-pairs: frozen + ordered
    vendor: str = ""
    product: str = ""
    kv_source: str = ""
    kv_sep: str = ""
    enabled: bool = True

    @property
    def field_map_dict(self) -> dict[str, str]:
        return dict(self.field_map)


@dataclass(frozen=True)
class RuleEntry:
    """One detection rule, carried as the verbatim YAML text that will be stored."""
    id: str
    title: str
    yaml_text: str
    enabled: bool = True

    @property
    def doc(self) -> dict:
        """The parsed rule document (first YAML document with a ``detection`` block)."""
        return _rule_doc(self.yaml_text)


@dataclass(frozen=True)
class CimEntry:
    """Membership clauses (and optional fields) ADDED to one existing data model."""
    model: str
    membership: tuple[Any, ...] = ()      # raw clause mappings, models.yaml syntax
    fields: tuple[Any, ...] = ()          # raw field mappings, models.yaml syntax
    note: str = ""


@dataclass(frozen=True)
class ComplianceEntry:
    """One ``technique -> framework -> [(control_id, control_name)]`` mapping."""
    technique: str
    framework: str
    controls: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Signature:
    algorithm: str
    key_id: str
    value: str


@dataclass(frozen=True)
class Pack:
    """A whole content pack. Frozen, hashable-by-value, and round-trip stable."""
    name: str
    version: str
    format: int = PACK_FORMAT
    description: str = ""
    author: str = ""
    license: str = ""
    homepage: str = ""
    labels: tuple[str, ...] = ()
    requires: tuple[tuple[str, str], ...] = ()      # ("logocean", ">=1.0"), ("cim", "3")
    parsers: tuple[ParserEntry, ...] = ()
    rules: tuple[RuleEntry, ...] = ()
    cim: tuple[CimEntry, ...] = ()
    compliance: tuple[ComplianceEntry, ...] = ()
    signature: Optional[Signature] = None

    @property
    def key(self) -> str:
        return f"{self.name}@{self.version}"

    @property
    def requires_dict(self) -> dict[str, str]:
        return dict(self.requires)

    @property
    def is_empty(self) -> bool:
        return not (self.parsers or self.rules or self.cim or self.compliance)

    def counts(self) -> dict[str, int]:
        return {"parsers": len(self.parsers), "rules": len(self.rules),
                "cim": len(self.cim), "compliance": len(self.compliance)}


# --------------------------------------------------------------------------- #
#  Planning contract                                                          #
# --------------------------------------------------------------------------- #
CREATE, UPDATE, UNCHANGED, DELETE, CONFLICT = (
    "create", "update", "unchanged", "delete", "conflict")


@dataclass(frozen=True)
class Change:
    """One thing an import would do. ``kind`` is the section, ``ident`` the object."""
    kind: str                 # parser | rule | cim | compliance | pack
    ident: str
    verb: str                 # create | update | unchanged | delete | conflict
    detail: str = ""
    owner: str = ""           # for a conflict: which pack (or "") already owns `ident`

    def describe(self) -> str:
        tail = f" (owned by {self.owner or 'hand-authored content'})" if self.verb == CONFLICT else ""
        return f"{self.verb} {self.kind} {self.ident}{tail}"


@dataclass(frozen=True)
class ExistingState:
    """A snapshot of what is already installed — the only input a plan needs besides the
    pack itself. Built from the DB by :func:`snapshot`, hand-built in tests."""
    parsers: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)   # id -> row
    rules: Mapping[str, str] = field(default_factory=dict)                   # id -> yaml
    owners: Mapping[tuple[str, str], str] = field(default_factory=dict)      # (kind,id) -> pack
    installed: Mapping[str, "Pack"] = field(default_factory=dict)            # name -> Pack
    models: tuple[str, ...] = ()          # known CIM model names + tags, lower-cased
    frameworks: tuple[str, ...] = ()      # known compliance frameworks

    def owner_of(self, kind: str, ident: str) -> str:
        return self.owners.get((kind, ident), "")


@dataclass(frozen=True)
class ImportPlan:
    """The dry run: exactly what would change, plus why it cannot be applied (if so)."""
    pack: Pack
    changes: tuple[Change, ...] = ()
    problems: tuple[str, ...] = ()
    overwrite: bool = False

    @property
    def conflicts(self) -> tuple[Change, ...]:
        return tuple(c for c in self.changes if c.verb == CONFLICT)

    @property
    def applicable(self) -> bool:
        return not self.problems and not self.conflicts

    @property
    def restart_required(self) -> bool:
        """CIM membership is compiled once per process and cached, and the compliance MAP
        is module state — both take effect on the next start, exactly as a ``models.yaml``
        edit does (see ``app/cim/registry.py:get_registry``)."""
        return any(c.kind in ("cim", "compliance") and c.verb != UNCHANGED
                   for c in self.changes)

    def counts(self) -> dict[str, int]:
        out = {CREATE: 0, UPDATE: 0, UNCHANGED: 0, DELETE: 0, CONFLICT: 0}
        for c in self.changes:
            out[c.verb] = out.get(c.verb, 0) + 1
        return out

    def summary(self) -> str:
        c = self.counts()
        return (f"{self.pack.key}: {c[CREATE]} create, {c[UPDATE]} update, "
                f"{c[UNCHANGED]} unchanged, {c[DELETE]} delete, {c[CONFLICT]} conflict")


@dataclass(frozen=True)
class ApplyResult:
    pack: Pack
    applied: tuple[Change, ...] = ()
    restart_required: bool = False

    def as_dict(self) -> dict:
        return {"pack": self.pack.name, "version": self.pack.version,
                "applied": [c.describe() for c in self.applied],
                "restart_required": self.restart_required}


# --------------------------------------------------------------------------- #
#  ReDoS guard                                                                #
# --------------------------------------------------------------------------- #
def _skip_class(pattern: str, i: int) -> int:
    """Index just past the character class starting at ``pattern[i] == '['``."""
    i += 1
    if i < len(pattern) and pattern[i] == "^":
        i += 1
    if i < len(pattern) and pattern[i] == "]":      # a leading ']' is a literal
        i += 1
    while i < len(pattern):
        if pattern[i] == "\\":
            i += 2
            continue
        if pattern[i] == "]":
            return i + 1
        i += 1
    return i


def _quantifier(pattern: str, i: int) -> tuple[int, bool, bool]:
    """Read a quantifier at ``i``. Returns ``(next_index, present, unbounded)``.

    ``unbounded`` is what matters: ``*``, ``+`` and ``{n,}`` can repeat without limit and
    are the only ones that turn a nested repetition into exponential backtracking.
    """
    if i >= len(pattern):
        return i, False, False
    ch = pattern[i]
    if ch in "*+":
        j = i + 1
        if j < len(pattern) and pattern[j] in "?+":     # lazy / possessive suffix
            j += 1
        return j, True, True
    if ch == "?":
        j = i + 1
        if j < len(pattern) and pattern[j] in "?+":
            j += 1
        return j, True, False
    if ch == "{":
        close = pattern.find("}", i)
        if close == -1:
            return i, False, False
        body = pattern[i + 1:close]
        if not re.fullmatch(r"\d*(?:,\d*)?", body) or body in ("", ","):
            return i, False, False                       # a literal '{'
        low, _, high = body.partition(",")
        j = close + 1
        if j < len(pattern) and pattern[j] in "?+":
            j += 1
        unbounded = ("," in body) and high == ""
        return j, True, unbounded
    return i, False, False


def _has_unbounded_repeat(body: str) -> bool:
    """Does ``body`` apply an unbounded quantifier to anything?  ``a+`` yes, ``a{1,3}`` no."""
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "[":
            i = _skip_class(body, i)
            continue
        nxt, present, unbounded = _quantifier(body, i)
        if present:
            if unbounded:
                return True
            i = nxt
            continue
        i += 1
    return False


def _split_alternatives(body: str) -> list[str]:
    """Split on TOP-LEVEL ``|`` only (nested groups and classes keep their own)."""
    out, depth, start, i = [], 0, 0, 0
    while i < len(body):
        ch = body[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "[":
            i = _skip_class(body, i)
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "|" and depth == 0:
            out.append(body[start:i])
            start = i + 1
        i += 1
    out.append(body[start:])
    return out


def _first_atom(branch: str) -> str:
    """The first matchable token of a branch — ``''`` when it cannot be read cheaply."""
    i = 0
    while i < len(branch) and branch[i] in "^(":
        if branch[i] == "(":                    # step over a group prefix like `(?:`
            i += 1
            if branch[i:i + 1] == "?":
                j = i + 1
                while j < len(branch) and branch[j] not in ":)>":
                    j += 1
                i = j + 1
            continue
        i += 1
    if i >= len(branch):
        return ""
    if branch[i] == "\\":
        return branch[i:i + 2]
    if branch[i] == "[":
        return branch[i:_skip_class(branch, i)]
    return branch[i]


_ANY = {".", "\\w", "\\W", "\\s", "\\S", "\\d", "\\D"}


def _atoms_overlap(a: str, b: str) -> bool:
    """Can two first-atoms match the same character?  Conservative: unknown -> True only
    for the classes that genuinely subsume, never for two distinct literals."""
    if not a or not b:
        return False
    if a == b:
        return True
    if "." in (a, b):
        return True
    if a.startswith("[") or b.startswith("["):
        return False                                    # distinct classes: don't guess
    wide, other = (a, b) if a in _ANY else (b, a)
    if wide not in _ANY:
        return False
    if len(other) == 1:
        if wide == "\\w":
            return other.isalnum() or other == "_"
        if wide == "\\d":
            return other.isdigit()
        if wide == "\\s":
            return other.isspace()
        return False
    return wide == other or {wide, other} <= {"\\w", "\\d"}


def redos_risk(pattern: str) -> Optional[str]:
    """A reason string when ``pattern`` looks catastrophically backtrackable, else None.

    A HEURISTIC, not a proof — the same posture ``app/ingest_actions.py`` takes on
    operator-authored masks, tightened here because a pack comes from the internet and its
    regexes run against every event. Three shapes are refused:

    * a repeated group whose body itself repeats without bound — ``(a+)+``, ``(\\d+\\s*)*``,
      ``([a-z]+){2,}``: the textbook exponential blow-up;
    * a repeated group whose alternatives can match the same next character —
      ``(a|ab)*``, ``(a|a)+``: the other textbook shape, where the engine has two ways to
      consume the same input at every step;
    * a repetition count above :data:`MAX_REPEAT`.

    It is deliberately conservative in one direction only: it can reject a pattern that
    would in fact have been safe (``(a+){2}`` is bounded, but ``(a+){2,}`` is not, and the
    difference is one character in a file nobody re-reads). The fix is always to rewrite
    the pattern, never to widen the guard.
    """
    if pattern is None:
        return None
    text = str(pattern)
    if len(text) > MAX_PATTERN_CHARS:
        return f"pattern is longer than {MAX_PATTERN_CHARS} characters"
    stack: list[int] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "[":
            i = _skip_class(text, i)
            continue
        if ch == "(":
            stack.append(i)
            i += 1
            continue
        if ch == ")":
            start = stack.pop() if stack else 0
            body = text[start + 1:i]
            if body.startswith("?"):                     # (?:...) (?=...) (?P<x>...)
                head = body.split(":", 1)
                body = head[1] if len(head) == 2 else body
            j, present, unbounded = _quantifier(text, i + 1)
            if present and unbounded:
                if _has_unbounded_repeat(body):
                    return (f"group ({body}) repeats without bound and its body repeats "
                            "too, which backtracks catastrophically; rewrite without (x+)+")
                branches = _split_alternatives(body)
                if len(branches) > 1:
                    firsts = [_first_atom(b) for b in branches]
                    for a in range(len(firsts)):
                        for b in range(a + 1, len(firsts)):
                            if _atoms_overlap(firsts[a], firsts[b]):
                                return (f"group ({body}) repeats without bound and its "
                                        f"alternatives {firsts[a]!r}/{firsts[b]!r} can "
                                        "match the same character, which backtracks "
                                        "catastrophically")
            i = j if present else i + 1
            continue
        if ch == "{":
            close = text.find("}", i)
            if close != -1:
                body = text[i + 1:close]
                if re.fullmatch(r"\d*(?:,\d*)?", body) and body not in ("", ","):
                    nums = [int(n) for n in body.split(",") if n]
                    if nums and max(nums) > MAX_REPEAT:
                        return f"repetition count above {MAX_REPEAT}"
        i += 1
    return None


def check_regex(pattern: Any, where: str) -> list[str]:
    """``[]`` when ``pattern`` is a safe, compilable regex, else the problem(s)."""
    text = str(pattern)
    problems: list[str] = []
    risk = redos_risk(text)
    if risk:
        problems.append(f"{where}: {risk}")
    try:
        re.compile(text)
    except re.error as exc:
        problems.append(f"{where}: not a valid regex ({exc})")
    return problems


# --------------------------------------------------------------------------- #
#  Parsing helpers (pure)                                                     #
# --------------------------------------------------------------------------- #
class _PackLoader(yaml.SafeLoader):
    """SafeLoader + two refusals a content pack cannot be allowed to exercise.

    * **Aliases.** ``&a``/``*a`` is how a 1 KB document expands to gigabytes (the
      "billion laughs" bomb). A pack has no legitimate use for them, so they are refused
      rather than bounded.
    * **Duplicate mapping keys.** PyYAML keeps the LAST value silently, so a document with
      two ``rules:`` keys shows a reviewer one list and installs another.
    """

    def compose_node(self, parent, index):             # type: ignore[override]
        if self.check_event(yaml.events.AliasEvent):
            event = self.peek_event()
            raise PackError(f"YAML aliases are not allowed in a content pack "
                            f"(line {event.start_mark.line + 1})")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):     # type: ignore[override]
        seen = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                if key in seen:
                    raise PackError(f"duplicate key {key!r} in the content pack "
                                    f"(line {key_node.start_mark.line + 1})")
                seen.add(key)
            except TypeError:               # unhashable key — SafeLoader rejects it below
                continue
        return super().construct_mapping(node, deep=deep)


class _PackDumper(yaml.SafeDumper):
    """SafeDumper that writes multi-line strings as literal blocks.

    Purely cosmetic — and it matters: a rule emitted as one quoted line with ``\\n``
    escapes is unreviewable, and an unreviewable pack is one nobody reads before importing.
    PyYAML falls back to a quoted style on its own when a scalar cannot be a literal block,
    so the round trip is unaffected either way.
    """


def _represent_str(dumper: yaml.SafeDumper, data: str):
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


_PackDumper.add_representer(str, _represent_str)


def _depth(obj: Any, level: int = 0) -> int:
    if level > MAX_DEPTH:
        return level
    if isinstance(obj, Mapping):
        return max((_depth(v, level + 1) for v in obj.values()), default=level)
    if isinstance(obj, (list, tuple)):
        return max((_depth(v, level + 1) for v in obj), default=level)
    return level


def _suggest(key: str, allowed: Sequence[str]) -> str:
    hint = _KEY_HINTS.get(str(key))
    if hint:
        return f" — {hint}"
    near = difflib.get_close_matches(str(key), list(allowed), n=1, cutoff=0.6)
    return f" (did you mean {near[0]!r}?)" if near else ""


def _reject_unknown(doc: Mapping, allowed: Sequence[str], where: str) -> None:
    for key in doc:
        if str(key) not in allowed:
            raise PackError(f"{where}: unknown key {str(key)!r}{_suggest(key, allowed)}; "
                            f"allowed: {', '.join(allowed)}")


def _mapping(value: Any, where: str) -> Mapping:
    if not isinstance(value, Mapping):
        raise PackError(f"{where} must be a mapping, got {type(value).__name__}")
    return value


def _seq(value: Any, where: str) -> list:
    if value is None:
        return []
    if isinstance(value, Mapping) or not isinstance(value, (list, tuple)):
        raise PackError(f"{where} must be a list, got {type(value).__name__}")
    items = list(value)
    if len(items) > MAX_SECTION_ITEMS:
        raise PackError(f"{where} has {len(items)} items (limit {MAX_SECTION_ITEMS})")
    return items


def _text(value: Any, where: str, *, required: bool = False,
          limit: int = MAX_TEXT_CHARS) -> str:
    if value is None:
        if required:
            raise PackError(f"{where} is required")
        return ""
    if isinstance(value, bool) or isinstance(value, (list, dict)):
        # YAML 1.1 turns bare yes/no/on/off into booleans; a pack author who wrote
        # `vendor: on` meant the string, and silently storing `True` is worse than a stop.
        raise PackError(f"{where} must be text, got {type(value).__name__} "
                        "(quote it: YAML reads bare yes/no/on/off as booleans)")
    text = str(value).strip()
    if required and not text:
        raise PackError(f"{where} is required")
    if len(text) > limit:
        raise PackError(f"{where} is longer than {limit} characters")
    return text


def _bool(value: Any, where: str, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("true", "yes", "1", "on"):
        return True
    if text in ("false", "no", "0", "off"):
        return False
    raise PackError(f"{where} must be true or false, got {value!r}")


def _slug(value: Any, where: str) -> str:
    text = _text(value, where, required=True, limit=MAX_NAME_CHARS)
    if not _SLUG_RE.match(text):
        raise PackError(f"{where} must be lower-case [a-z0-9._-] starting with a letter "
                        f"or digit, got {text!r}")
    return text


def _ident(value: Any, where: str) -> str:
    text = _text(value, where, required=True, limit=MAX_NAME_CHARS * 2)
    if not _ID_RE.match(text):
        raise PackError(f"{where} must match [A-Za-z0-9][A-Za-z0-9._:-]*, got {text!r}")
    return text


def _version(value: Any, where: str) -> str:
    text = _text(value, where, required=True, limit=MAX_NAME_CHARS)
    if not _VERSION_RE.match(text):
        raise PackError(f"{where} must be a semver-ish version like 1.2.0, got {text!r}")
    return text


# --------------------------------------------------------------------------- #
#  Compatibility (pure)                                                       #
# --------------------------------------------------------------------------- #
def version_tuple(text: str) -> tuple[int, ...]:
    """``"1.2.0-rc1"`` -> ``(1, 2, 0)``. Pre-release/build metadata is ignored, which is
    the only sane reading for a compatibility floor."""
    core = re.split(r"[-+]", str(text).strip(), maxsplit=1)[0]
    parts = [p for p in core.split(".") if p != ""]
    out = []
    for p in parts:
        if not p.isdigit():
            raise PackError(f"{text!r} is not a numeric version")
        out.append(int(p))
    if not out:
        raise PackError(f"{text!r} is not a numeric version")
    return tuple(out)


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    width = max(len(a), len(b))
    a2 = a + (0,) * (width - len(a))
    b2 = b + (0,) * (width - len(b))
    return (a2 > b2) - (a2 < b2)


def satisfies(actual: str, constraint: str) -> bool:
    """Does ``actual`` satisfy a comma-joined constraint like ``">=1.2, <2.0"``?

    A bare version means ``>=`` — the common intent ("needs at least this") — because a
    bare ``1.2`` read as ``==1.2`` would make every pack expire on the next patch release.
    """
    got = version_tuple(actual)
    for part in str(constraint).split(","):
        part = part.strip()
        if not part:
            continue
        m = _CONSTRAINT_RE.match(part)
        if not m:
            raise PackError(f"unreadable version constraint {part!r}")
        op = m.group(1) or ">="
        want = version_tuple(m.group(2))
        c = _cmp(got, want)
        ok = {">=": c >= 0, ">": c > 0, "<=": c <= 0, "<": c < 0,
              "==": c == 0, "=": c == 0}[op]
        if not ok:
            return False
    return True


def compatibility_problems(pack: Pack, *, app_version: str,
                           cim_version: Optional[int] = None) -> list[str]:
    """``[]`` when this build can run the pack, else why not. Pure — versions are given."""
    problems: list[str] = []
    req = pack.requires_dict
    if pack.format > PACK_FORMAT:
        problems.append(f"pack format {pack.format} is newer than this build understands "
                        f"({PACK_FORMAT}); upgrade LogOcean")
    want_app = req.get("logocean")
    if want_app:
        try:
            if not satisfies(app_version, want_app):
                problems.append(f"pack requires LogOcean {want_app}, this is {app_version}")
        except PackError as exc:
            problems.append(str(exc))
    want_cim = req.get("cim")
    if want_cim and cim_version is not None:
        try:
            if int(str(want_cim).lstrip(">=")) > int(cim_version):
                problems.append(f"pack requires CIM registry version {want_cim}, "
                                f"this build has {cim_version}")
        except ValueError:
            problems.append(f"unreadable CIM requirement {want_cim!r}")
    return problems


# --------------------------------------------------------------------------- #
#  Rule validation (pure)                                                     #
# --------------------------------------------------------------------------- #
def _rule_doc(text: str) -> dict:
    """The first YAML document in ``text`` that carries a ``detection`` block."""
    for doc in yaml.load_all(text, Loader=_PackLoader):     # noqa: S506 — hardened loader
        if isinstance(doc, Mapping) and doc.get("detection"):
            return dict(doc)
    return {}


def condition_problems(detection: Mapping) -> list[str]:
    """Every token in ``condition:`` must name a selection the rule defines.

    A typo'd selection name is not an error in ``engine._Cond`` — it evaluates to False
    (``self.sel.get(t, False)``), so the rule loads, runs, and never fires. That is the
    single most expensive silent failure a content pack can ship, so it is an error here.
    """
    names = {str(k) for k in detection if str(k) != "condition"}
    if not names:
        return ["detection: needs at least one selection besides `condition`"]
    condition = str(detection.get("condition") or "").strip()
    if not condition:
        return []                                # engine reads this as "all selections"
    problems: list[str] = []
    tokens = condition.replace("(", " ( ").replace(")", " ) ").split()
    for idx, tok in enumerate(tokens):
        low = tok.lower()
        if low in _CONDITION_WORDS or low.isdigit():
            continue
        if idx and tokens[idx - 1].lower() == "of":
            if tok.endswith("*"):
                prefix = tok[:-1]
                if not any(n.startswith(prefix) for n in names):
                    problems.append(f"condition: `{tok}` matches no selection "
                                    f"(defined: {', '.join(sorted(names))})")
                continue
        if tok not in names:
            problems.append(f"condition: undefined selection {tok!r} "
                            f"(defined: {', '.join(sorted(names))})")
    return problems


def _selection_regexes(detection: Mapping) -> list[tuple[str, Any]]:
    """Every value a rule will hand to ``re.search`` — the ``|re`` modifier."""
    found: list[tuple[str, Any]] = []

    def walk(name: str, sel: Any) -> None:
        if isinstance(sel, Mapping):
            for fieldspec, value in sel.items():
                mods = [m.lower() for m in str(fieldspec).split("|")[1:]]
                if "re" not in mods:
                    continue
                for v in (value if isinstance(value, list) else [value]):
                    found.append((f"{name}.{fieldspec}", v))
        elif isinstance(sel, list):
            for item in sel:
                walk(name, item)

    for name, body in detection.items():
        if str(name) != "condition":
            walk(str(name), body)
    return found


def rule_problems(doc: Any, *, known_models: Sequence[str] = ()) -> list[str]:
    """``[]`` when ``doc`` is a detection rule this build can actually run, else why not."""
    if not isinstance(doc, Mapping):
        return ["a rule must be a mapping"]
    rid = str(doc.get("id") or doc.get("title") or "?")
    problems: list[str] = []
    if doc.get("correlation"):
        # `load_correlation_rules` reads FILES only; a correlation rule stored as a
        # custom_rules row is loaded by nothing and fires never.
        problems.append(f"{rid}: correlation rules load from `rules/` files only and "
                        "cannot travel in a content pack")
    detection = doc.get("detection")
    if not isinstance(detection, Mapping) or not detection:
        return problems + [f"{rid}: needs a non-empty `detection` block"]
    if not str(doc.get("title") or "").strip():
        problems.append(f"{rid}: missing title")
    level = str(doc.get("level") or "medium").lower()
    if level not in _RULE_LEVELS:
        problems.append(f"{rid}: level must be one of {sorted(_RULE_LEVELS)}, got {level!r}")
    problems += [f"{rid}: {p}" for p in condition_problems(detection)]
    for where, pattern in _selection_regexes(detection):
        problems += [f"{rid}: {p}" for p in check_regex(pattern, where)]
    try:
        rule = detection_engine.rule_from_dict(dict(doc), "contentpack")
    except Exception as exc:                                # noqa: BLE001 — untrusted doc
        return problems + [f"{rid}: does not compile ({exc})"]
    if known_models:
        known = {str(m).strip().lower() for m in known_models}
        for name in rule.datamodels:
            if str(name).strip().lower() not in known:
                # An unknown binding disables the rule in `engine._gate` — invisibly.
                problems.append(f"{rid}: unknown CIM data model {name!r} "
                                f"(known: {', '.join(sorted(known))})")
    return problems


# --------------------------------------------------------------------------- #
#  Section parsing (pure)                                                     #
# --------------------------------------------------------------------------- #
def _parser_entry(raw: Any, index: int) -> ParserEntry:
    where = f"parsers[{index}]"
    doc = _mapping(raw, where)
    _reject_unknown(doc, _PARSER_KEYS, where)
    field_map_raw = doc.get("field_map") or {}
    if not isinstance(field_map_raw, Mapping):
        raise PackError(f"{where}.field_map must be a mapping of raw key -> column")
    if len(field_map_raw) > MAX_FIELD_MAP_ENTRIES:
        raise PackError(f"{where}.field_map has {len(field_map_raw)} entries "
                        f"(limit {MAX_FIELD_MAP_ENTRIES})")
    pairs: list[tuple[str, str]] = []
    for key, column in field_map_raw.items():
        col = _text(column, f"{where}.field_map[{key!r}]", required=True, limit=64)
        if col not in PARSER_COLUMNS:
            raise PackError(f"{where}.field_map[{key!r}] targets {col!r}, which is not a "
                            f"fillable column (allowed: {', '.join(sorted(PARSER_COLUMNS))})")
        pairs.append((_text(key, f"{where}.field_map key", required=True, limit=256), col))
    if not pairs and not (doc.get("vendor") or doc.get("product")):
        raise PackError(f"{where}: a parser needs a field_map, a vendor or a product — "
                        "otherwise it matches events and changes nothing")
    return ParserEntry(
        id=_ident(doc.get("id"), f"{where}.id"),
        title=_text(doc.get("title") or doc.get("id"), f"{where}.title", required=True,
                    limit=200),
        match_key=_text(doc.get("match_key"), f"{where}.match_key", required=True, limit=256),
        match_value=_text(doc.get("match_value"), f"{where}.match_value", required=True,
                          limit=256),
        field_map=tuple(pairs),
        vendor=_text(doc.get("vendor"), f"{where}.vendor", limit=64),
        product=_text(doc.get("product"), f"{where}.product", limit=64),
        kv_source=_text(doc.get("kv_source"), f"{where}.kv_source", limit=256),
        kv_sep=_text(doc.get("kv_sep"), f"{where}.kv_sep", limit=16),
        enabled=_bool(doc.get("enabled"), f"{where}.enabled"),
    )


def _rule_entry(raw: Any, index: int, known_models: Sequence[str]) -> RuleEntry:
    where = f"rules[{index}]"
    doc = _mapping(raw, where)
    _reject_unknown(doc, _RULE_KEYS, where)
    text = doc.get("yaml")
    inline = doc.get("rule")
    if text and inline:
        raise PackError(f"{where}: give either `yaml` (verbatim text) or `rule` "
                        "(an inline mapping), not both")
    if inline is not None:
        _mapping(inline, f"{where}.rule")
        text = yaml.safe_dump(dict(inline), sort_keys=False, allow_unicode=True)
    if not text:
        raise PackError(f"{where}: needs a `yaml` rule body")
    text = str(text)
    if len(text) > MAX_RULE_CHARS:
        raise PackError(f"{where}.yaml is longer than {MAX_RULE_CHARS} characters")
    try:
        parsed = _rule_doc(text)
    except PackError:
        raise
    except Exception as exc:                                # noqa: BLE001 — untrusted text
        raise PackError(f"{where}.yaml is not valid YAML ({exc})") from exc
    if not parsed:
        raise PackError(f"{where}.yaml has no document with a `detection` block")
    problems = rule_problems(parsed, known_models=known_models)
    if problems:
        raise PackError(f"{where}: " + "; ".join(problems))
    rule_id = doc.get("id") or parsed.get("id")
    return RuleEntry(
        id=_ident(rule_id, f"{where}.id"),
        title=_text(doc.get("title") or parsed.get("title"), f"{where}.title",
                    required=True, limit=200),
        yaml_text=text,
        enabled=_bool(doc.get("enabled"), f"{where}.enabled"),
    )


def _cim_entry(raw: Any, index: int, known_models: Sequence[str]) -> CimEntry:
    where = f"cim[{index}]"
    doc = _mapping(raw, where)
    _reject_unknown(doc, _CIM_KEYS, where)
    model = _text(doc.get("model"), f"{where}.model", required=True, limit=64)
    if known_models and model.strip().lower() not in {str(m).lower() for m in known_models}:
        raise PackError(
            f"{where}.model {model!r} is not a data model in this build "
            f"(known: {', '.join(sorted(str(m) for m in known_models))}). A pack may EXTEND "
            "a model, never define one: a model tag is what detections bind to.")
    clauses = _seq(doc.get("membership"), f"{where}.membership")
    fields = _seq(doc.get("fields"), f"{where}.fields")
    if not clauses and not fields:
        raise PackError(f"{where}: needs `membership` clauses or `fields`")
    # Validate through the registry's OWN parser, so a pack can express exactly what
    # models.yaml can express and nothing more (bad column / unsafe jsonb key / bad
    # value type all raise CimError here, before anything is stored).
    for clause in clauses:
        try:
            cim_registry._clause(_mapping(clause, f"{where}.membership item"))
        except CimError as exc:
            raise PackError(f"{where}.membership: {exc}") from exc
    for spec in fields:
        try:
            cim_registry._field(dict(_mapping(spec, f"{where}.fields item")))
        except CimError as exc:
            raise PackError(f"{where}.fields: {exc}") from exc
    return CimEntry(model=model, membership=tuple(clauses), fields=tuple(fields),
                    note=_text(doc.get("note"), f"{where}.note"))


def _compliance_entry(raw: Any, index: int,
                      known_frameworks: Sequence[str]) -> ComplianceEntry:
    where = f"compliance[{index}]"
    doc = _mapping(raw, where)
    _reject_unknown(doc, _COMPLIANCE_KEYS, where)
    technique = _text(doc.get("technique"), f"{where}.technique", required=True, limit=32).upper()
    if not _TECHNIQUE_RE.match(technique):
        raise PackError(f"{where}.technique must be an ATT&CK id like T1110 / T1021.001 / "
                        f"AML.T0051, got {technique!r}")
    framework = _text(doc.get("framework"), f"{where}.framework", required=True, limit=64)
    if known_frameworks and framework not in known_frameworks:
        raise PackError(
            f"{where}.framework {framework!r} is not rendered by this build "
            f"(known: {', '.join(known_frameworks)}); adding a framework needs an edit to "
            "`app/compliance.py:FRAMEWORKS`, otherwise its controls would import and never "
            "be shown")
    controls: list[tuple[str, str]] = []
    for j, control in enumerate(_seq(doc.get("controls"), f"{where}.controls")):
        cwhere = f"{where}.controls[{j}]"
        cdoc = _mapping(control, cwhere)
        _reject_unknown(cdoc, _CONTROL_KEYS, cwhere)
        controls.append((_text(cdoc.get("id"), f"{cwhere}.id", required=True, limit=64),
                         _text(cdoc.get("name"), f"{cwhere}.name", required=True, limit=200)))
    if not controls:
        raise PackError(f"{where}.controls must list at least one control")
    return ComplianceEntry(technique=technique, framework=framework,
                           controls=tuple(controls))


def _signature(raw: Any) -> Optional[Signature]:
    if raw is None:
        return None
    doc = _mapping(raw, "signature")
    _reject_unknown(doc, _SIGNATURE_KEYS, "signature")
    algorithm = _text(doc.get("algorithm"), "signature.algorithm", required=True, limit=32)
    if algorithm != SIGNATURE_ALGORITHM:
        raise PackError(f"signature.algorithm {algorithm!r} is not supported "
                        f"(this build verifies {SIGNATURE_ALGORITHM})")
    value = _text(doc.get("value"), "signature.value", required=True, limit=256)
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise PackError("signature.value must be a 64-character lower-case hex digest")
    return Signature(algorithm=algorithm,
                     key_id=_text(doc.get("key_id"), "signature.key_id", limit=64),
                     value=value)


def _requires(raw: Any) -> tuple[tuple[str, str], ...]:
    if raw is None:
        return ()
    doc = _mapping(raw, "requires")
    _reject_unknown(doc, _REQUIRES_KEYS, "requires")
    return tuple((str(k), _text(v, f"requires.{k}", required=True, limit=64))
                 for k, v in doc.items())


# --------------------------------------------------------------------------- #
#  Parse / serialize (pure)                                                   #
# --------------------------------------------------------------------------- #
def pack_from_dict(doc: Any, *, known_models: Sequence[str] = (),
                   known_frameworks: Sequence[str] = ()) -> Pack:
    """Validate a parsed document into a :class:`Pack`. Raises :class:`PackError`.

    ``known_models`` / ``known_frameworks`` are passed in rather than looked up so this
    stays a pure function; :func:`parse` fills them from the live registry by default.
    """
    top = _mapping(doc, "the pack")
    _reject_unknown(top, _TOP_KEYS, "the pack")
    if _depth(top) > MAX_DEPTH:
        raise PackError(f"the pack nests deeper than {MAX_DEPTH} levels")
    fmt_raw = top.get("pack", PACK_FORMAT)
    try:
        fmt = int(fmt_raw)
    except (TypeError, ValueError) as exc:
        raise PackError(f"pack: format must be an integer, got {fmt_raw!r}") from exc
    labels = tuple(_text(x, "labels item", required=True, limit=64)
                   for x in _seq(top.get("labels"), "labels"))
    pack = Pack(
        name=_slug(top.get("name"), "name"),
        version=_version(top.get("version"), "version"),
        format=fmt,
        description=_text(top.get("description"), "description"),
        author=_text(top.get("author"), "author", limit=200),
        license=_text(top.get("license"), "license", limit=200),
        homepage=_text(top.get("homepage"), "homepage", limit=500),
        labels=labels,
        requires=_requires(top.get("requires")),
        parsers=tuple(_parser_entry(x, i)
                      for i, x in enumerate(_seq(top.get("parsers"), "parsers"))),
        rules=tuple(_rule_entry(x, i, known_models)
                    for i, x in enumerate(_seq(top.get("rules"), "rules"))),
        cim=tuple(_cim_entry(x, i, known_models)
                  for i, x in enumerate(_seq(top.get("cim"), "cim"))),
        compliance=tuple(_compliance_entry(x, i, known_frameworks)
                         for i, x in enumerate(_seq(top.get("compliance"), "compliance"))),
        signature=_signature(top.get("signature")),
    )
    for kind, idents in (("parser", [p.id for p in pack.parsers]),
                         ("rule", [r.id for r in pack.rules])):
        dupes = sorted({i for i in idents if idents.count(i) > 1})
        if dupes:
            raise PackError(f"duplicate {kind} id(s) in the pack: {', '.join(dupes)}")
    if pack.is_empty:
        raise PackError("a content pack must carry at least one parser, rule, CIM "
                        "membership or compliance entry")
    return pack


def parse(text: str, *, known_models: Optional[Sequence[str]] = None,
          known_frameworks: Optional[Sequence[str]] = None) -> Pack:
    """Read pack TEXT (YAML or JSON) into a :class:`Pack`. Raises :class:`PackError`.

    With ``known_models``/``known_frameworks`` omitted, the live CIM registry and the
    shipped framework list are consulted — both are file/module state, never the database.
    Pass them explicitly to keep a caller (or a test) fully self-contained.
    """
    if text is None:
        raise PackError("no pack content")
    blob = text.encode("utf-8", "ignore") if isinstance(text, str) else bytes(text)
    if len(blob) > MAX_DOCUMENT_BYTES:
        raise PackError(f"pack is {len(blob)} bytes, over the {MAX_DOCUMENT_BYTES}-byte limit")
    try:
        doc = yaml.load(text, Loader=_PackLoader)           # noqa: S506 — hardened loader
    except PackError:
        raise
    except yaml.YAMLError as exc:
        raise PackError(f"pack is not valid YAML: {exc}") from exc
    if known_models is None:
        known_models = _registry_model_names()
    if known_frameworks is None:
        known_frameworks = tuple(compliance_module.FRAMEWORKS)
    return pack_from_dict(doc, known_models=known_models,
                          known_frameworks=known_frameworks)


def _registry_model_names() -> tuple[str, ...]:
    """Model names + tags from the live registry; ``()`` when it cannot be read.

    Degrading to "no known models" disables the two membership checks rather than
    refusing every pack — a broken registry is already reported by ``/health``, and a
    second, more confusing symptom there does not help anyone.
    """
    try:
        reg = cim_registry.get_registry()
    except Exception:                                       # noqa: BLE001
        log.warning("content pack validation: CIM registry unavailable, "
                    "skipping data-model checks")
        return ()
    return tuple(sorted({*(t for t in reg.tags), *(n.lower() for n in reg.names)}))


def to_dict(pack: Pack) -> dict:
    """The pack as plain JSON/YAML-able data. Empty sections and empty optional fields are
    omitted so the exported document reads like something a human wrote."""
    out: dict[str, Any] = {"pack": pack.format, "name": pack.name, "version": pack.version}
    for key in ("description", "author", "license", "homepage"):
        value = getattr(pack, key)
        if value:
            out[key] = value
    if pack.labels:
        out["labels"] = list(pack.labels)
    if pack.requires:
        out["requires"] = {k: v for k, v in pack.requires}
    if pack.parsers:
        out["parsers"] = [_parser_to_dict(p) for p in pack.parsers]
    if pack.rules:
        out["rules"] = [{"id": r.id, "title": r.title, "yaml": r.yaml_text,
                         **({} if r.enabled else {"enabled": False})}
                        for r in pack.rules]
    if pack.cim:
        out["cim"] = [{"model": c.model,
                       **({"membership": [dict(m) for m in c.membership]} if c.membership else {}),
                       **({"fields": [dict(f) for f in c.fields]} if c.fields else {}),
                       **({"note": c.note} if c.note else {})}
                      for c in pack.cim]
    if pack.compliance:
        out["compliance"] = [{"technique": c.technique, "framework": c.framework,
                              "controls": [{"id": i, "name": n} for i, n in c.controls]}
                             for c in pack.compliance]
    if pack.signature:
        out["signature"] = {"algorithm": pack.signature.algorithm,
                            **({"key_id": pack.signature.key_id} if pack.signature.key_id else {}),
                            "value": pack.signature.value}
    return out


def _parser_to_dict(p: ParserEntry) -> dict:
    out: dict[str, Any] = {"id": p.id, "title": p.title, "match_key": p.match_key,
                           "match_value": p.match_value}
    if p.field_map:
        out["field_map"] = dict(p.field_map)
    for key in ("vendor", "product", "kv_source", "kv_sep"):
        value = getattr(p, key)
        if value:
            out[key] = value
    if not p.enabled:
        out["enabled"] = False
    return out


def dumps(pack: Pack) -> str:
    """Serialize a pack to the canonical YAML document. ``parse(dumps(p)) == p``."""
    return yaml.dump(to_dict(pack), Dumper=_PackDumper, sort_keys=False,
                     allow_unicode=True, default_flow_style=False, width=100)


def validate(source: Any, *, known_models: Optional[Sequence[str]] = None,
             known_frameworks: Optional[Sequence[str]] = None) -> list[str]:
    """``[]`` when ``source`` (pack text or a parsed mapping) is a usable pack, else the
    problem. For the console's pre-import check, where a human is looking at the message."""
    try:
        if isinstance(source, Mapping):
            pack_from_dict(source,
                           known_models=known_models if known_models is not None
                           else _registry_model_names(),
                           known_frameworks=known_frameworks if known_frameworks is not None
                           else tuple(compliance_module.FRAMEWORKS))
        else:
            parse(source, known_models=known_models, known_frameworks=known_frameworks)
    except PackError as exc:
        return [str(exc)]
    return []


# --------------------------------------------------------------------------- #
#  Integrity + signing (pure)                                                 #
# --------------------------------------------------------------------------- #
def canonical_bytes(pack: Pack) -> bytes:
    """The exact bytes a digest or signature covers: canonical JSON of the pack WITHOUT
    its signature block, keys sorted, no insignificant whitespace.

    Covering the PARSED pack rather than the file bytes is deliberate: re-indenting the
    YAML, reordering keys or converting it to JSON must not invalidate a signature, while
    anything that changes what gets INSTALLED must. Since a pack is parsed with aliases and
    duplicate keys refused, there is no YAML construct that can differ here and still land
    differently in the database.
    """
    return json.dumps(to_dict(replace(pack, signature=None)), sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(pack: Pack) -> str:
    """SHA-256 of :func:`canonical_bytes` — the pack's content address.

    Always available, no key needed. This is the value to publish alongside a download and
    to compare against a detached GPG/minisign signature over the file in a distribution
    model where no shared secret exists.
    """
    return hashlib.sha256(canonical_bytes(pack)).hexdigest()


def sign(pack: Pack, key: str, *, key_id: str = "") -> Pack:
    """Return a copy of ``pack`` carrying an HMAC-SHA256 signature.

    HMAC is symmetric, so this authenticates "produced by someone holding this key" — the
    right model for an internal or air-gapped pack repository, which is the shipped one.
    It is NOT public-key signing: a true community-distribution model needs Ed25519, which
    needs the optional ``cryptography`` package, so :func:`digest` is published instead and
    can be checked against a detached out-of-band signature.
    """
    if not key:
        raise PackError("signing needs a key")
    mac = hmac.new(_key_bytes(key), canonical_bytes(pack), hashlib.sha256).hexdigest()
    return replace(pack, signature=Signature(algorithm=SIGNATURE_ALGORITHM,
                                             key_id=str(key_id), value=mac))


def verify(pack: Pack, key: str) -> bool:
    """True when ``pack`` carries a signature this ``key`` produced. Constant-time."""
    if pack.signature is None or not key:
        return False
    if pack.signature.algorithm != SIGNATURE_ALGORITHM:
        return False
    expected = hmac.new(_key_bytes(key), canonical_bytes(pack), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, pack.signature.value)


def _key_bytes(key: Any) -> bytes:
    return key if isinstance(key, (bytes, bytearray)) else str(key).encode("utf-8")


# --------------------------------------------------------------------------- #
#  Export (pure transforms over DB ROWS — no database here)                   #
# --------------------------------------------------------------------------- #
def parser_entry_from_row(row: Mapping[str, Any]) -> ParserEntry:
    """A ``custom_parsers`` row -> :class:`ParserEntry`. Pure: ``row`` is a plain dict."""
    field_map = row.get("field_map") or {}
    if isinstance(field_map, str):                  # jsonb may arrive as text
        try:
            field_map = json.loads(field_map)
        except ValueError:
            field_map = {}
    pairs = tuple((str(k), str(v)) for k, v in sorted(dict(field_map).items())
                  if str(v) in PARSER_COLUMNS)
    return ParserEntry(
        id=str(row.get("parser_id") or row.get("id") or ""),
        title=str(row.get("title") or row.get("parser_id") or ""),
        match_key=str(row.get("match_key") or ""),
        match_value=str(row.get("match_value") or ""),
        field_map=pairs,
        vendor=str(row.get("vendor") or ""),
        product=str(row.get("product") or ""),
        kv_source=str(row.get("kv_source") or ""),
        kv_sep=str(row.get("kv_sep") or ""),
        enabled=bool(row.get("enabled", True)),
    )


def rule_entry_from_row(row: Mapping[str, Any]) -> RuleEntry:
    """A ``custom_rules`` row -> :class:`RuleEntry`, keeping the YAML text verbatim."""
    return RuleEntry(id=str(row.get("rule_id") or row.get("id") or ""),
                     title=str(row.get("title") or row.get("rule_id") or ""),
                     yaml_text=str(row.get("yaml_text") or ""),
                     enabled=bool(row.get("enabled", True)))


def compliance_entries_from_map(mapping: Mapping[str, Mapping[str, Sequence]],
                                techniques: Sequence[str] = ()) -> tuple[ComplianceEntry, ...]:
    """``compliance.MAP``-shaped data -> entries, optionally narrowed to ``techniques``."""
    want = {str(t).upper() for t in techniques}
    out: list[ComplianceEntry] = []
    for technique in sorted(mapping):
        if want and str(technique).upper() not in want:
            continue
        for framework in sorted(mapping[technique]):
            controls = tuple((str(cid), str(cname))
                             for cid, cname in mapping[technique][framework])
            if controls:
                out.append(ComplianceEntry(technique=str(technique).upper(),
                                           framework=str(framework), controls=controls))
    return tuple(out)


def export_pack(*, name: str, version: str, description: str = "", author: str = "",
                license: str = "", homepage: str = "", labels: Sequence[str] = (),
                requires: Mapping[str, str] = (),
                parser_rows: Sequence[Mapping[str, Any]] = (),
                rule_rows: Sequence[Mapping[str, Any]] = (),
                cim: Sequence[CimEntry] = (),
                compliance: Sequence[ComplianceEntry] = (),
                known_models: Sequence[str] = (),
                known_frameworks: Sequence[str] = ()) -> Pack:
    """Build a :class:`Pack` from DB rows and hand-written sections, then validate it.

    Pure: every input is a plain data structure, so the export path is unit-tested with no
    database. The built pack goes through :func:`pack_from_dict`, which means an export can
    never produce a document this build would refuse to import.
    """
    draft = Pack(
        name=str(name), version=str(version), description=description, author=author,
        license=license, homepage=homepage, labels=tuple(labels),
        requires=tuple(dict(requires).items()) if requires else (),
        parsers=tuple(parser_entry_from_row(r) for r in parser_rows),
        rules=tuple(rule_entry_from_row(r) for r in rule_rows),
        cim=tuple(cim), compliance=tuple(compliance))
    return pack_from_dict(to_dict(draft), known_models=known_models,
                          known_frameworks=known_frameworks)


# --------------------------------------------------------------------------- #
#  Planning (pure): what an import WOULD do                                   #
# --------------------------------------------------------------------------- #
def _parser_row_matches(entry: ParserEntry, row: Mapping[str, Any]) -> bool:
    """Is the stored row already exactly this entry?  ``field_map`` is compared as a SET of
    pairs (``parser_entry_from_row`` sorts it), so a re-ordered map is not a spurious
    update — but any changed value, title included, is."""
    return parser_entry_from_row(row) == replace(entry,
                                                 field_map=tuple(sorted(entry.field_map)))


def _verb(ident: str, kind: str, present: bool, same: bool, owner: str,
          pack_name: str, overwrite: bool) -> tuple[str, str]:
    """(verb, detail) for one object. Ownership is what separates update from conflict."""
    if not present:
        return CREATE, ""
    if owner and owner != pack_name and not overwrite:
        return CONFLICT, f"{kind} {ident} already belongs to pack {owner!r}"
    if not owner and not overwrite:
        return CONFLICT, (f"{kind} {ident} exists but was not installed by a pack; "
                          "re-import with overwrite to replace it")
    return (UNCHANGED, "") if same else (UPDATE, "")


def plan_install(pack: Pack, existing: ExistingState, *,
                 overwrite: bool = False,
                 app_version: Optional[str] = None,
                 cim_version: Optional[int] = None) -> ImportPlan:
    """The dry run. Pure: ``(pack, snapshot) -> every change and every problem``, no writes.

    Objects the SAME pack installed previously but that this version no longer carries
    become ``delete`` changes, so an upgrade removes what it dropped instead of leaving
    orphans behind. Objects owned by a different pack — or by hand — are ``conflict``s, and
    a plan with conflicts is not applicable unless ``overwrite`` was asked for explicitly.
    """
    problems: list[str] = []
    if app_version is not None:
        problems += compatibility_problems(pack, app_version=app_version,
                                           cim_version=cim_version)
    if existing.models:
        known = {str(m).lower() for m in existing.models}
        for entry in pack.cim:
            if entry.model.lower() not in known:
                problems.append(f"cim: unknown data model {entry.model!r}")
    if existing.frameworks:
        for entry in pack.compliance:
            if entry.framework not in existing.frameworks:
                problems.append(f"compliance: unknown framework {entry.framework!r}")

    changes: list[Change] = []
    previous = existing.installed.get(pack.name)
    changes.append(Change("pack", pack.key,
                          UPDATE if previous else CREATE,
                          f"was {previous.version}" if previous else ""))

    for entry in pack.parsers:
        row = existing.parsers.get(entry.id)
        same = bool(row) and _parser_row_matches(entry, row)
        verb, detail = _verb(entry.id, "parser", row is not None, same,
                             existing.owner_of("parser", entry.id), pack.name, overwrite)
        changes.append(Change("parser", entry.id, verb, detail,
                              owner=existing.owner_of("parser", entry.id)))

    for entry in pack.rules:
        stored = existing.rules.get(entry.id)
        same = stored is not None and stored == entry.yaml_text
        verb, detail = _verb(entry.id, "rule", stored is not None, same,
                             existing.owner_of("rule", entry.id), pack.name, overwrite)
        changes.append(Change("rule", entry.id, verb, detail,
                              owner=existing.owner_of("rule", entry.id)))

    for entry in pack.cim:
        same = bool(previous) and entry in previous.cim
        changes.append(Change("cim", entry.model, UNCHANGED if same else CREATE,
                              f"+{len(entry.membership)} clause(s), "
                              f"+{len(entry.fields)} field(s)"))
    for entry in pack.compliance:
        same = bool(previous) and entry in previous.compliance
        changes.append(Change("compliance", f"{entry.technique}/{entry.framework}",
                              UNCHANGED if same else CREATE,
                              f"{len(entry.controls)} control(s)"))

    if previous:
        keep_parsers = {p.id for p in pack.parsers}
        keep_rules = {r.id for r in pack.rules}
        for old in previous.parsers:
            if old.id not in keep_parsers:
                changes.append(Change("parser", old.id, DELETE,
                                      f"dropped in {pack.version}"))
        for old in previous.rules:
            if old.id not in keep_rules:
                changes.append(Change("rule", old.id, DELETE,
                                      f"dropped in {pack.version}"))

    return ImportPlan(pack=pack, changes=tuple(changes), problems=tuple(problems),
                      overwrite=overwrite)


def plan_uninstall(name: str, existing: ExistingState) -> ImportPlan:
    """Remove exactly what the named pack installed — nothing it merely touched."""
    pack = existing.installed.get(name)
    if pack is None:
        raise PackError(f"content pack {name!r} is not installed")
    changes = [Change("pack", pack.key, DELETE)]
    for entry in pack.parsers:
        if existing.owner_of("parser", entry.id) in ("", name):
            changes.append(Change("parser", entry.id, DELETE))
    for entry in pack.rules:
        if existing.owner_of("rule", entry.id) in ("", name):
            changes.append(Change("rule", entry.id, DELETE))
    for entry in pack.cim:
        changes.append(Change("cim", entry.model, DELETE))
    for entry in pack.compliance:
        changes.append(Change("compliance", f"{entry.technique}/{entry.framework}", DELETE))
    return ImportPlan(pack=pack, changes=tuple(changes))


# --------------------------------------------------------------------------- #
#  Merges (pure): how a pack's CIM + compliance sections take effect          #
# --------------------------------------------------------------------------- #
def merge_cim(registry: CimRegistry, entries: Sequence[CimEntry]) -> CimRegistry:
    """Return a NEW registry with each entry's clauses/fields APPENDED to its model.

    Additive only, by design:

    * a pack cannot define a model (unknown name -> :class:`PackError`), because a model
      tag is the handle detections bind to;
    * a pack cannot replace or remove a shipped clause or field — its clauses are ORed on
      the end, so it can only widen membership, never narrow or redirect it;
    * a field name already on the model is refused: two fields of one name load fine and
      then abort ``CREATE VIEW`` with SQLSTATE 42701.

    ``version`` is bumped only when FIELDS are added, because ``version`` documents the
    model's schema; widening membership adds no column and breaks no consumer.
    """
    by_model: dict[str, list[CimEntry]] = {}
    known = {m.name.lower(): m for m in registry.models}
    known.update({m.tag: m for m in registry.models})
    for entry in entries:
        model = known.get(entry.model.strip().lower())
        if model is None:
            raise PackError(f"cim: {entry.model!r} is not a data model in this build "
                            f"(known: {', '.join(sorted(registry.tags))})")
        by_model.setdefault(model.tag, []).append(entry)
    if not by_model:
        return registry

    models: list[CimModel] = []
    for model in registry.models:
        additions = by_model.get(model.tag)
        if not additions:
            models.append(model)
            continue
        clauses = list(model.clauses)
        fields: list[CimField] = list(model.fields)
        names = {f.name for f in fields}
        for entry in additions:
            clauses += [cim_registry._clause(dict(c)) for c in entry.membership]
            for spec in entry.fields:
                new = cim_registry._field(dict(spec))
                if new.name in names:
                    raise PackError(
                        f"cim: field {new.name!r} already exists on model {model.name!r}; "
                        "a pack may add fields, never redefine them")
                names.add(new.name)
                fields.append(new)
        added_fields = len(fields) - len(model.fields)
        models.append(CimModel(
            name=model.name, tag=model.tag,
            version=model.version + (1 if added_fields else 0),
            description=model.description, clauses=tuple(clauses), fields=tuple(fields)))
    return CimRegistry(version=registry.version, models=tuple(models))


def merge_compliance(base: Mapping[str, Mapping[str, Sequence]],
                     entries: Sequence[ComplianceEntry]) -> dict:
    """Return a NEW ``compliance.MAP``-shaped dict with the entries merged in.

    Additive and order-stable: an entry adds controls to
    ``technique -> framework``, keeping the shipped ones first and dropping exact
    duplicates. Nothing is removed — a pack cannot un-map a control someone else's audit
    report already depends on.
    """
    out: dict[str, dict[str, list[tuple[str, str]]]] = {
        str(t): {str(f): [(str(c[0]), str(c[1])) for c in controls]
                 for f, controls in frameworks.items()}
        for t, frameworks in base.items()}
    for entry in entries:
        frameworks = out.setdefault(entry.technique, {})
        controls = frameworks.setdefault(entry.framework, [])
        seen = {c[0] for c in controls}
        for cid, cname in entry.controls:
            if cid not in seen:
                controls.append((cid, cname))
                seen.add(cid)
    return out


# --------------------------------------------------------------------------- #
#  Writers — the ONE place a pack reaches the database                        #
# --------------------------------------------------------------------------- #
class PackWriter:
    """Buffers every write a plan implies, then commits them in one flush.

    Two implementations: :class:`RecordingWriter` (memory — dry runs and tests) and
    :class:`DbWriter`. Buffering is what makes the import as atomic as it can be: the
    whole plan is validated, then staged, then handed to the database in ONE call. Nothing
    is written while the plan is still being decided.
    """

    def __init__(self) -> None:
        self.parsers: list[ParserEntry] = []
        self.rules: list[RuleEntry] = []
        self.removed_parsers: list[str] = []
        self.removed_rules: list[str] = []
        self.pack: Optional[Pack] = None
        self.removed_pack: str = ""

    def put_parser(self, entry: ParserEntry) -> None:
        self.parsers.append(entry)

    def put_rule(self, entry: RuleEntry) -> None:
        self.rules.append(entry)

    def drop_parser(self, parser_id: str) -> None:
        self.removed_parsers.append(parser_id)

    def drop_rule(self, rule_id: str) -> None:
        self.removed_rules.append(rule_id)

    def put_pack(self, pack: Pack) -> None:
        self.pack = pack

    def drop_pack(self, name: str) -> None:
        self.removed_pack = name

    def flush(self) -> None:
        """Commit the buffer. The base class keeps it in memory (dry runs, tests)."""


class RecordingWriter(PackWriter):
    """A writer that only remembers. What a dry run and a unit test both want."""


class DbWriter(PackWriter):
    """Commits the buffered plan through ONE database call, inside one transaction.

    ``db.apply_content_pack`` is the single wiring point this module needs on the write
    side — deliberately one call rather than a loop of upserts, so a pack cannot land
    half-installed. Its ``parsers``/``rules`` rows carry exactly the keyword names of
    ``db.upsert_custom_parser`` / ``db.upsert_custom_rule``, so the transaction body is a
    pair of ``**row`` splats.

    ``installed_by`` is the console user who imported the pack. It is carried here rather
    than looked up because this module never touches the request: the route passes it in,
    exactly as it passes the actor to ``db.add_audit``. Empty means "unattributed" (a CLI
    or test import) and stores NULL.
    """

    def __init__(self, installed_by: str = "") -> None:
        super().__init__()
        self.installed_by = installed_by

    def flush(self) -> None:
        from . import db                                   # lazy: keeps this module DB-free
        db.apply_content_pack(
            installed_by=self.installed_by,
            pack_name=self.pack.name if self.pack else self.removed_pack,
            version=self.pack.version if self.pack else "",
            document=dumps(self.pack) if self.pack else "",
            digest=digest(self.pack) if self.pack else "",
            parsers=[_parser_write_row(p) for p in self.parsers],
            rules=[{"rule_id": r.id, "title": r.title, "yaml_text": r.yaml_text,
                    "enabled": r.enabled} for r in self.rules],
            removed_parsers=list(self.removed_parsers),
            removed_rules=list(self.removed_rules),
            remove_pack=self.removed_pack or "")


def _parser_write_row(p: ParserEntry) -> dict:
    return {"parser_id": p.id, "title": p.title, "match_key": p.match_key,
            "match_value": p.match_value, "field_map": p.field_map_dict,
            "vendor": p.vendor or None, "product": p.product or None,
            "enabled": p.enabled, "kv_source": p.kv_source or None,
            "kv_sep": p.kv_sep or None}


def apply_plan(plan: ImportPlan, writer: PackWriter) -> ApplyResult:
    """Stage a plan into ``writer`` and flush it. Refuses anything but a clean plan.

    The refusal is the point: validation and conflict detection happen in
    :func:`plan_install`, with no writes, and this function will not paper over either.
    """
    if plan.problems:
        raise PackError("this pack cannot be imported:\n  " + "\n  ".join(plan.problems))
    if plan.conflicts:
        raise PackError("this pack conflicts with existing content:\n  " +
                        "\n  ".join(c.describe() for c in plan.conflicts))
    by_ident = {(c.kind, c.ident): c for c in plan.changes}
    applied: list[Change] = []
    for entry in plan.pack.parsers:
        change = by_ident.get(("parser", entry.id))
        if change and change.verb in (CREATE, UPDATE):
            writer.put_parser(entry)
            applied.append(change)
    for entry in plan.pack.rules:
        change = by_ident.get(("rule", entry.id))
        if change and change.verb in (CREATE, UPDATE):
            writer.put_rule(entry)
            applied.append(change)
    # Only parser/rule deletions are RECORDED here. `cim`/`compliance` are owned by the
    # loop below and the pack row by the block after it, so restricting this loop to the
    # two kinds it actually writes is what keeps `applied` a faithful list: before, an
    # uninstall reported every cim, compliance and pack removal TWICE, because each was
    # appended once here and again by its real owner.
    for change in plan.changes:
        if change.verb != DELETE or change.kind not in ("parser", "rule"):
            continue
        if change.kind == "parser":
            writer.drop_parser(change.ident)
        else:
            writer.drop_rule(change.ident)
        applied.append(change)
    for change in plan.changes:
        if change.kind in ("cim", "compliance") and change.verb != UNCHANGED:
            applied.append(change)
    pack_change = by_ident.get(("pack", plan.pack.key))
    if pack_change and pack_change.verb == DELETE:
        writer.drop_pack(plan.pack.name)
    else:
        writer.put_pack(plan.pack)
    if pack_change:
        applied.append(pack_change)
    writer.flush()
    return ApplyResult(pack=plan.pack, applied=tuple(applied),
                       restart_required=plan.restart_required)


# --------------------------------------------------------------------------- #
#  The thin database layer (everything above is pure)                         #
# --------------------------------------------------------------------------- #
def snapshot() -> ExistingState:
    """Read what is installed today. The only DB READ in this module."""
    from . import db                                       # lazy: keeps imports DB-free
    parsers = {str(r["parser_id"]): dict(r) for r in db.list_custom_parsers()}
    rules = {str(r["rule_id"]): str(r["yaml_text"]) for r in db.list_custom_rules()}
    installed: dict[str, Pack] = {}
    owners: dict[tuple[str, str], str] = {}
    for pack in installed_packs():
        installed[pack.name] = pack
        for entry in pack.parsers:
            owners[("parser", entry.id)] = pack.name
        for entry in pack.rules:
            owners[("rule", entry.id)] = pack.name
    return ExistingState(parsers=parsers, rules=rules, owners=owners, installed=installed,
                         models=_registry_model_names(),
                         frameworks=tuple(compliance_module.FRAMEWORKS))


def installed_packs(known_models: Optional[Sequence[str]] = None) -> tuple[Pack, ...]:
    """Every installed pack, newest-installed last. Never raises: a pack that no longer
    parses (an older format, a hand-edited row) is logged and skipped, because a bad row
    must not be able to take down the CIM registry or the compliance page with it.

    ``known_models`` MUST be supplied by :func:`overlay_registry`. Left None, :func:`parse`
    resolves the model list by calling ``cim_registry.get_registry()`` — and the overlay
    runs *inside* that function, whose lock is a plain non-reentrant ``threading.Lock``.
    The re-entrant call therefore deadlocks the whole process on the first startup after
    a pack is installed, and it deadlocks silently: ``_registry_model_names`` boxes
    exceptions, but a lock that never releases raises nothing to box. Passing the names
    of the registry the overlay was handed is also the semantically right answer — a
    pack may only EXTEND a model models.yaml already defines, so the shipped registry is
    exactly what its `cim:` section must validate against.
    """
    from . import db                                       # lazy: keeps imports DB-free
    out: list[Pack] = []
    try:
        rows = db.list_content_packs()
    except Exception:                                      # noqa: BLE001 — table may not exist
        return ()
    for row in rows:
        try:
            out.append(parse(str(row["document"]), known_models=known_models))
        except Exception:                                  # noqa: BLE001 — untrusted stored doc
            log.warning("installed content pack %r no longer parses; skipped",
                        row.get("name"))
    return tuple(out)


def registry_model_names(registry: CimRegistry) -> tuple[str, ...]:
    """The model names + tags of a registry ALREADY IN HAND, for `known_models`."""
    return tuple(sorted({*(t for t in registry.tags),
                         *(n.lower() for n in registry.names)}))


def installed_cim_entries(packs: Sequence[Pack]) -> tuple[CimEntry, ...]:
    """Every CIM addition contributed by installed packs, in install order.

    This is what ``app/cim/registry.py`` feeds to :func:`merge_cim` after loading
    ``models.yaml``, so pack membership takes effect — see the wiring notes.
    """
    return tuple(entry for pack in packs for entry in pack.cim)


def installed_compliance_entries(packs: Sequence[Pack]) -> tuple[ComplianceEntry, ...]:
    return tuple(entry for pack in packs for entry in pack.compliance)


def overlay_registry(registry: CimRegistry) -> CimRegistry:
    """``registry`` + every installed pack's CIM additions, or ``registry`` unchanged.

    The single call ``app/cim/registry.py:get_registry`` makes. It never raises: a pack
    whose clauses no longer merge (a model renamed out from under it, say) is logged and
    the SHIPPED registry is returned intact, because the failure mode of a broken overlay
    must be "the pack's model is empty", never "no model works".

    ``known_models`` is threaded through explicitly so nothing on this path calls back
    into ``cim_registry.get_registry`` — see :func:`installed_packs` for why that
    re-entrance is a deadlock rather than merely wasteful.
    """
    try:
        packs = installed_packs(registry_model_names(registry))
        return merge_cim(registry, installed_cim_entries(packs))
    except Exception:                                      # noqa: BLE001
        log.exception("content-pack CIM overlay failed; using the shipped registry")
        return registry


def install(text: str, *, overwrite: bool = False, dry_run: bool = True,
            app_version: Optional[str] = None,
            installed_by: str = "") -> ImportPlan | ApplyResult:
    """Side-load a pack. ``dry_run=True`` (the default) reports and changes NOTHING.

    Defaulting to a dry run is deliberate: a content pack is untrusted input, and the
    caller has to say a second time that it should actually land.

    ``installed_by`` is recorded on the pack row so "who put this rule here?" is
    answerable from the pack table alone, not only from the audit log.
    """
    pack = parse(text)
    plan = plan_install(pack, snapshot(), overwrite=overwrite, app_version=app_version)
    if dry_run:
        return plan
    return apply_plan(plan, DbWriter(installed_by))


def uninstall(name: str, *, dry_run: bool = True) -> ImportPlan | ApplyResult:
    """Remove an installed pack and everything it installed."""
    plan = plan_uninstall(name, snapshot())
    if dry_run:
        return plan
    return apply_plan(plan, DbWriter())
