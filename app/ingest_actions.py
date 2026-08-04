# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Ingest Actions — data-not-code drop / mask / route / sample, applied at write time.

Splunk's equivalent is *Ingest Actions*: the thing an operator reaches for to stop
storing a noisy source, redact PII before it lands, re-attribute a mislabelled feed or
thin a firehose — **without a code change and without a redeploy**. Rules are YAML data,
exactly like ``rules/`` and ``app/cim/models.yaml``.

The matching language is NOT a second language. An ingest action carries the same
``logsource:`` / ``datamodels:`` / ``detection:`` block a detection rule carries, and it
is evaluated by :mod:`app.detection.engine` itself — see "What is reused" below. There is
no ``eval``, no expression compiler and no regex-driven mini-DSL of our own.

Everything that decides is a pure function. :func:`decide` takes ``(actions, event)`` and
returns a :class:`Decision`; it touches no database, no singleton and no clock. The
runtime half (:class:`ActionIndex`, :func:`apply`) is a thin, never-raising wrapper that
holds the loaded rules and counts what happened.


Rule schema
===========

One or more YAML documents per file, in a directory (``ingest_actions/*.yml``)::

    id: ia-drop-dns-noise                 # required-ish (defaults to title, then filename)
    title: Drop successful internal DNS lookups
    description: >
      Free text. Shown in the console; never interpreted.
    enabled: true                         # default true
    order: 10                             # lower runs first; default 100
    stamp: true                           # record provenance in raw (mask/route only)

    # ── the match condition — the Sigma subset, identical to a detection rule ──
    logsource: {vendor: microsoft, log_type: security}
    datamodels: [dns]                     # optional CIM binding (see "CIM" below)
    detection:
      selection:
        action: allow
        dst_port: 53
      condition: selection

    # ── the action ────────────────────────────────────────────────────────────
    action: drop | mask | route | sample

``logsource`` alone is enough: a rule with a non-empty ``logsource`` and no ``detection``
reduces to its logsource gate. A rule with NEITHER is rejected at load — an ingest action
that matches every event is a foot-gun, not a feature.


``action: drop``
----------------
The event is never appended to the write chunk, so it is never INSERTed, raises no
alerts, feeds no threat-intel match and contributes nothing to the UEBA baselines. Takes
no parameters. Terminal: no later rule runs.

This is NOT alert suppression. ``app.triage`` marks an *alert* ``suppressed`` and still
stores the event and the alert for audit; a drop erases the event itself. Two different
objects and two different audit stories — the drop's only trail is the counter in
:meth:`ActionIndex.stats` (and whatever the console writes to ``audit_log`` when the rule
is authored).


``action: mask``
----------------
Explicit about what it rewrites — a named field, or a regex *within* a field::

    action: mask
    mask:
      fields: [user_name, src_ip]         # whole normalized column
      raw_keys: [Account Name, [Event, System, Computer]]   # a jsonb key / nested path
      patterns:                           # regex within one field
        - {field: message, regex: '\\b\\d{3}-\\d{2}-\\d{4}\\b', replacement: '[SSN]'}
        - {raw: CommandLine, regex: '(?i)-password\\s+\\S+'}
      replacement: "***"                  # default placeholder
      mode: redact | hash                 # default redact
      salt: ""                            # optional, mode: hash only
      scrub: true                         # default true — see "Scrubbing"
                                          # (`scrub_raw:` is accepted as an alias)

``mode: hash`` pseudonymizes instead of erasing: ``sha256(salt + value)`` truncated, so
"the same user" is still joinable across events while the identifier itself is gone. The
salt is plain rule data, deliberately not a vault secret — state the trade honestly to
operators: **an unsalted hash of a small domain (usernames, hostnames, RFC1918 addresses)
is reversible by enumeration.** Set a salt when that matters.

*Type safety is not optional here.* ``db._INSERT`` binds ``%(src_ip)s::inet`` and the port
columns are integers, so a mask that writes ``"***"`` into ``src_ip`` would raise inside
``executemany`` and abort the whole batch — turning a redaction rule into total data loss.
So masks are typed:

* ``src_ip`` / ``dst_ip`` — ``redact`` → NULL (or ``replacement`` if it parses as an IP);
  ``hash`` → a deterministic address inside ``100.64.0.0/10`` (RFC 6598 shared address
  space), which is a valid ``inet``, is unambiguously not a real host, and keeps
  "same source" joinable. ~4.2M buckets, so collisions are real at scale — that is the
  price of keeping the column typed, and it is documented rather than hidden.
* ``src_port`` / ``dst_port`` / ``bytes_total`` — NULL (or ``replacement`` if it parses
  as an integer).
* everything else — the replacement string, or the hash.

``vendor``, ``event_time`` and ``raw`` are not maskable. ``vendor`` is the CIM handle and
the source-health key (``app.sourcehealth.source_key``); ``event_time`` decides the
partition. Re-attributing a source is what ``route`` is for.

Scrubbing — why masking one column is not redaction
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
``scrub`` (default **true**) is the difference between redaction and theatre. The value a
mask erases from ``user_name`` is still in at least two other places: ``raw``, stored
verbatim as jsonb (``db._row``: ``"raw": Jsonb(evt.raw)``) and GIN-indexed; and whatever
sibling column it was extracted alongside — typically ``message``, which
``normalize.tsv_text`` feeds to the full-text vector *separately from* ``raw``. Masking
only the named column would leave the secret searchable by ``| search jdoe`` and by
``raw @> ...``, which is worse than not masking at all because the operator believes it
is gone.

So with ``scrub`` on, every masked value is removed from the whole event — the ``raw``
record (recursively, values only, never keys) **and** the other text columns. A string
**equal** to the original is always replaced. A string merely *containing* it is
replaced as a plain substring when the original is at least 8 characters (a long value
is routinely embedded with no delimiter — inside a URL, a DN, a base64 blob), and as a
whole TOKEN when it is shorter. The token rule is what makes the common case work:
most masking targets are under 8 characters (``jdoe``, ``admin``, ``root``), and
skipping them outright left the value sitting in ``message`` and in nested ``raw``
strings — indexed and searchable — while the operator was told the mask had applied. It
is a token rather than a bare substring because substring-rewriting ``80`` inside
``8080``, or ``GET`` inside ``TARGET``, shreds unrelated fields. A ``patterns`` entry
that targets a normalized column is likewise re-run over every string in ``raw``.

Masking and ``dedup_hash`` — the decision, and why
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
``normalize.dedup_hash`` is ``sha256(vendor + event_time + json.dumps(raw))``, and
``db._row`` derives it at flush time — downstream of this seam either way. **Masking
happens BEFORE the hash: the stored identity is derived from the masked event.**

* The hash is what makes re-uploading a file idempotent. Deriving it from what is
  *stored* keeps that property exactly: the same bytes, ingested twice under the same
  rules, dedup as they always did.
* Hashing the PRE-mask event would make the row's identity a function of bytes we
  deliberately never persisted — i.e. the identity column becomes a side channel for the
  redacted value. Two rows identical after masking but differing in the secret would get
  different hashes, and anyone holding the hash plus a guess could confirm the secret. A
  redaction whose entire purpose is that the value never reaches the database must not
  leave a keyed function of it in an indexed column.
* The cost, stated plainly: **editing a mask rule changes the identity of everything
  ingested afterwards**, so the same source re-ingested under a changed rule re-inserts
  instead of dedupping. That is the honest trade — a rule change *is* a change to what is
  stored, and pretending otherwise would mean the store's identity ignored its content.

Masking is idempotent for identity: masking the same event twice yields the same hash.


``action: route``
-----------------
::

    action: route
    route: {vendor: acme, product: firewall, log_type: traffic, index: noisy}

**Route rewrites attribution; it does not change the destination batch.** Be clear about
this, because the name promises more than the seam can deliver: ``batch_id`` is fixed for
an entire ``pipeline.write_stream`` call — the batch is created before the stream opens
and one ``batch_id`` is bound for every row in the chunk — so a per-event destination is
not expressible here without restructuring ``flush()`` into per-destination chunks. What
route *does* is rewrite ``vendor`` / ``product`` / ``log_type`` (the three columns that
decide CIM membership, source health and most detection logsource gates) and stamp
``raw["_index"]``, which carries the operator's intended destination as data so LOQL and
CIM can filter on it today and a real per-destination flush can consume it later.

Rewriting ``vendor`` changes ``dedup_hash`` for the same reason a mask does, and
deterministically, so re-ingest still dedups.


``action: sample``
------------------
::

    action: sample
    sample:
      rate: 100                 # keep 1 in 100
      # percent: 5              # ...or keep 5% (mutually exclusive with rate)
      key: [src_ip]             # optional: bucket by these fields

Deterministic by construction — **never** ``random``. The bucket is a hash: with ``key``,
of those fields' values (so one entity is kept or dropped *whole*, which is what makes a
sampled dataset still usable for "show me everything this host did"); without ``key``, of
``normalize.dedup_hash``, i.e. the event's own identity, so the same event always samples
the same way and a re-ingest of the same file keeps exactly the same subset.

The identity hash is computed lazily, only inside the sample branch and only after the
rule's condition already matched, so a deployment with no sample rules pays nothing and
one with a sample rule pays a sha256 only on the source it samples. Give ``key`` to avoid
it entirely.

A rejected sample is terminal, like a drop.


Ordering and composition
------------------------
Rules run in ``order`` then ``(source, id)``. ``mask`` and ``route`` mutate the event and
**continue**, so several masks compose. ``drop`` and a rejected ``sample`` are terminal.
A later rule sees the *already-masked* event — matching on a value an earlier rule
redacted must not fire, or masking would be observable through the rules that follow it.


CIM binding
-----------
``datamodels:`` works because :func:`app.detection.engine.match_rule` implements the gate.
Note the cost and the ordering: this seam sits BEFORE ``cim_match.tags_for`` in the
pipeline (it must — a mask that blanks ``user_name`` has to change membership, not
disagree with it), so no resolved tags are available and a datamodel-bound ingest action
resolves membership itself, on the pre-mask event. A rule with no ``datamodels:`` never
touches the CIM layer at all. Callers that already hold tags may pass them to
:func:`decide`.


Failure policy: fail OPEN
-------------------------
This runs OUTSIDE ``write_stream``'s existing try/except, and ``streaming.IngestQueue``
discards an entire buffered group when a write raises — one bad rule would become
permanent, silent loss of every syslog event. So :meth:`ActionIndex.apply` never raises:
a rule that blows up is skipped, its id is recorded in ``Decision.errors``, the per-rule
error counter is bumped and one log line is emitted per rule id. The event is stored
un-transformed. Same precedent as ``db._cim_tags``: degrade the feature, never the write.


Wiring (owned by the WIRE phase — see the handoff)
--------------------------------------------------
``app/pipeline.py``, in ``write_stream``'s ``for evt in events:`` loop, between
``apply_fallback_time(evt, fb)`` and ``chunk.append(evt)``::

    for evt in events:
        total += 1
        apply_fallback_time(evt, fb)
        custom_parser.apply(evt)          # HOISTED from below the transform
        verdict = ingest_actions.apply(evt)
        if verdict.dropped:
            dropped += 1
            continue                      # never appended, never inserted
        chunk.append(evt)
        ...

``custom_parser.apply`` MUST be hoisted above the call: it fills any normalized column
that is None or "" from ``raw``, so a mask that nulls ``src_ip`` is otherwise silently
refilled. (Text masks default to a non-empty placeholder and survive either way; inet and
integer masks null the column and do not.)

``dropped`` must be subtracted from the duplicate arithmetic in both ``ingest.ingest``
and ``streaming._write_group`` — ``duplicates = max(result.total - inserted, 0)`` counts
every dropped event as a duplicate otherwise.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

import yaml

from .detection import engine
from .normalize import dedup_hash
from .util import to_int

log = logging.getLogger("logocean")

ACTIONS = ("drop", "mask", "route", "sample")

# Columns a mask may rewrite, grouped by the type the INSERT binds them as. `vendor`,
# `event_time` and `raw` are absent on purpose (see the module docstring).
_TEXT_FIELDS = ("product", "log_type", "severity", "action", "protocol", "app",
                "user_name", "host_name", "rule_name", "message")
_INET_FIELDS = ("src_ip", "dst_ip")
_INT_FIELDS = ("src_port", "dst_port", "bytes_total")
MASKABLE_FIELDS = frozenset(_TEXT_FIELDS + _INET_FIELDS + _INT_FIELDS)

# Columns `route` may rewrite: the three that decide CIM membership, source health and
# most detection logsource gates.
ROUTABLE_FIELDS = ("vendor", "product", "log_type")

_DEFAULT_REPLACEMENT = "***"
_DEFAULT_ORDER = 100

# `scrub` substring rewriting is only applied to originals at least this long. An
# exact-value match is always replaced whatever its length; substring rewriting a short,
# common value ("high", "GET", "80") across a whole record destroys unrelated fields.
_MIN_SUBSTRING_LEN = 8
_MAX_SCRUB_DEPTH = 16          # same bound `engine._flatten_raw` uses on `raw`

# Pseudonymised addresses land in RFC 6598 shared address space: a valid `inet`, routable
# nowhere, and never a customer's real subnet the way 10/8 or 192.168/16 would be.
_PSEUDO_NET_BASE = int(ipaddress.IPv4Address("100.64.0.0"))
_PSEUDO_NET_BITS = 22          # 100.64.0.0/10 -> 4,194,304 buckets

_MAX_PATTERN_CHARS = 512
# A cheap catastrophic-backtracking heuristic, not a proof: a quantified group whose body
# is itself quantified — `(a+)+`, `(a*)*`, `(\d+\s*)*`. Operator-authored regexes carry the
# same trust as a detection rule's `|re`, but a rule that runs on EVERY event deserves the
# textbook shape rejected at load rather than discovered in production.
_CATASTROPHIC_RE = re.compile(r"\([^()]*[+*][^()]*\)\s*[+*]")

# `logsource:`-only sugar. `vendor` is non-Optional on NormalizedEvent and every parser
# fills it, so `vendor|exists: true` is a tautology that reduces the rule to its logsource
# gate — expressed in the engine's own public grammar rather than by reaching into its
# private `_logsource_matches`. If a caller ever hands us an event with no vendor the rule
# simply does not fire, which is the fail-safe direction (no drop, no mask).
_LOGSOURCE_ONLY_DETECTION = {"_logsource": {"vendor|exists": True},
                             "condition": "_logsource"}


class ActionError(ValueError):
    """A malformed ingest-action document. Raised at LOAD time, never at ingest."""


# --------------------------------------------------------------------------- #
#  Specs                                                                       #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class PatternSpec:
    """One regex-within-a-field redaction. `regex` is compiled at load."""
    regex: Any                              # re.Pattern
    replacement: str = _DEFAULT_REPLACEMENT
    field_name: str = ""                    # a normalized column, or ""
    raw_path: tuple[str, ...] = ()          # a jsonb path, or ()


@dataclass(frozen=True)
class MaskSpec:
    fields: tuple[str, ...] = ()
    raw_keys: tuple[tuple[str, ...], ...] = ()
    patterns: tuple[PatternSpec, ...] = ()
    replacement: str = _DEFAULT_REPLACEMENT
    mode: str = "redact"                    # redact | hash
    salt: str = ""
    scrub: bool = True
    # `replacement` re-read as the column's own type, resolved once at load so the
    # per-event path never parses. None means "NULL this column".
    inet_replacement: Optional[str] = None
    int_replacement: Optional[int] = None


@dataclass(frozen=True)
class RouteSpec:
    vendor: Optional[str] = None
    product: Optional[str] = None
    log_type: Optional[str] = None
    index: Optional[str] = None             # stamped into raw["_index"]


@dataclass(frozen=True)
class SampleSpec:
    """Keep the event when ``bucket % modulus < numerator``.

    ``rate: N`` is ``(modulus=N, numerator=1)``; ``percent: p`` is
    ``(modulus=10000, numerator=round(p*100))`` — basis points, so 0.05% is expressible.
    """
    modulus: int
    numerator: int
    key: tuple[str, ...] = ()


@dataclass
class IngestAction:
    """One loaded rule: a match condition (an ``engine.Rule``) plus what to do."""
    id: str
    action: str
    rule: Any                               # engine.Rule
    title: str = ""
    description: str = ""
    order: int = _DEFAULT_ORDER
    enabled: bool = True
    source: str = ""
    stamp: bool = True
    mask: Optional[MaskSpec] = None
    route: Optional[RouteSpec] = None
    sample: Optional[SampleSpec] = None


@dataclass(frozen=True)
class Decision:
    """What the rule set did to one event.

    ``applied`` lists every rule that MATCHED, in evaluation order, including the
    terminal one. ``errors`` lists rules that raised and were skipped (fail-open).
    """
    dropped: bool = False
    rule_id: str = ""                       # the terminal rule ("" when kept)
    action: str = ""                        # "drop" | "sample" | "" when kept
    applied: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()


KEEP = Decision()


def sort_key(a: IngestAction) -> tuple:
    """Evaluation order: explicit ``order``, then file, then id — total and stable."""
    return (a.order, a.source, a.id)


# --------------------------------------------------------------------------- #
#  Pure helpers: hashing, raw paths, scrubbing                                 #
# --------------------------------------------------------------------------- #
def hash_value(value: Any, salt: str = "", length: int = 16) -> str:
    """``sha256(salt + value)`` truncated — deterministic pseudonymisation.

    Truncation is to keep a masked column readable; it does not weaken the property that
    matters here (same input -> same output), and the docstring is honest that an
    unsalted hash over a small domain is enumerable.
    """
    h = hashlib.sha256()
    if salt:
        h.update(salt.encode("utf-8", "replace"))
    h.update(str(value).encode("utf-8", "replace"))
    return h.hexdigest()[:length]


def pseudo_ip(value: Any, salt: str = "") -> str:
    """A deterministic address in ``100.64.0.0/10`` for ``value``.

    Keeps ``src_ip`` / ``dst_ip`` a valid ``inet`` — the INSERT casts them, so a text
    placeholder would abort the batch — while keeping "same host" joinable.
    """
    n = int(hash_value(value, salt, 16), 16) % (1 << _PSEUDO_NET_BITS)
    return str(ipaddress.IPv4Address(_PSEUDO_NET_BASE + n))


def raw_path(value: Any) -> tuple[str, ...]:
    """``"k"`` -> ``("k",)``; ``["a", "b"]`` -> ``("a", "b")``.

    The ``models.yaml`` segment convention, so an operator who can write a CIM field
    source can write a mask target. Keys are byte-exact, never lower-cased — the same
    rule ``app.cim.match`` follows, and for the same reason (Zeek's literal ``id.orig_h``).
    """
    if isinstance(value, (list, tuple)):
        return tuple(str(s) for s in value if str(s) != "")
    return (str(value),)


def raw_get(raw: Any, path: Sequence[str]) -> Any:
    """Walk ``raw`` one Mapping level per segment. Objects only, never array indices."""
    cur = raw
    for seg in path:
        if not isinstance(cur, Mapping) or seg not in cur:
            return None
        cur = cur[seg]
    return cur


def raw_set(raw: Any, path: Sequence[str], value: Any) -> bool:
    """Set ``raw[path] = value`` **only where the key already exists**.

    Masking never invents structure: a rule naming a key this source does not emit is a
    no-op, not a new column of placeholders in every row. The existence check is this
    helper's own contract, not an optimisation for its current callers — :func:`apply_mask`
    happens to pre-check with :func:`raw_get`, which makes the guard unreachable from
    there today and would make it silently droppable tomorrow.
    """
    if not path:
        return False
    cur = raw
    for seg in path[:-1]:
        if not isinstance(cur, Mapping) or seg not in cur:
            return False
        cur = cur[seg]
    if not isinstance(cur, dict) or path[-1] not in cur:
        return False
    cur[path[-1]] = value
    return True


def walk_strings(obj: Any, fn, depth: int = 0) -> bool:
    """Rewrite every string VALUE in a nested dict/list through ``fn``, in place.

    Keys are left alone: a jsonb key is the record's shape, not its content, and
    rewriting one would break every CIM term and detection field that names it.
    """
    changed = False
    if depth > _MAX_SCRUB_DEPTH:
        return False
    if isinstance(obj, dict):
        items: Iterable = list(obj.items())
    elif isinstance(obj, list):
        items = list(enumerate(obj))
    else:
        return False
    for k, v in items:
        if isinstance(v, str):
            nv = fn(v)
            if nv != v:
                obj[k] = nv
                changed = True
        elif isinstance(v, (dict, list)):
            changed = walk_strings(v, fn, depth + 1) or changed
    return changed


_WORD_CHARS = "0-9A-Za-z_"


def _token_pattern(value: str) -> "re.Pattern[str]":
    """`value` as a whole token — not as a fragment of a longer word.

    The lookarounds are applied only on the ends that are themselves word characters,
    so a value that already begins or ends with punctuation (``CORP\\``, ``svc-``)
    still matches where it really appears.
    """
    left = f"(?<![{_WORD_CHARS}])" if (value[:1].isalnum() or value[:1] == "_") else ""
    right = f"(?![{_WORD_CHARS}])" if (value[-1:].isalnum() or value[-1:] == "_") else ""
    return re.compile(left + re.escape(value) + right)


def literal_scrubber(pairs: Sequence[tuple[str, str]]):
    """A ``fn(s) -> s`` that removes each ``(original, replacement)`` from a string.

    Exact equality always replaces. Beyond that there are two regimes, and the short
    one is the whole point:

    * ``len(original) >= _MIN_SUBSTRING_LEN`` -> plain substring replacement. A long
      value (an email address, a key fragment) is routinely embedded with no delimiter
      around it — inside a URL, a DN, a base64 blob — so boundaries would miss it.
    * shorter -> replaced only where it stands as a WHOLE TOKEN.

    Short values used to be skipped entirely, which quietly defeated the feature for
    the common case. Most masking targets are under 8 characters — ``jdoe``, ``admin``,
    ``root``, ``svc_bk`` — so the shipped GDPR proxy-mask rule hashed ``user_name`` to
    a pseudonym while leaving ``message='GET /hr/salaries.xlsx by jdoe from 10.1.2.3'``,
    ``raw.cs_username='CORP\\jdoe'`` and ``raw.detail.cmd='runas /user:jdoe whoami'``
    untouched — all three indexed, by ``search_tsv`` and by the raw GIN index, so
    ``| search jdoe`` recovered the identity in full and the pseudonym column made it
    trivially re-joinable. The behaviour flipped on identifier LENGTH alone: the same
    rule scrubbed ``jdoe.smith`` correctly. By this module's own standard — "worse than
    not masking at all because the operator believes it is gone" — that was the failure
    it set out to prevent.

    Token boundaries, rather than dropping the threshold, because the hazard the
    threshold guarded against is real and specific: substring-rewriting ``80`` inside
    ``8080``, or ``GET`` inside ``TARGET``, shreds unrelated fields. Requiring a word
    boundary removes exactly that case and keeps every real occurrence.
    """
    compiled: list[tuple[str, str, Optional["re.Pattern[str]"]]] = [
        (original, replacement,
         None if len(original) >= _MIN_SUBSTRING_LEN else _token_pattern(original))
        for original, replacement in pairs if original
    ]

    def fn(s: str) -> str:
        for original, replacement, token in compiled:
            if s == original:
                s = replacement
            elif token is None:
                if original in s:
                    s = s.replace(original, replacement)
            else:
                # a lambda, not the string: a replacement containing `\1` or `\g`
                # would otherwise be read as a backreference
                s = token.sub(lambda _m, r=replacement: r, s)
        return s
    return fn


# --------------------------------------------------------------------------- #
#  Loading + validation                                                        #
# --------------------------------------------------------------------------- #
def _compile_pattern(spec: Any, default_replacement: str) -> PatternSpec:
    if not isinstance(spec, Mapping):
        raise ActionError("mask.patterns entries must be mappings")
    expr = spec.get("regex") or spec.get("re")
    if not expr:
        raise ActionError("mask.patterns entry needs a `regex`")
    expr = str(expr)
    if len(expr) > _MAX_PATTERN_CHARS:
        raise ActionError(f"mask pattern is longer than {_MAX_PATTERN_CHARS} characters")
    if _CATASTROPHIC_RE.search(expr):
        raise ActionError(
            f"mask pattern {expr!r} nests a quantifier inside a quantified group, which "
            "backtracks catastrophically on adversarial input; rewrite it without `(x+)+`")
    try:
        rx = re.compile(expr)
    except re.error as exc:
        raise ActionError(f"mask pattern {expr!r} is not a valid regex: {exc}") from exc
    field_name = str(spec.get("field") or "")
    path = raw_path(spec["raw"]) if spec.get("raw") is not None else ()
    if not field_name and not path:
        raise ActionError("mask.patterns entry needs a `field` or a `raw` target")
    if field_name and field_name not in MASKABLE_FIELDS:
        raise ActionError(f"mask pattern field {field_name!r} is not maskable "
                          f"(allowed: {', '.join(sorted(MASKABLE_FIELDS))})")
    # A pattern substitution produces a STRING, and `apply_mask` assigns it with a bare
    # setattr — so a regex target must be a text column. `mask.fields` is typed for
    # exactly this reason (`_mask_column` gives src_ip a `pseudo_ip()` or a pre-parsed
    # `inet_replacement`); the pattern branch had no equivalent guard, and the gap was
    # reachable through the single most obvious IP-anonymisation idiom there is:
    #
    #     patterns: [{field: src_ip, regex: '\d+$', replacement: 'xxx'}]   # last octet
    #
    # That loaded clean, `validate()` approved it, and every matching event then bound
    # '10.1.2.xxx' to `%(src_ip)s::inet`. Postgres rejects it, the exception escapes
    # `write_stream`, and on the live queue path `IngestQueue._flush` discards the whole
    # buffered group — a redaction rule that deletes the data it was added to protect.
    if field_name in _INET_FIELDS or field_name in _INT_FIELDS:
        raise ActionError(
            f"mask pattern field {field_name!r} is typed ({'inet' if field_name in _INET_FIELDS else 'numeric'}), "
            "and a regex substitution yields text that the column cannot hold — the "
            "INSERT would abort and take the whole batch with it. Use `mask.fields: "
            f"[{field_name}]`, which rewrites it as the right type (hash mode gives "
            "stable RFC 6598 pseudonyms for addresses).")
    return PatternSpec(regex=rx, field_name=field_name, raw_path=path,
                       replacement=str(spec.get("replacement", default_replacement)))


def _mask_from(doc: Mapping) -> MaskSpec:
    m = doc.get("mask") or {}
    if not isinstance(m, Mapping):
        raise ActionError("`mask:` must be a mapping")
    replacement = str(m.get("replacement", _DEFAULT_REPLACEMENT))
    mode = str(m.get("mode") or "redact").strip().lower()
    if mode not in ("redact", "hash"):
        raise ActionError(f"unknown mask mode {mode!r} (expected redact | hash)")

    raw_fields = m.get("fields") or []
    if isinstance(raw_fields, str):
        raw_fields = [raw_fields]
    fields = tuple(str(f) for f in raw_fields)
    bad = [f for f in fields if f not in MASKABLE_FIELDS]
    if bad:
        raise ActionError(
            f"mask.fields {', '.join(bad)} not maskable — `vendor` is the CIM and "
            "source-health handle (use `route`), `event_time` decides the partition, and "
            "`raw` is masked through mask.raw_keys / mask.patterns / scrub")

    keys = m.get("raw_keys") or []
    if isinstance(keys, str):
        keys = [keys]
    raw_keys = tuple(raw_path(k) for k in keys)

    pats = m.get("patterns") or []
    if isinstance(pats, Mapping):
        pats = [pats]
    patterns = tuple(_compile_pattern(p, replacement) for p in pats)

    if not fields and not raw_keys and not patterns:
        raise ActionError("`mask:` names nothing to rewrite — give fields, raw_keys "
                          "or patterns")
    # `scrub_raw:` is accepted as an alias because it names the hazard operators think of
    # first; `scrub:` is canonical because the sweep covers the sibling columns too.
    scrub = bool(m.get("scrub", m.get("scrub_raw", True)))

    # `replacement` re-read as the column's own type. A text placeholder in `src_ip`
    # would abort the INSERT at `%(src_ip)s::inet`, so an unparseable replacement means
    # NULL rather than a batch failure.
    try:
        inet_replacement: Optional[str] = str(ipaddress.ip_address(replacement.strip()))
    except ValueError:
        inet_replacement = None
    # `to_int`, not bare `int()`: the parsed value goes straight into `bytes_total`,
    # whose `bigint` column cannot hold an arbitrary-precision Python int. An
    # out-of-range replacement fails the same way an unparseable one would, so it takes
    # the same path — None (leave the column alone) rather than a doomed INSERT.
    # `src_port`/`dst_port` survive this only incidentally, via `to_port` in `db._row`.
    int_replacement: Optional[int] = to_int(replacement)

    return MaskSpec(fields=fields, raw_keys=raw_keys, patterns=patterns,
                    replacement=replacement, mode=mode, salt=str(m.get("salt") or ""),
                    scrub=scrub,
                    inet_replacement=inet_replacement, int_replacement=int_replacement)


def _route_from(doc: Mapping) -> RouteSpec:
    r = doc.get("route") or {}
    if not isinstance(r, Mapping):
        raise ActionError("`route:` must be a mapping")
    unknown = set(r) - set(ROUTABLE_FIELDS) - {"index"}
    if unknown:
        raise ActionError(
            f"route cannot rewrite {', '.join(sorted(unknown))} — route sets "
            f"{', '.join(ROUTABLE_FIELDS)} and `index` (stamped into raw['_index']); "
            "per-event destinations are not expressible at this seam (batch_id is fixed "
            "for the whole write_stream call)")
    spec = RouteSpec(**{k: (None if r.get(k) is None else str(r[k]))
                        for k in (*ROUTABLE_FIELDS, "index") if k in r})
    if not any(getattr(spec, k) for k in (*ROUTABLE_FIELDS, "index")):
        raise ActionError("`route:` sets nothing")
    return spec


def _sample_from(doc: Mapping) -> SampleSpec:
    s = doc.get("sample") or {}
    if not isinstance(s, Mapping):
        raise ActionError("`sample:` must be a mapping")
    has_rate, has_pct = s.get("rate") is not None, s.get("percent") is not None
    if has_rate and has_pct:
        raise ActionError("`sample:` takes `rate` or `percent`, not both")
    keys = s.get("key") or []
    if isinstance(keys, str):
        keys = [keys]
    key = tuple(str(k) for k in keys)
    bad = [k for k in key if k not in MASKABLE_FIELDS and k != "vendor"]
    if bad:
        raise ActionError(f"sample.key {', '.join(bad)} is not a normalized column")
    if has_rate:
        try:
            rate = int(s["rate"])
        except (TypeError, ValueError) as exc:
            raise ActionError("sample.rate must be an integer") from exc
        if rate < 1:
            raise ActionError("sample.rate must be >= 1 (1 keeps everything; use "
                              "`action: drop` to keep nothing)")
        return SampleSpec(modulus=rate, numerator=1, key=key)
    if has_pct:
        try:
            pct = float(s["percent"])
        except (TypeError, ValueError) as exc:
            raise ActionError("sample.percent must be a number") from exc
        if not 0 < pct <= 100:
            raise ActionError("sample.percent must be > 0 and <= 100")
        return SampleSpec(modulus=10_000, numerator=round(pct * 100), key=key)
    raise ActionError("`sample:` needs a `rate` or a `percent`")


def action_from_dict(doc: Mapping, source: str = "") -> IngestAction:
    """Build one :class:`IngestAction` from a parsed YAML document.

    Raises :class:`ActionError` with an operator-readable message. Every validation lives
    here so the console pre-check (:func:`validate`), the file loader and the tests all
    exercise one code path.
    """
    if not isinstance(doc, Mapping):
        raise ActionError("an ingest action must be a mapping")
    act = str(doc.get("action") or "").strip().lower()
    if act not in ACTIONS:
        raise ActionError(f"unknown action {act!r} (expected {' | '.join(ACTIONS)})")

    logsource = doc.get("logsource") or {}
    if not isinstance(logsource, Mapping):
        raise ActionError("`logsource:` must be a mapping")
    detection = doc.get("detection") or {}
    if not isinstance(detection, Mapping):
        raise ActionError("`detection:` must be a mapping")
    if not detection and not logsource:
        raise ActionError(
            "an ingest action needs a `logsource:` or a `detection:` — a rule with "
            "neither matches every event, which for `drop` is total data loss")
    if not detection:
        detection = _LOGSOURCE_ONLY_DETECTION

    rid = str(doc.get("id") or doc.get("title") or source or "unnamed")
    try:
        order = int(doc.get("order", _DEFAULT_ORDER))
    except (TypeError, ValueError) as exc:
        raise ActionError("`order:` must be an integer") from exc

    rule = engine.Rule(
        id=rid, title=str(doc.get("title") or rid), level="informational",
        description=str(doc.get("description") or ""),
        logsource=dict(logsource), detection=dict(detection),
        datamodels=engine.as_str_list(doc.get("datamodels") or doc.get("datamodel")),
        source=source)

    return IngestAction(
        id=rid, action=act, rule=rule,
        title=str(doc.get("title") or rid),
        description=str(doc.get("description") or ""),
        order=order, enabled=bool(doc.get("enabled", True)), source=source,
        stamp=bool(doc.get("stamp", True)),
        mask=_mask_from(doc) if act == "mask" else None,
        route=_route_from(doc) if act == "route" else None,
        sample=_sample_from(doc) if act == "sample" else None)


def validate(doc: Any) -> list[str]:
    """``[]`` when ``doc`` is a usable ingest action, else the problem(s).

    For the console's save-time pre-check: an invalid rule must be refused at authoring
    time, when a human is looking at the message, rather than logged at ingest time.
    """
    try:
        action_from_dict(doc if isinstance(doc, Mapping) else {}, "console")
    except ActionError as exc:
        return [str(exc)]
    return []


def load_actions(path) -> tuple[list[IngestAction], list[str]]:
    """Load ``*.yml`` / ``*.yaml`` from a file or a directory.

    Returns ``(actions, errors)``. A malformed document is skipped with a message rather
    than aborting the load: one bad rule must cost that rule, not every rule.
    """
    base = Path(path)
    if base.is_dir():
        files = sorted(list(base.glob("*.yml")) + list(base.glob("*.yaml")))
    elif base.is_file():
        files = [base]
    else:
        # A CONFIGURED-BUT-ABSENT PATH IS AN ERROR, NOT AN EMPTY LOAD. This returned
        # ([], []) — byte-identical to a correctly configured empty directory — and
        # `settings.ingest_actions_dir` defaults to the RELATIVE "ingest_actions",
        # resolved against the process CWD. So a systemd unit with a different
        # WorkingDirectory, or a container with a different workdir, loaded nothing
        # while /health reported `{rules: 0, load_errors: []}` and status ok.
        #
        # That defeats the product's own control: README tells operators to check
        # /health after every edit because "a dropped event leaves no row behind", and
        # main.py promotes load_errors to `degraded` for the same reason — but the two
        # ways a rule can vanish entirely both produced an EMPTY load_errors. An
        # unredacted PII feed and a working one looked the same.
        return [], [f"{base}: ingest actions path does not exist "
                    f"(resolved to {base.resolve()}) — no rules are loaded"]
    out: list[IngestAction] = []
    errors: list[str] = []
    for f in files:
        try:
            docs = list(yaml.safe_load_all(f.read_text(encoding="utf-8")))
        except Exception as exc:  # noqa: BLE001 — unreadable / unparseable file
            errors.append(f"{f.name}: {exc}")
            continue
        for doc in docs:
            if doc is None:
                continue                       # an empty document between `---` markers
            if not isinstance(doc, Mapping):
                errors.append(f"{f.name}: a document is {type(doc).__name__}, "
                              "not a mapping — a rule must be a YAML mapping")
                continue
            if "action" not in doc:
                # Reported, not skipped. `actions:` instead of `action:` — or any other
                # typo in that ONE key — used to vanish silently while every other
                # malformed field raised an ActionError that reached load_errors.
                errors.append(
                    f"{f.name}: a document has no `action:` key "
                    f"(found {', '.join(sorted(str(k) for k in doc)) or 'nothing'}) — "
                    "it defines no rule and was skipped")
                continue
            try:
                out.append(action_from_dict(doc, f.name))
            except ActionError as exc:
                errors.append(f"{f.name}: {exc}")
    out.sort(key=sort_key)
    return out, errors


# --------------------------------------------------------------------------- #
#  The transforms (pure: they mutate the event they are handed, nothing else)  #
# --------------------------------------------------------------------------- #
def _mask_column(evt: Any, name: str, spec: MaskSpec) -> Optional[tuple[str, str]]:
    """Rewrite one normalized column. Returns ``(original, replacement_text)`` when it
    changed, so the caller can scrub the same value out of ``raw``."""
    cur = getattr(evt, name, None)
    if cur is None or cur == "":
        return None
    if name in _INT_FIELDS:
        new: Any = spec.int_replacement
    elif name in _INET_FIELDS:
        new = pseudo_ip(cur, spec.salt) if spec.mode == "hash" else spec.inet_replacement
    else:
        new = hash_value(cur, spec.salt) if spec.mode == "hash" else spec.replacement
    setattr(evt, name, new)
    # A NULLed column cannot carry a placeholder into `raw`, so the text replacement
    # stands in for it there.
    return (str(cur), str(new) if new is not None else spec.replacement)


def apply_mask(evt: Any, spec: MaskSpec) -> bool:
    """Apply one mask to ``evt`` in place. Returns True when anything changed."""
    changed = False
    pairs: list[tuple[str, str]] = []
    for name in spec.fields:
        got = _mask_column(evt, name, spec)
        if got is not None:
            pairs.append(got)
            changed = True

    raw = getattr(evt, "raw", None)
    if isinstance(raw, dict):
        for path in spec.raw_keys:
            cur = raw_get(raw, path)
            if cur is None or cur == "":
                continue
            new = hash_value(cur, spec.salt) if spec.mode == "hash" else spec.replacement
            if raw_set(raw, path, new):
                changed = True

    for pat in spec.patterns:
        if pat.field_name:
            cur = getattr(evt, pat.field_name, None)
            if isinstance(cur, str) and cur:
                new_text = pat.regex.sub(pat.replacement, cur)
                if new_text != cur:
                    setattr(evt, pat.field_name, new_text)
                    changed = True
        if pat.raw_path and isinstance(raw, dict):
            cur = raw_get(raw, pat.raw_path)
            if isinstance(cur, str) and cur:
                new_text = pat.regex.sub(pat.replacement, cur)
                if new_text != cur and raw_set(raw, pat.raw_path, new_text):
                    changed = True

    if spec.scrub:
        # Masking only the named column is theatre: the value is still in `raw` (stored
        # verbatim, GIN-indexed) and in whatever sibling column it was extracted
        # alongside — usually `message`, which `normalize.tsv_text` feeds to the full-text
        # vector separately from `raw`. So the sweep covers both. A pattern that targeted
        # a column is re-run over `raw` because the same substring is almost always in
        # the record the column was extracted from.
        if pairs:
            scrub = literal_scrubber(pairs)
            changed = _scrub_columns(evt, scrub) or changed
            if isinstance(raw, dict):
                changed = walk_strings(raw, scrub) or changed
        if isinstance(raw, dict):
            for pat in spec.patterns:
                if pat.field_name:
                    changed = walk_strings(
                        raw, lambda s, p=pat: p.regex.sub(p.replacement, s)) or changed
    return changed


def _scrub_columns(evt: Any, fn) -> bool:
    """Run ``fn`` over every TEXT column. The inet and integer columns are skipped —
    they are typed, and a placeholder in either aborts the INSERT."""
    changed = False
    for name in _TEXT_FIELDS:
        cur = getattr(evt, name, None)
        if isinstance(cur, str) and cur:
            new = fn(cur)
            if new != cur:
                setattr(evt, name, new)
                changed = True
    return changed


def apply_route(evt: Any, spec: RouteSpec) -> bool:
    """Rewrite attribution in place. Returns True when anything changed."""
    changed = False
    for name in ROUTABLE_FIELDS:
        want = getattr(spec, name)
        if want is not None and getattr(evt, name, None) != want:
            setattr(evt, name, want)
            changed = True
    if spec.index is not None:
        raw = getattr(evt, "raw", None)
        if isinstance(raw, dict) and raw.get("_index") != spec.index:
            raw["_index"] = spec.index
            changed = True
    return changed


def sample_bucket(evt: Any, key: Sequence[str]) -> int:
    """The deterministic bucket ``evt`` falls in — never random, never clock-derived.

    With ``key``, the hash is of those columns' values, so every event for one entity
    shares a bucket and is kept or dropped whole. Without one it is the event's own
    identity (``normalize.dedup_hash``), so re-ingesting a file keeps the same subset.
    """
    if key:
        text = "\x1f".join(str(getattr(evt, k, "") or "") for k in key)
        return int(hash_value(text, "", 16), 16)
    return int(dedup_hash(evt)[:16], 16)


def sample_keeps(evt: Any, spec: SampleSpec) -> bool:
    return sample_bucket(evt, spec.key) % spec.modulus < spec.numerator


# --------------------------------------------------------------------------- #
#  The evaluator — pure                                                        #
# --------------------------------------------------------------------------- #
def decide(actions: Sequence[IngestAction], evt: Any,
           tags: Optional[Iterable[str]] = None) -> Decision:
    """Run ``actions`` against ``evt`` and return what happened. **Pure.**

    Mutates only ``evt`` (that is what a mask *is*); touches no database, no singleton,
    no clock and no randomness, so the same rules and the same event always produce the
    same decision and the same stored row.

    ``tags`` is the event's already-resolved CIM membership, for a caller that holds one.
    The pipeline does not: this seam runs before ``cim_match.tags_for`` precisely so a
    mask changes membership rather than disagreeing with it, so a datamodel-bound rule
    resolves membership itself through ``engine.match_rule``.
    """
    applied: list[str] = []
    errors: list[str] = []
    flat: Optional[dict] = None             # rebuilt after any mutation, see below
    for a in actions:
        if not a.enabled:
            continue
        try:
            if flat is None:
                flat = engine.flatten_event(evt)
            if not engine.match_rule(a.rule, flat, evt, tags):
                continue
            applied.append(a.id)
            if a.action == "drop":
                return Decision(True, a.id, "drop", tuple(applied), tuple(errors))
            if a.action == "sample":
                if not sample_keeps(evt, a.sample):
                    return Decision(True, a.id, "sample", tuple(applied), tuple(errors))
                continue                    # kept: a sample that keeps changes nothing
            changed = (apply_mask(evt, a.mask) if a.action == "mask"
                       else apply_route(evt, a.route))
            if changed:
                if a.stamp:
                    _stamp(evt, a.id)
                # A later rule must see the MASKED event: matching on a value an earlier
                # rule redacted would make the redaction observable through the rules
                # that follow it, and would let a drop fire on a secret that is no longer
                # stored. `flat` is a snapshot, so it is discarded and rebuilt on demand.
                flat = None
        except Exception:  # noqa: BLE001 — fail OPEN, see the module docstring
            errors.append(a.id)
            log.warning("ingest action %s failed to evaluate; event kept untransformed",
                        a.id, exc_info=True)
            flat = None                     # the event may be half-transformed
    return Decision(False, "", "", tuple(applied), tuple(errors))


def _stamp(evt: Any, rule_id: str) -> None:
    """Record in ``raw['_ingest_actions']`` which rules rewrote this event.

    A dropped event leaves no row, so its only trail is the counter; a masked or rerouted
    one is stored, and the row itself should say it was rewritten — otherwise a
    downstream analyst cannot tell a redacted field from a source that never sent it.
    Mirrors the existing ``raw['_parse_note']`` convention. It changes ``dedup_hash``
    deterministically, so re-ingest still dedups.
    """
    raw = getattr(evt, "raw", None)
    if not isinstance(raw, dict):
        return
    marks = raw.get("_ingest_actions")
    if not isinstance(marks, list):
        marks = []
        raw["_ingest_actions"] = marks
    if rule_id not in marks:
        marks.append(rule_id)


# --------------------------------------------------------------------------- #
#  Runtime: the loaded index + counters (the audit trail for what was dropped) #
# --------------------------------------------------------------------------- #
_COUNTERS = ("matched", "dropped", "changed", "errors")


class ActionIndex:
    """The loaded rules plus per-rule counters. :meth:`apply` never raises."""

    def __init__(self, actions: Optional[Sequence[IngestAction]] = None,
                 errors: Optional[Sequence[str]] = None):
        self.actions: list[IngestAction] = sorted(list(actions or []), key=sort_key)
        self.load_errors: list[str] = list(errors or [])
        # rule id -> {matched, dropped, changed, errors}. Plain dict increments: a lost
        # count under concurrent writers is acceptable for a statistic; a lock on a
        # per-event path is not.
        self.counts: dict[str, dict[str, int]] = {}

    def __len__(self) -> int:
        return len(self.actions)

    def _bump(self, rule_id: str, name: str) -> None:
        row = self.counts.get(rule_id)
        if row is None:
            row = self.counts[rule_id] = {c: 0 for c in _COUNTERS}
        row[name] = row.get(name, 0) + 1

    def apply(self, evt: Any, tags: Optional[Iterable[str]] = None) -> Decision:
        """:func:`decide`, plus counters, and guaranteed not to raise.

        ``streaming.IngestQueue._flush`` discards an entire buffered group when a write
        raises, so an exception escaping here is silent permanent loss of every syslog
        event in that flush. Degrade the feature, never the write.
        """
        if not self.actions:
            return KEEP
        try:
            d = decide(self.actions, evt, tags)
        except Exception:  # noqa: BLE001 — the last line of defence
            log.warning("ingest actions failed; event kept untransformed", exc_info=True)
            return KEEP
        for rid in d.applied:
            self._bump(rid, "matched")
        for rid in d.errors:
            self._bump(rid, "errors")
        if d.dropped:
            self._bump(d.rule_id, "dropped")
        elif d.applied:
            self._bump(d.applied[-1], "changed")
        return d

    def summary(self) -> dict:
        """Shape for ``/health`` and the console: totals plus the per-rule breakdown."""
        return {
            "rules": len(self.actions),
            "enabled": sum(1 for a in self.actions if a.enabled),
            "load_errors": list(self.load_errors),
            "dropped": sum(r.get("dropped", 0) for r in self.counts.values()),
            "changed": sum(r.get("changed", 0) for r in self.counts.values()),
            "errors": sum(r.get("errors", 0) for r in self.counts.values()),
            "by_rule": {k: dict(v) for k, v in self.counts.items()},
        }


_index = ActionIndex()


def get_index() -> ActionIndex:
    return _index


def set_index(index: ActionIndex) -> None:
    """Install a rule set. The seam a future ``ingest_actions`` DB table plugs into."""
    global _index
    _index = index


def reload_index(path) -> ActionIndex:
    """Rebuild the index from ``path`` (a file or a directory of YAML).

    Called from the app lifespan next to ``custom_parser.reload()`` and
    ``triage_runtime.reload_index()``, and again after a console edit.
    """
    actions, errors = load_actions(path)
    index = ActionIndex(actions, errors)
    set_index(index)
    log.info("ingest actions loaded: %d rule(s), %d error(s)", len(index), len(errors))
    for msg in errors:
        log.warning("ingest action rejected: %s", msg)
    return index


def apply(evt: Any, tags: Optional[Iterable[str]] = None) -> Decision:
    """The pipeline hook. Never raises; returns :data:`KEEP` when nothing applies."""
    return _index.apply(evt, tags)


def stats() -> dict:
    return _index.summary()
