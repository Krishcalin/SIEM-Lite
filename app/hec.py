# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Splunk HTTP Event Collector (HEC) wire-compatible ingest shim.

A migration wedge: a customer evaluating a Splunk replacement already has HEC
senders deployed (universal forwarders in HTTP mode, the Splunk logging libraries,
Fluent Bit's `splunk` output, Vector's `splunk_hec` sink, Logstash's `splunk_hec`
output, every cloud "send to Splunk" button). Repointing them at LogOcean must be a
URL change and nothing else — same paths, same `Authorization: Splunk <token>`
scheme, same JSON envelope, same response bodies.

Everything here is a pure function over strings and dicts; the route handlers at the
bottom do body reading, auth lookup and the hand-off to `ingest.ingest`, nothing more.

WIRE FACTS THIS MODULE HONOURS
------------------------------
* **Concatenated envelopes.** HEC senders batch by writing JSON objects back to back
  with no separator — ``{"event":"a"}{"event":"b"}`` — which is neither valid JSON,
  nor an array, nor NDJSON. ``json.loads`` fails on it and `util.iter_json_records`'s
  line fallback fails too, so the whole request would silently yield zero events.
  `split_hec_envelopes` runs a ``JSONDecoder().raw_decode`` offset loop instead and
  also accepts pretty-printed multi-line objects, NDJSON, comma separation and a
  top-level array.
* **Response shape.** A sender parses the body and keys off ``code``; the absence of
  that field reads as a failure and it retries forever. Success is exactly
  ``{"text": "Success", "code": 0}`` — never LogOcean's batch summary. The batch ids
  go out in an ``X-LogOcean-Batch-Ids`` response header, which senders ignore.
* **Tolerated noise.** ``?channel=<guid>`` and ``X-Splunk-Request-Channel`` are sent
  by real clients and are deliberately NOT declared as parameters — declaring them in
  a model would turn an unexpected extra into a 422 for a sender that is behaving
  correctly. Undeclared query params and headers are ignored by FastAPI.
* **No ack.** ``useACK`` needs a durable queue, which the roadmap parks as open. The
  ack endpoint answers code 14 ("ACK is disabled") so a sender fails fast and loudly
  rather than blocking on an ack that will never come.

SOURCETYPE ROUTING, AND THE ONE TRADE-OFF IN IT
-----------------------------------------------
`ingest.ingest` takes one *text* payload and one format key, so envelope metadata and
event text cannot travel side by side the way they do inside Splunk. That forces a
choice per envelope, and the rule is:

* A **string** ``event`` whose ``sourcetype`` maps to a parser that can read it goes to
  that parser **verbatim** — this is the whole point of sourcetype mapping, and it is
  what turns ``sourcetype=cisco:asa`` into real src/dst/port/action columns instead of
  an opaque blob. The envelope's ``time`` is not carried on this path; the raw line
  carries its own timestamp, which is the same instant at whole-second resolution.
* **Everything else** — object events, and string events with no usable vendor parser —
  is rendered as a JSON record that carries ``time``/``host``/``source``/``sourcetype``/
  ``index``/``fields`` into `raw` (jsonb, GIN-indexed), so the metadata stays searchable
  and CIM-matchable and the envelope ``time`` is honoured exactly.

Envelope metadata is authoritative over same-named keys inside the event body, which
is Splunk's own precedence.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Iterable, Mapping, Optional

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from . import db, ingest
from .config import settings
from .parsers import PARSERS
from .util import _exceeds_json_depth, _MAX_JSON_DEPTH, gunzip_capped

log = logging.getLogger("logocean")

# ── Splunk HEC status codes ─────────────────────────────────────────────────── #
# code -> (HTTP status, text). Verbatim from Splunk's documented HEC responses; a
# sender switch-cases on `code`, so neither the number nor the string is ours to
# improve on. Only the codes this shim can actually emit are listed.
HEC_CODES: dict[int, tuple[int, str]] = {
    0: (200, "Success"),
    1: (403, "Token disabled"),
    2: (401, "Token is required"),
    3: (401, "Invalid authorization"),
    4: (403, "Invalid token"),
    5: (400, "No data"),
    6: (400, "Invalid data format"),
    8: (500, "Internal server error"),
    9: (503, "Server is busy"),
    12: (400, "Event field is required"),
    13: (400, "Event field cannot be blank"),
    14: (400, "ACK is disabled"),
    17: (200, "HEC is healthy"),
}


def hec_body(code: int) -> dict:
    """The Splunk response body for a HEC status code: ``{"text": …, "code": N}``."""
    text = HEC_CODES.get(code, (500, "Internal server error"))[1]
    return {"text": text, "code": code}


def hec_status(code: int) -> int:
    """The HTTP status Splunk pairs with a HEC status code."""
    return HEC_CODES.get(code, (500, "Internal server error"))[0]


# ── auth ────────────────────────────────────────────────────────────────────── #

def hec_token(authorization: Optional[str]) -> Optional[str]:
    """``Authorization: Splunk <token>`` -> token, else None.

    The scheme is compared case-insensitively (senders write "Splunk", "splunk" and
    occasionally "SPLUNK"). `util.extract_api_key` deliberately understands only
    Bearer/X-API-Key, so the Splunk scheme needs its own extractor; the token it
    yields is then verified against the ordinary `api_keys` table with no special
    casing — a HEC token *is* a LogOcean API key.
    """
    if not authorization:
        return None
    scheme, _, rest = authorization.strip().partition(" ")
    if scheme.lower() != "splunk":
        return None
    return rest.strip() or None


# ── body splitting ──────────────────────────────────────────────────────────── #

# Secondary bound on a single request. The transport cap (`settings.max_upload_mb`)
# is the primary one; this stops a body of tightly packed `{}` from materialising an
# unbounded list of dicts. Real senders batch in the hundreds, not the hundred
# thousands, so this can only be reached by something pathological.
MAX_ENVELOPES = 250_000


def split_hec_envelopes(body: str, *, limit: int = MAX_ENVELOPES) -> list[dict]:
    """Split a HEC request body into envelope dicts. Pure.

    Accepts every shape a real sender produces, in one pass:

    * concatenated with no separator — ``{"event":"a"}{"event":"b"}``
    * newline-delimited (NDJSON)
    * pretty-printed across several lines
    * comma-separated, with or without an enclosing array
    * a single object

    A run of bytes that will not decode is resynchronised to the next ``{`` rather
    than aborting the batch, so one corrupt envelope costs one envelope. A
    deeply-nested payload is dropped before the decoder ever sees it (the same bomb
    guard `util.iter_json_records` uses), and at most `limit` envelopes are returned.
    """
    text = body.strip() if body else ""
    if not text:
        return []
    if _exceeds_json_depth(text, _MAX_JSON_DEPTH):
        return []
    decoder = json.JSONDecoder()
    out: list[dict] = []
    idx, end = 0, len(text)
    while idx < end and len(out) < limit:
        while idx < end and text[idx] in " \t\r\n,":   # tolerate any separator style
            idx += 1
        if idx >= end:
            break
        try:
            obj, nxt = decoder.raw_decode(text, idx)
        except ValueError:
            nxt_brace = text.find("{", idx + 1)        # resync; always advances
            if nxt_brace == -1:
                break
            idx = nxt_brace
            continue
        idx = nxt
        if isinstance(obj, dict):
            out.append(obj)
        elif isinstance(obj, list):                    # a top-level array of envelopes
            out.extend(r for r in obj if isinstance(r, dict))
    return out[:limit]


# ── sourcetype -> format routing ────────────────────────────────────────────── #

# Formats that cannot make sense of a bare text line (they need a JSON document).
# A string event routed to one of these would parse to nothing at all, so it is
# wrapped as a JSON record instead — silent loss is the failure mode to avoid.
# `windows_security` / `sysmon` are here on purpose: they read CSV or JSON, and a
# lone CSV data row with no header is as unparseable to them as JSON is to a syslog
# parser, which is exactly what Splunk's `WinEventLog:*` text format arrives as.
NEEDS_JSON = frozenset({
    "aws_cloudtrail", "aws_guardduty", "aws_securityhub", "azure_activity",
    "crowdstrike_json", "defender_xdr", "entra_signin", "gcp_audit", "generic_json",
    "github_audit", "gitlab_audit", "m365_audit", "netflow", "okta_system_log",
    "rapid7", "suricata_eve", "sysmon", "tenable", "windows_security", "zeek_json",
})

# Formats that cannot make sense of a JSON line (they read raw text / CSV / TSV / XML).
NEEDS_TEXT = frozenset({
    "cef", "cisco_asa", "cisco_ftd", "cisco_ios", "crowdstrike_csv",
    "fortinet_fortigate", "generic_syslog", "leef", "linux_auditd", "meraki",
    "paloalto_csv", "paloalto_syslog", "qualys", "web_access", "zeek_tsv",
})

# Sourcetypes whose family prefix would route them wrong ("json_suricata" starts
# with "json"), or that carry no family prefix at all.
_SOURCETYPE_EXACT: dict[str, str] = {
    "json_suricata": "suricata_eve",
    "syslog": "generic_syslog",
    "rfc5424_syslog": "generic_syslog",
    "json": "generic_json",
    "_json": "generic_json",
    "json_no_timestamp": "generic_json",
    "azure:monitor:aad": "entra_signin",
    "azure:monitor:activitylog": "azure_activity",
    "auditd": "linux_auditd",
    "linux_secure": "generic_syslog",
    "linux_messages_syslog": "generic_syslog",
}

# Family prefixes, most specific first — the first match wins, so anything that would
# be shadowed by a shorter sibling has to be listed above it.
_SOURCETYPE_PREFIXES: tuple[tuple[str, str], ...] = (
    ("cisco:asa", "cisco_asa"),
    # FTD emits BOTH grammars down one stream — Lina data-plane messages in the ASA
    # dialect and the unified security events 430001-430005. `cisco_ftd` reads the
    # unified ids and delegates Lina lines to `cisco_asa`, so it is the parser that
    # handles the whole stream; routing these two sourcetypes to `cisco_asa` instead
    # sent every unified event to the wrong grammar, which parsed them into
    # log_type='430003' with src/dst/port/user all null and collapsed their CIM
    # membership from ['ids'] / ['malware'] / ['endpoint'] down to ['network'].
    ("cisco:ftd", "cisco_ftd"),
    ("cisco:sourcefire", "cisco_ftd"),   # Snort/FMC alerts — the SFIMS grammar
    ("cisco:firepower", "cisco_ftd"),
    ("cisco:fmc", "cisco_ftd"),
    ("cisco:fwsm", "cisco_asa"),
    ("cisco:pix", "cisco_asa"),
    ("cisco:ios", "cisco_ios"),
    ("cisco:nxos", "cisco_ios"),
    ("cisco:nx-os", "cisco_ios"),
    ("cisco:meraki", "meraki"),
    ("meraki", "meraki"),
    ("pan:", "paloalto_syslog"),
    ("pan_", "paloalto_syslog"),
    ("paloalto", "paloalto_syslog"),
    ("palo_alto", "paloalto_syslog"),
    ("fgt_", "fortinet_fortigate"),
    ("fgt:", "fortinet_fortigate"),
    ("fortigate", "fortinet_fortigate"),
    ("fortinet", "fortinet_fortigate"),
    ("xmlwineventlog", "windows_security"),
    ("wineventlog", "windows_security"),
    ("windows:", "windows_security"),
    ("linux_audit", "linux_auditd"),
    ("access_", "web_access"),
    ("apache", "web_access"),
    ("nginx", "web_access"),
    ("suricata", "suricata_eve"),
    ("cef", "cef"),
    ("leef", "leef"),
    ("bro", "zeek_json"),                # the Splunk Zeek/Bro TA ships JSON
    ("zeek", "zeek_json"),
    ("aws:cloudtrail", "aws_cloudtrail"),
    ("aws:guardduty", "aws_guardduty"),
    ("aws:securityhub", "aws_securityhub"),
    ("aws:inspector", "aws_securityhub"),   # Inspector reaches Splunk as ASFF
    # Microsoft Defender XDR. The Splunk add-ons spell it several ways, and none of
    # them was reachable — every Defender feed arriving over HEC landed in
    # generic_json with vendor='json' and NO CIM tags at all, so an HEC-fed tenant
    # contributed nothing to the Endpoint/Identity/Email models this wave populated.
    ("ms:defender", "defender_xdr"),
    ("ms365:defender", "defender_xdr"),
    ("mscs:defender", "defender_xdr"),
    ("microsoft:defender", "defender_xdr"),
    ("azure:defender", "defender_xdr"),
    ("defender", "defender_xdr"),
    # Vulnerability scanners -> the CIM Vulnerability model.
    ("qualys", "qualys"),
    ("tenable", "tenable"),
    ("nessus", "tenable"),
    ("rapid7", "rapid7"),
    ("insightvm", "rapid7"),
    ("nexpose", "rapid7"),
    # Flow records. Splunk Stream / the NetFlow TAs both spell it this way.
    ("netflow", "netflow"),
    ("ipfix", "netflow"),
    ("sflow", "netflow"),
    ("o365:", "m365_audit"),
    ("ms:o365", "m365_audit"),
    ("okta", "okta_system_log"),
    ("azure:aad", "entra_signin"),
    ("ms:aad", "entra_signin"),
    ("msaad", "entra_signin"),
    ("entra", "entra_signin"),
    ("azure:activity", "azure_activity"),
    ("mscs:azure", "azure_activity"),
    ("google:gcp", "gcp_audit"),
    ("gcp:", "gcp_audit"),
    ("github", "github_audit"),
    ("gitlab", "gitlab_audit"),
    ("crowdstrike", "crowdstrike_json"),
    ("nutanix:files", "nutanix_files"),
    ("nutanix", "nutanix_pc"),
)

# Checked before the prefixes: Splunk's Sysmon sourcetype is
# "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational", which the "xmlwineventlog"
# prefix would otherwise claim for windows_security.
_SOURCETYPE_CONTAINS: tuple[tuple[str, str], ...] = (
    ("sysmon", "sysmon"),
)


def format_for_sourcetype(sourcetype: Any, *, default: Optional[str] = "generic_json",
                          available: Optional[Iterable[str]] = None) -> Optional[str]:
    """Map a Splunk sourcetype onto a LogOcean format key. Pure.

    Returns `default` (``"generic_json"`` unless overridden; callers pass ``None`` to
    mean "unmapped") for an unrecognised sourcetype, and also for one that maps to a
    parser this build does not register — `available` defaults to the live `PARSERS`
    keys, so a forward-looking entry in the table lights up the day its parser is
    registered and degrades safely until then instead of raising.
    """
    if sourcetype is None:
        return default
    st = str(sourcetype).strip().lower()
    if not st:
        return default
    fmt = _SOURCETYPE_EXACT.get(st)
    if fmt is None:
        for needle, candidate in _SOURCETYPE_CONTAINS:
            if needle in st:
                fmt = candidate
                break
    if fmt is None:
        for prefix, candidate in _SOURCETYPE_PREFIXES:
            if st.startswith(prefix):
                fmt = candidate
                break
    if fmt is None:
        return default
    keys = PARSERS.keys() if available is None else available
    return fmt if fmt in keys else default


def looks_json(text: str) -> bool:
    """True if `text` opens a JSON document — the payload-shape test that decides
    whether a mapped parser can actually read this event."""
    return text.lstrip()[:1] in ("{", "[")


# ── envelope -> parser input ────────────────────────────────────────────────── #

_META_KEYS = ("host", "source", "sourcetype", "index")


def envelope_record(env: Mapping[str, Any], *, event: Optional[Mapping[str, Any]] = None,
                    message: Optional[str] = None) -> dict:
    """One HEC envelope rendered as a JSON record for `generic_json` (and friends).

    Precedence, matching Splunk: the event body is the base, ``fields`` fill gaps it
    does not already define, and the envelope's ``host``/``source``/``sourcetype``/
    ``index``/``time`` are authoritative over same-named keys inside the body — those
    five are indexed metadata in Splunk, not payload. `message` (a raw string event
    being wrapped because no vendor parser could read it) is authoritative over
    everything, since it is the event itself.

    Every key lands at the top level on purpose: `generic_json` flattens and matches
    candidate names there, so ``time`` becomes `event_time`, ``host`` becomes
    `host_name`, and the rest stays in `raw`, which is GIN-indexed and searchable.
    """
    rec: dict[str, Any] = dict(event) if isinstance(event, Mapping) else {}
    fields = env.get("fields")
    if isinstance(fields, Mapping):
        for k, v in fields.items():
            rec.setdefault(str(k), v)
    for key in _META_KEYS:
        value = env.get(key)
        if value not in (None, ""):
            rec[key] = value
    when = env.get("time")
    if when not in (None, ""):
        rec["time"] = when
    if message is not None:
        rec["message"] = message
    return rec


def _json_line(rec: Mapping[str, Any]) -> str:
    """A record as one NDJSON line. `default=str` so a stray non-serialisable value
    degrades to its repr instead of 500-ing the whole request."""
    return json.dumps(rec, default=str, separators=(",", ":"))


def envelope_entry(env: Mapping[str, Any], *,
                   available: Optional[Iterable[str]] = None) -> Optional[tuple[str, str]]:
    """One envelope -> ``(format key, one line of parser input)``, or None if it
    carries nothing to store. Pure — this is where the routing trade-off documented
    in the module docstring is actually decided.
    """
    if not isinstance(env, Mapping):
        return None
    raw_event = env.get("event")
    if isinstance(raw_event, Mapping):
        fmt = format_for_sourcetype(env.get("sourcetype"), default="generic_json",
                                    available=available)
        if fmt in NEEDS_TEXT:              # a syslog/CSV parser cannot read a JSON line
            fmt = "generic_json"
        return fmt, _json_line(envelope_record(env, event=raw_event))

    if raw_event is None:
        text = ""
    elif isinstance(raw_event, str):
        text = raw_event
    else:                                  # number / bool / list — Splunk stringifies
        text = _json_line(raw_event) if isinstance(raw_event, list) else str(raw_event)

    if not text.strip():
        # No event body. A `fields`-only envelope still carries data worth keeping
        # (that is how senders ship index-time metadata); a truly empty one does not.
        fields = env.get("fields")
        if isinstance(fields, Mapping) and fields:
            return "generic_json", _json_line(envelope_record(env))
        return None

    mapped = format_for_sourcetype(env.get("sourcetype"), default=None, available=available)
    if mapped is not None:
        readable = (mapped not in NEEDS_TEXT) if looks_json(text) else (mapped not in NEEDS_JSON)
        if readable:
            # The point of sourcetype mapping: hand the vendor its own text verbatim.
            return mapped, text
    return "generic_json", _json_line(envelope_record(env, message=text))


def group_envelopes(envelopes: Iterable[Mapping[str, Any]], *,
                    available: Optional[Iterable[str]] = None) -> list[tuple[str, str]]:
    """Envelopes -> one ``(format, content)`` batch per distinct format, first-seen
    order preserved. Pure.

    `ingest.ingest` takes ONE format per batch while a single HEC POST may carry mixed
    sourcetypes, so a request becomes N batches. Ordering is first-seen rather than
    arbitrary so the batch ids a request reports are stable and reproducible.
    """
    order: list[str] = []
    lines: dict[str, list[str]] = {}
    for env in envelopes:
        entry = envelope_entry(env, available=available)
        if entry is None:
            continue
        fmt, line = entry
        if fmt not in lines:
            order.append(fmt)
            lines[fmt] = []
        lines[fmt].append(line)
    return [(fmt, "\n".join(lines[fmt])) for fmt in order]


def raw_envelopes(body: str, params: Mapping[str, Any],
                  *, limit: int = MAX_ENVELOPES) -> list[dict]:
    """``/services/collector/raw``: the body is event text, metadata is in the query
    string. Each non-blank line becomes a synthetic envelope so the raw endpoint
    reuses `group_envelopes` and inherits identical routing. Pure.

    BOUNDED LIKE `split_hec_envelopes`, and the asymmetry it used to have was the
    whole defect. This is the line-oriented endpoint — the one Fluent Bit, Vector and
    a plain `curl` point at — so it is where a body of one-character lines lands, and
    it built one dict per line with no cap at all. Measured at ~100x amplification:
    a 1.05 MB body of `"x\\n"` became 524,288 envelopes at 105.8 MB, which at the
    default `max_upload_mb` of 512 extrapolates to ~268 million dicts and a worker
    killed by a single authenticated POST. The caller compares the returned length
    against the limit to tell a full read from a truncated one.
    """
    meta: dict[str, Any] = {}
    for key in _META_KEYS + ("time",):
        value = params.get(key)
        if value not in (None, ""):
            meta[key] = value
    out: list[dict] = []
    for line in (body or "").splitlines():
        if len(out) >= limit:
            break
        if line.strip():
            out.append(dict(meta, event=line))
    return out


def _parse_envelopes(text: str, raw: bool,
                     params: Mapping[str, Any]) -> tuple[list[dict], bool]:
    """``(envelopes, was_truncated)`` for either endpoint.

    Parsed one OVER the cap so a body holding exactly `MAX_ENVELOPES` is a complete
    read rather than an ambiguous one — only a genuinely larger body is refused.
    """
    over = MAX_ENVELOPES + 1
    envelopes = (raw_envelopes(text, params, limit=over) if raw
                 else split_hec_envelopes(text, limit=over))
    if len(envelopes) > MAX_ENVELOPES:
        return envelopes[:MAX_ENVELOPES], True
    return envelopes, False


# ── HTTP plumbing ───────────────────────────────────────────────────────────── #

async def read_body_capped(request: Request, limit: int) -> Optional[bytes]:
    """Stream the request body in chunks, returning None past `limit` bytes.

    Same contract as `api._read_body_capped` and deliberately a separate copy: the
    HEC router is mounted from `api.py`, so importing back the other way would be a
    cycle. Bounds peak memory instead of buffering a hostile body first.
    """
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _reply(code: int, *, status: Optional[int] = None,
           headers: Optional[dict] = None) -> JSONResponse:
    return JSONResponse(status_code=status or hec_status(code), content=hec_body(code),
                        headers=headers)


router = APIRouter(tags=["hec"])


def _authorize(authorization: Optional[str],
               x_api_key: Optional[str]) -> tuple[Optional[dict], Optional[int]]:
    """``(key row, None)`` on success, or ``(None, HEC code)`` describing the refusal.

    A HEC token IS a LogOcean API key — `db.verify_api_key` is used unchanged, and
    `source_label` is the natural place to record "hec" on the key. `X-API-Key` is
    accepted alongside the Splunk scheme purely so an operator can smoke-test the
    endpoint with a key they already have; real senders only ever send
    ``Authorization: Splunk <token>``.

    `db.verify_api_key` cannot distinguish "unknown" from "disabled" — it returns None
    for both — so both answer code 4 rather than guessing at code 1. A confidently
    wrong reason is worse than a general one.
    """
    token = hec_token(authorization) or (x_api_key.strip() if x_api_key else None)
    if not token:
        return None, 2                      # Token is required
    rec = db.verify_api_key(token)
    if rec is None:
        return None, 4                      # Invalid token
    return rec, None


async def _collect(request: Request) -> tuple[Optional[str], Optional[int], Optional[int]]:
    """``(decoded body, None, None)`` or ``(None, HEC code, HTTP status override)``.

    Gzip is unwrapped under the same byte budget as the plaintext cap, so a
    decompression bomb cannot get past it. An over-cap body is the one place the HTTP
    status and the HEC code disagree: 413 is the honest HTTP answer and a sender
    treats it as fatal, while the body still has to carry a `code` a sender
    understands — 6 ("Invalid data format"), the non-retryable payload-rejection class.
    """
    cap = settings.max_upload_mb * 1024 * 1024
    body = await read_body_capped(request, cap)
    if body is None:
        return None, 6, 413                 # body exceeds the transport cap
    body = await run_in_threadpool(gunzip_capped, body, cap)
    if body is None:
        return None, 6, 413                 # corrupt gzip, or expands past the cap
    text = body.decode("utf-8", "replace")
    if not text.strip():
        return None, 5, None                # No data
    return text, None, None


async def _store(batches: list[tuple[str, str]], source_addr: Optional[str]) -> list[int]:
    """Hand each per-format batch to the shared ingest pipeline. One HEC POST can
    become several LogOcean batches — `ingest.ingest` binds one format per batch."""
    ids: list[int] = []
    for fmt, content in batches:
        result = await run_in_threadpool(
            ingest.ingest, content, fmt,
            filename=None, source_type="hec", source_addr=source_addr)
        if isinstance(result, Mapping) and result.get("batch_id") is not None:
            ids.append(int(result["batch_id"]))
    return ids


async def _handle(request: Request, authorization: Optional[str], x_api_key: Optional[str],
                  *, raw: bool) -> JSONResponse:
    # `db.verify_api_key` is blocking and also does an UPDATE + commit; api.py's sync
    # dependency gets threadpooled by FastAPI automatically, this hand-rolled one does
    # not, so it is dispatched explicitly.
    key, refusal = await run_in_threadpool(_authorize, authorization, x_api_key)
    if refusal is not None:
        return _reply(refusal)

    text, refusal, status = await _collect(request)
    if refusal is not None or text is None:
        return _reply(refusal if refusal is not None else 5, status=status)

    # OFF THE EVENT LOOP. `_exceeds_json_depth`, the envelope split and the grouping
    # are per-character / per-envelope pure-Python loops over a body that may be the
    # whole `max_upload_mb`; measured at ~10.8 s and ~6.6 s respectively for 64 MB, so
    # a single 512 MB request stalled the console, /api/v1, /health and — worse — the
    # syslog and NetFlow `datagram_received` callbacks, whose UDP socket buffers then
    # overflow unrecoverably. Gzip made that cheap to trigger rather than expensive:
    # 512 MB of HEC body compresses to about 1 MB. /api/v1/ingest already does the
    # equivalent work in a threadpool for exactly this reason.
    envelopes, truncated = await run_in_threadpool(
        _parse_envelopes, text, raw, dict(request.query_params))

    if truncated:
        # REFUSE, and ingest nothing. Answering 200/`code: 0` here was silent,
        # unrecoverable loss: a HEC sender switch-cases on `code`, and 0 means
        # "indexed, you may advance", so it deleted its buffer over the events we
        # dropped. The cap is on envelope COUNT while the transport cap is on BYTES —
        # 300,000 minimal envelopes is only ~13 MB, 2.5% of the default 512 MB budget
        # — so a forwarder catching up after an outage reaches it easily, which is
        # precisely when losing the batch matters most.
        # Code 9 / 503 is the RETRYABLE class: the sender backs off and keeps its
        # buffer. All-or-nothing on purpose — a partial ingest plus a retry would
        # duplicate the prefix, and HEC has no way to say "I took the first N".
        log.error(
            "hec: refusing a request of more than %d envelopes (key=%s, endpoint=%s); "
            "answered 503/code 9 so the sender retries — lower the sender's batch size",
            MAX_ENVELOPES, (key or {}).get("key_prefix"), "raw" if raw else "event")
        return _reply(9, headers={"Retry-After": "30"})     # Server is busy

    if not raw and not envelopes:
        return _reply(6)                    # Invalid data format

    batches = await run_in_threadpool(group_envelopes, envelopes)
    if not batches:
        return _reply(12)                   # Event field is required

    try:
        ids = await _store(batches, request.client.host if request.client else None)
    except Exception:  # noqa: BLE001 — a sender must never see a stack trace
        log.exception("hec ingest failed (key=%s, batches=%d)",
                      (key or {}).get("key_prefix"), len(batches))
        return _reply(8)                    # Internal server error

    return _reply(0, headers={"X-LogOcean-Batch-Ids": ",".join(str(i) for i in ids)})


@router.post("/services/collector")
@router.post("/services/collector/event")
@router.post("/services/collector/event/1.0")
async def hec_event(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> JSONResponse:
    """The endpoint every HEC sender posts to. `?channel=` and
    `X-Splunk-Request-Channel` are accepted and ignored — undeclared on purpose."""
    return await _handle(request, authorization, x_api_key, raw=False)


@router.post("/services/collector/raw")
@router.post("/services/collector/raw/1.0")
async def hec_raw(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> JSONResponse:
    """Raw text mode: the body is the event(s), metadata comes from the query string
    (`?sourcetype=&host=&source=&index=&time=`). Line-oriented by definition."""
    return await _handle(request, authorization, x_api_key, raw=True)


@router.get("/services/collector/health")
@router.get("/services/collector/health/1.0")
async def hec_health() -> JSONResponse:
    """Liveness of the HEC listener. Deliberately token-free and dependency-free:
    a sender polls this to decide whether to send at all, so it must not be able to
    fail for a reason unrelated to whether the endpoint is accepting posts."""
    return _reply(17)


@router.post("/services/collector/ack")
async def hec_ack() -> JSONResponse:
    """Indexer acknowledgement is not supported — it needs a durable queue LogOcean
    does not have yet. Answering code 14 makes a `useACK=true` sender fail fast
    instead of blocking forever on an ack that is never coming."""
    return _reply(14)
