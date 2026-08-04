# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Cisco Firepower Threat Defense (FTD) — security-event syslog parser.

This is NOT an extension of ``cisco_asa.py``. That parser reads the Lina
data-plane messages FTD inherits from ASA — free text behind ``%ASA-6-302013:``,
mined with ``src``/``dst``/``from``/``to`` regexes. FTD's *security* events are a
different grammar with its own message-id block (430001-430005) whose payload is
a comma-separated ``Key: Value`` list, plus the classic Snort/FMC alert line.
Both are handled here; the Lina messages stay with ``cisco_asa``.

GRAMMAR 1 — FTD unified security events (Cisco message ids 430001-430005)::

    <134>Jun 15 2026 10:00:31 ftd01 : %FTD-6-430003: EventPriority: Low,
      DeviceUUID: 1a2b…, FirstPacketSecond: 2026-06-15T10:00:28Z, SrcIP: 10.20.30.40,
      DstIP: 93.184.216.34, SrcPort: 51514, DstPort: 443, Protocol: tcp,
      AccessControlRuleAction: Allow, AccessControlRuleName: Allow-Web, …

  ============  =========================  ================================
  message id    event                      ``log_type``
  ============  =========================  ================================
  430001        intrusion (Snort)          ``intrusion``
  430002        connection, at start       ``connection``
  430003        connection, at end         ``connection``
  430004        file                       ``file``
  430005        file malware               ``malware``
  ============  =========================  ================================

GRAMMAR 2 — FMC / Snort intrusion alert (``SFIMS:``)::

    <129>Jun 15 2026 10:01:12 fmc01 SFIMS: [1:2019401:5] "OS-WINDOWS SMB RCE attempt"
      [Impact: Vulnerable] From "sensor01" at Mon Jun 15 10:01:12 2026 UTC
      [Classification: Attempted Administrator Privilege Gain] [Priority: 1]
      {tcp} 45.83.122.7:40331 -> 10.20.30.40:445

WHY ``log_type`` IS THE EVENT CLASS AND NOT THE MESSAGE ID
----------------------------------------------------------
``cisco_asa.py`` puts the numeric message id in ``log_type``, which works there
because the CIM registry keys ASA on ``{vendor: cisco, product: asa|firepower|ios}``
and on specific numeric ids for Authentication. Here the four event classes must
reach four DIFFERENT models, and ``log_type`` is the only membership handle a
generic clause can read, so it carries the class. MEASURED against the shipped
registry, with no ``models.yaml`` edit required:

  * ``connection`` -> Network   (``log_type`` clause; ``connection`` is listed)
  * ``intrusion``  -> IDS       (``log_type`` clause; ``intrusion`` is listed)
  * ``file``       -> Endpoint  (``log_type`` clause; ``file`` is listed)
  * ``malware``    -> Malware   (``log_type`` clause; ``malware`` is listed)

Every one of them ALSO matches ``{vendor: [cisco], product: [asa, firepower, ios]}``
and is therefore a Network member too — which is correct: all four carry a full
5-tuple, and models are not mutually exclusive.

The numeric message id is kept in ``raw["message_id"]`` and the class in
``raw["event_class"]``. Two canonical keys are written back beside the vendor's
own spelling, the way ``windows_security.py`` writes ``event_id`` — ``raw`` keys are
byte-exact to CIM, so an alias is the only way ``FileSHA256`` and ``Classification``
can be read by the shipped ``file_hash`` / ``category`` field mappings.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, parse_ts, to_int, to_port

# Syslog severity level -> name (same table ASA/FTD use).
_SEVERITY = {0: "emergency", 1: "alert", 2: "critical", 3: "error",
             4: "warning", 5: "notice", 6: "informational", 7: "debug"}

#: FTD unified security-event message id -> event class. ONLY these ids are ours;
#: every other %FTD-/%ASA- message is a Lina message and belongs to `cisco_asa`.
_EVENT_CLASS = {
    "430001": "intrusion",
    "430002": "connection",
    "430003": "connection",
    # `file-transfer`, deliberately NOT the bare `file` the CIM Endpoint model
    # matches on. That token exists for a FIM source's ECS event.category, and
    # borrowing it made an FTD file event a member of a model whose own description
    # is "host telemetry ... from EDR/Sysmon/auditd/FIM" — while `dvc` was the
    # firewall rather than the host and process/parent_process/registry_path were
    # null by construction. It also split the two file-policy events arbitrarily:
    # 430004 landed in Endpoint, its sibling 430005 (same inspection engine, same
    # FileName/FileSHA256/FileDirection fields) did not. This is an inline network
    # observation, so it is a Network member and nothing else; 430005 additionally
    # carries a malware verdict, which is a real, semantic reason to differ.
    "430004": "file-transfer",
    "430005": "malware",
}

_PRI = re.compile(r"^<\d{1,3}>")
# RFC 3164 ("Jun 15 2026 10:00:31") or ISO-8601 syslog header timestamp.
_TS = re.compile(
    r"\b(?:[A-Z][a-z]{2}\s+\d{1,2}\s+(?:\d{4}\s+)?\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)")
# %FTD-6-430003: <key: value, key: value …>. ASA-tagged FTD deployments exist, so
# the facility is permissive — the id whitelist above is what actually gates it.
_MSGID = re.compile(
    r"%(?P<fac>ASA|FTD|FPR|FIREPOWER|SFIMS)-(?P<lvl>\d)-(?P<id>\d+):\s*(?P<body>.*)$",
    re.IGNORECASE)

# One `Key: Value` pair. The value is taken lazily up to the next `, Key:` boundary
# (or end of line) instead of splitting on commas, because FTD values legitimately
# contain them — "NAPPolicy: Balanced Security and Connectivity, Version 2".
_KV = re.compile(
    r"(?P<k>[A-Za-z][A-Za-z0-9_/ -]*?)\s*:\s*(?P<v>.*?)"
    r"(?=\s*,\s*[A-Za-z][A-Za-z0-9_/ -]*?\s*:\s|\s*$)")

# --- Snort / FMC alert line ------------------------------------------------- #
_SNORT_ID = re.compile(r"\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]")
_SNORT_MSG = re.compile(
    r'\[\d+:\d+:\d+\]\s*(?:"(?P<q>[^"]*)"|(?P<u>[^\[{]+?))\s*(?=\[|From\b|\{|$)')
_SNORT_TAG = re.compile(r"\[(?P<k>[A-Za-z][A-Za-z ]*?)\s*:\s*(?P<v>[^\]]*)\]")
# The inline-drop verdict FMC appends as a BARE bracket (no `key:`), which is why
# `_SNORT_TAG` above cannot see it. Matching the whole line for "block" instead
# would call every alert a block the moment a signature name contains the word.
_SNORT_BLOCK = re.compile(
    r"\[(?:Would\s+Have\s+Blocked|Blocked|Dropped|Partially\s+Dropped)\]",
    re.IGNORECASE)
_SNORT_FROM = re.compile(r'\bFrom\s+"(?P<sensor>[^"]+)"')
_SNORT_PROTO = re.compile(r"\{(?P<proto>\w+)\}")
_SNORT_FLOW = re.compile(
    r"(?P<sip>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<sport>\d+))?\s*->\s*"
    r"(?P<dip>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<dport>\d+))?")
# The syslog program tag FMC puts in front of a Snort alert.
_PROGRAM = re.compile(r"\b(?:SFIMS|snort)\s*:", re.IGNORECASE)

# FTD action vocabularies (AccessControlRuleAction / InlineResult / FileAction),
# normalized the way `cisco_asa._action` normalizes Lina verbs.
_ACTIONS = {
    "allow": "allow", "trust": "allow", "monitor": "allow", "permit": "allow",
    "block": "block", "blocked": "block", "block with reset": "block",
    "blockwithreset": "block", "reset": "block", "drop": "block",
    "interactive block": "block", "interactiveblock": "block",
    "would have blocked": "block", "would block": "block",
    "detect": "detect", "malware cloud lookup": "detect", "cloud lookup": "detect",
    "pending": "detect", "custom detection": "detect",
}
# Snort / FTD event priority, numeric or already-named.
_PRIORITY = {"1": "high", "2": "medium", "3": "low", "4": "informational",
             "high": "high", "medium": "medium", "low": "low",
             "very low": "informational", "informational": "informational"}
# Numeric IP protocol, for the deployments that report `Protocol: 6`.
_IP_PROTO = {"1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp",
             "58": "ipv6-icmp", "132": "sctp"}
# FTD's placeholder for "the connection had no authenticated identity". Storing it
# as a user_name would make it the busiest account in the deployment.
_NO_USER = {"no authentication required", "unknown", "n/a", "none", ""}


def kv_pairs(body: str) -> dict:
    """The ``Key: Value, Key: Value`` payload of an FTD unified event.

    Keys keep their VENDOR spelling (``FileSHA256``, not ``filesha256``) because
    ``raw`` keys are byte-exact to the CIM evaluator. Surrounding quotes are
    stripped from values so ``Message: "…"`` reads as the bare signature text."""
    out: dict = {}
    for m in _KV.finditer(body or ""):
        key = m.group("k").strip()
        if key:
            out[key] = m.group("v").strip().strip('"').strip()
    return out


def _pick(low: dict, *names: str) -> Optional[str]:
    """First non-empty value among ``names`` from a lower-cased key index."""
    for n in names:
        v = low.get(n.lower())
        if v not in (None, ""):
            return v
    return None


def _action(value: Any) -> Optional[str]:
    if value in (None, ""):
        return None
    return _ACTIONS.get(str(value).strip().lower(), str(value).strip().lower())


def _protocol(value: Any) -> Optional[str]:
    if value in (None, ""):
        return None
    v = str(value).strip().lower()
    return _IP_PROTO.get(v, v) or None


def _user(value: Any) -> Optional[str]:
    if value in (None, ""):
        return None
    v = str(value).strip()
    return None if v.lower() in _NO_USER else v


def _header(line: str, upto: int) -> tuple[Optional[datetime], Optional[str]]:
    """(event_time, hostname) mined from the syslog header before ``upto``."""
    head = _PRI.sub("", line[:upto]).strip()
    m = _TS.search(head)
    ts = parse_ts(m.group(0)) if m else None
    if m:
        head = head[:m.start()] + head[m.end():]
    head = head.strip().strip(":").strip()
    # Drop the RFC 5424 version digit and its "-" nil placeholders.
    parts = [p for p in head.split() if p not in ("1", "-")]
    host = parts[-1].strip(": ") if parts else None
    return ts, (host or None)


def _unified(line: str, m: "re.Match") -> NormalizedEvent:
    """One FTD 430001-430005 security event."""
    mid, level = m.group("id"), int(m.group("lvl"))
    klass = _EVENT_CLASS[mid]
    body = m.group("body").strip()
    kv = kv_pairs(body)
    low = {k.lower(): v for k, v in kv.items()}
    hdr_time, host = _header(line, m.start())

    raw = dict(kv)
    raw["message_id"] = mid
    raw["event_class"] = klass
    raw["severity_level"] = level
    if host:
        raw["host"] = host
    raw["line"] = line

    # Canonical write-backs. `raw` keys are byte-exact to CIM, so the shipped
    # `file_hash: raw: [Hashes, SHA256, …]` and `category: raw: [category, …]`
    # mappings can only see FTD's values under an agreed spelling.
    sha = _pick(low, "FileSHA256", "SHA256", "SHA_256", "FileSha256")
    if sha:
        raw["SHA256"] = sha
    classification = _pick(low, "Classification")
    if classification:
        raw["category"] = classification

    initiator = to_int(_pick(low, "InitiatorBytes"))
    responder = to_int(_pick(low, "ResponderBytes"))
    total = to_int(_pick(low, "Bytes", "TotalBytes"))
    if total is None and (initiator is not None or responder is not None):
        # re-bounded through to_int: both operands are individually within signed
        # 64-bit, but their sum need not be, and an out-of-range `bytes_total` aborts
        # the executemany and takes the whole buffered syslog group down with it
        total = to_int((initiator or 0) + (responder or 0))

    if klass == "intrusion":
        signature = _pick(low, "Message", "Msg", "IntrusionPolicy")
        action = _action(first(_pick(low, "InlineResult", "InlineResultReason"),
                               _pick(low, "AccessControlRuleAction")))
    elif klass == "malware":
        signature = _pick(low, "ThreatName", "FilePolicy", "AccessControlRuleName")
        action = _action(first(_pick(low, "FileAction"),
                               _pick(low, "AccessControlRuleAction")))
    elif klass == "file-transfer":
        signature = _pick(low, "FilePolicy", "AccessControlRuleName")
        action = _action(first(_pick(low, "FileAction"),
                               _pick(low, "AccessControlRuleAction")))
    else:                                            # connection
        signature = _pick(low, "AccessControlRuleName", "ACPolicy", "PrefilterPolicy")
        action = _action(_pick(low, "AccessControlRuleAction"))

    priority = _pick(low, "Priority", "EventPriority")
    severity = first(_PRIORITY.get((priority or "").strip().lower()),
                     _SEVERITY.get(level))

    return NormalizedEvent(
        event_time=first(
            parse_ts(_pick(low, "FirstPacketSecond", "ConnectionTimestamp",
                           "EventSecond", "LastPacketSecond", "FileEventTimestamp")),
            hdr_time),
        vendor="cisco",
        product="firepower",
        log_type=klass,
        severity=severity,
        action=action,
        src_ip=clean_ip(_pick(low, "SrcIP", "Src_IP", "SourceIP", "OriginalClientIP")),
        dst_ip=clean_ip(_pick(low, "DstIP", "Dst_IP", "DestinationIP")),
        src_port=to_port(_pick(low, "SrcPort", "SourcePort")),
        dst_port=to_port(_pick(low, "DstPort", "DestinationPort")),
        protocol=_protocol(_pick(low, "Protocol", "IPProto")),
        app=_pick(low, "ApplicationProtocol", "WebApplication", "Client",
                  "ClientApplication"),
        user_name=_user(_pick(low, "User", "UserName")),
        host_name=first(host, _pick(low, "DeviceName", "Device", "DeviceUUID")),
        rule_name=signature,
        bytes_total=total,
        message=first(_pick(low, "Message", "Msg"), _pick(low, "ThreatName"),
                      body) or None,
        raw=raw,
    )


def _snort(line: str) -> Optional[NormalizedEvent]:
    """One FMC / Snort intrusion alert, or None when the line is not one.

    Requires BOTH the ``[gid:sid:rev]`` signature id and an ``a.b.c.d -> a.b.c.d``
    flow: either alone appears in unrelated syslog, and a parser that grabs
    whatever it can here would swallow lines that belong to another vendor."""
    idm = _SNORT_ID.search(line)
    flow = _SNORT_FLOW.search(line)
    if not idm or not flow:
        return None

    tags = {m.group("k").strip().lower(): m.group("v").strip()
            for m in _SNORT_TAG.finditer(line)}
    msgm = _SNORT_MSG.search(line)
    signature = None
    if msgm:
        signature = (msgm.group("q") or msgm.group("u") or "").strip() or None

    program = _PROGRAM.search(line)
    hdr_time, host = _header(line, program.start() if program else idm.start())
    sensor = _SNORT_FROM.search(line)
    protom = _SNORT_PROTO.search(line)
    gid, sid, rev = idm.group("gid"), idm.group("sid"), idm.group("rev")

    raw = {
        "gid": gid, "sid": sid, "rev": rev,
        "signature_id": f"{gid}:{sid}:{rev}",
        "event_class": "intrusion",
        "message": signature,
        "line": line,
    }
    raw.update({k: v for k, v in tags.items() if v})
    if sensor:
        raw["sensor"] = sensor.group("sensor")
    if host:
        raw["host"] = host
    # `category` is the shipped IDS field's first alternative; Snort's own name for
    # it is `Classification`, so the alias is what makes IDS.category non-null.
    if tags.get("classification"):
        raw["category"] = tags["classification"]

    blocked = _SNORT_BLOCK.search(line) is not None
    return NormalizedEvent(
        event_time=hdr_time,
        vendor="cisco",
        product="firepower",
        log_type="intrusion",
        severity=_PRIORITY.get((tags.get("priority") or "").strip().lower()),
        action="block" if blocked else "detect",
        src_ip=clean_ip(flow.group("sip")),
        dst_ip=clean_ip(flow.group("dip")),
        src_port=to_port(flow.group("sport")),
        dst_port=to_port(flow.group("dport")),
        protocol=_protocol(protom.group("proto") if protom else None),
        host_name=first(sensor.group("sensor") if sensor else None, host),
        rule_name=signature,
        message=signature or line,
        raw=raw,
    )


def parse(content: str) -> Iterator[NormalizedEvent]:
    """FTD's syslog stream, both grammars.

    An FTD appliance emits Lina data-plane messages (302013 connection built, 106023
    deny, 605005 login permitted) and unified security events (430001-430005) down the
    SAME stream, but `detect_format` is a whole-FILE decision — one format wins the
    file. Lina lines used to be dropped here with no counter and no log line, and
    `ingest.py` hardcodes `error_rows=0` while `result.total` counts only what a parser
    yielded, so a mixed file ingested "cleanly" while a third of it vanished: an
    `%ASA-6-605005` login (an Authentication CIM member) and an `%ASA-2-106023` deny
    simply were not there.

    So they are DELEGATED rather than discarded. `cisco_asa` owns that grammar and is
    imported lazily — both modules are registered in the same `PARSERS` dict, and a
    module-level import would run during that package's own import.
    """
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        m = _MSGID.search(line)
        if m and m.group("id") in _EVENT_CLASS:
            yield _unified(line, m)
            continue
        if m:
            from . import cisco_asa            # a Lina message — that grammar's owner
            yield from cisco_asa.parse(line)
            continue
        event = _snort(line)
        if event is not None:
            yield event
