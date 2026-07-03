# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Nutanix Prism Central parser — remote-syslog audit, API and Flow logs.

Prism Central forwards its security-relevant modules to a remote syslog server,
each carried on its own syslog *tag* (program name). Three modules matter to a
SIEM (verified against the format FortiSIEM / Splunk / Google SecOps parse):

``api_audit``
    Every REST API call. A double-pipe (``||``) delimited key=value payload::

        INFO  2026-06-28 10:16:01,001 clientType=External||userName=svc||\
NutanixApiVersion=3.1||httpMethod=DELETE||restEndpoint=/api/nutanix/v3/vms/<uuid>||\
entityUuid=<uuid>||queryParams=||payload=

``consolidated_audit``
    The user / configuration audit trail (and consolidated alerts). A JSON object
    payload with ``operationType`` / ``userName`` / ``clientIp`` /
    ``affectedEntityList`` / ``defaultMsg`` / ``recordType`` / ``severity`` ...

``flow-hitCountN``
    Flow Network Security microsegmentation hits::

        INFO:2026/06/28 10:19:18  [<rule-uuid>] <policy> [<state>] SRC=.. DST=.. \
PROTO=TCP SPORT=.. DPORT=.. ACTION=DROP ORIG: PKTS=.. BYTES=.. REPLY: PKTS=.. BYTES=..

Each line arrives inside a syslog envelope ``<PRI>timestamp host tag: payload``.
We strip the envelope, route on the tag (or, offline, sniff the payload), and
keep the full parsed record in ``raw`` so nothing is lost. Offline JSON exports
of the audit trail (a bare array / NDJSON of audit records) are handled too.

Note: the raw PCVM *component* logs (``aplos.out``, ``prism_gateway.log`` ...)
are local glog troubleshooting files, not a forwarded stream; the SIEM ingests
the forwarded audit / API / Flow syslog above.
"""
from __future__ import annotations

import re
from typing import Any, Iterator, Optional

from ..models import NormalizedEvent
from ..util import (clean_ip, first, iter_json_records, json_or_none, parse_ts,
                    to_int, to_port)

# Standard syslog PRI severities (facility*8 + severity), for the envelope.
_SEVERITY = {0: "emergency", 1: "alert", 2: "critical", 3: "error",
             4: "warning", 5: "notice", 6: "informational", 7: "debug"}
# Log-level word (INFO / WARNING / ERROR ...) inside a payload -> our severity.
_LEVEL = {"emerg": "emergency", "alert": "alert", "crit": "critical",
          "critical": "critical", "err": "error", "error": "error",
          "warn": "warning", "warning": "warning", "notice": "notice",
          "info": "informational", "debug": "debug"}

_PRI = re.compile(r"^<(\d{1,3})>")
# Syslog envelope: <PRI> already stripped. ISO-8601 (Nutanix default) or BSD ts,
# then host, then the tag (program) ending in ':'. hitCount tags carry digits.
_ISO_HDR = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+)\s+(?P<host>\S+)\s+"
    r"(?P<tag>[A-Za-z][\w.\-]*)(?:\[\d+\])?:\s*(?P<payload>.*)$")
_BSD_HDR = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<tag>[A-Za-z][\w.\-]*)(?:\[\d+\])?:\s*(?P<payload>.*)$")

# api_audit payload: "INFO  <ts>[,millis] <k=v>||<k=v>||...".
_API_HDR = re.compile(
    r"^(?P<level>[A-Za-z]+)\s+"
    r"(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)\s+(?P<rest>.*)$")

# flow payload: "INFO:<ts>  [<rule-uuid>] <policy> [<state>] <SRC=.. ...>".
_FLOW_HDR = re.compile(
    r"^(?P<level>[A-Za-z]+):?\s*"
    r"(?P<ts>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"\[(?P<rule_uuid>[^\]]+)\]\s+(?P<policy>\S+)\s+\[(?P<state>[^\]]+)\]\s*(?P<rest>.*)$")
_FLOW_KV = re.compile(r"\b([A-Za-z]+)=(\S+)")
_FLOW_ORIG = re.compile(r"ORIG:\s*PKTS=(\d+)\s+BYTES=(\d+)", re.IGNORECASE)
_FLOW_REPLY = re.compile(r"REPLY:\s*PKTS=(\d+)\s+BYTES=(\d+)", re.IGNORECASE)

_VENDOR = "nutanix"
_PRODUCT = "prism-central"


def _nz(v: Optional[str]) -> Optional[str]:
    return v if v not in (None, "", "-") else None


def _severity_word(level: Optional[str], fallback: Optional[str]) -> Optional[str]:
    if not level:
        return fallback
    return _LEVEL.get(str(level).strip().lower(), fallback)


def _norm_severity(value: Any, fallback: Optional[str]) -> Optional[str]:
    """Normalize an audit-record severity (``AUDIT`` / ``kCritical`` / ``WARNING``)."""
    if value in (None, ""):
        return fallback
    s = str(value).strip().lower()
    if s.startswith("k") and len(s) > 1:      # Nutanix enum style: kCritical
        s = s[1:]
    return {"info": "informational", "information": "informational",
            "audit": "informational"}.get(s, s) or fallback


def parse(content: str) -> Iterator[NormalizedEvent]:
    text = content.strip()
    # Offline export: the whole document is JSON / NDJSON of audit records.
    if text[:1] in ("{", "["):
        for rec in iter_json_records(content, "entities", "audits", "data", "records"):
            ev = _from_audit(rec, None, None, None)
            if ev is not None:
                yield ev
        return

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        pri_sev = None
        pm = _PRI.match(line)
        body = line
        if pm:
            pri_sev = _SEVERITY.get(int(pm.group(1)) % 8)
            body = line[pm.end():].lstrip()
        hm = _ISO_HDR.match(body) or _BSD_HDR.match(body)
        if hm:
            env_ts, host, tag = hm.group("ts"), _nz(hm.group("host")), _nz(hm.group("tag"))
            payload = hm.group("payload")
        else:
            env_ts, host, tag, payload = None, None, None, body

        ev = _route(tag, payload, pri_sev, env_ts, host)
        if ev is not None:
            yield ev


def _route(tag: Optional[str], payload: str, pri_sev: Optional[str],
           env_ts: Optional[str], host: Optional[str]) -> Optional[NormalizedEvent]:
    tag_l = (tag or "").lower()
    stripped = payload.lstrip()

    if "flow" in tag_l:
        return _from_flow(payload, pri_sev, env_ts, host)
    if "api_audit" in tag_l:
        return _from_api(payload, pri_sev, env_ts, host)
    if "consolidated_audit" in tag_l or stripped[:1] == "{":
        rec = json_or_none(stripped)
        if isinstance(rec, dict):
            return _from_audit(rec, pri_sev, env_ts, host)
    # Offline / unknown tag — sniff the payload shape.
    if _FLOW_HDR.match(stripped) or ("SRC=" in payload and "PROTO=" in payload):
        return _from_flow(payload, pri_sev, env_ts, host)
    if "httpMethod=" in payload or "restEndpoint=" in payload:
        return _from_api(payload, pri_sev, env_ts, host)
    return _generic(tag, payload, pri_sev, env_ts, host)


# --------------------------------------------------------------------------- #
#  consolidated_audit — JSON audit / alert record                             #
# --------------------------------------------------------------------------- #
def _from_audit(rec: dict, pri_sev: Optional[str], env_ts: Optional[str],
                host: Optional[str]) -> Optional[NormalizedEvent]:
    if not isinstance(rec, dict):
        return None
    # Case/underscore-insensitive lookup (syslog uses camelCase, the v3 API
    # export uses snake_case): index both forms.
    low: dict[str, Any] = {}
    for k, v in rec.items():
        lk = str(k).lower()
        low.setdefault(lk, v)
        low.setdefault(lk.replace("_", ""), v)

    def g(*names: str) -> Any:
        for n in names:
            v = low.get(n.lower())
            if v not in (None, ""):
                return v
        return None

    operation = g("operationtype", "optype", "operation")
    user = g("username", "originatingusername", "user")
    client_ip = g("clientip", "originatingclientip", "remoteip", "sourceip")
    record_type = g("recordtype")
    entities = g("affectedentitylist", "affectedentities", "affected_entity_list")
    ent_summary = _entity_summary(entities)

    msg = g("defaultmsg", "defaultmessage", "auditmessage", "message")
    if not msg:
        msg = " ".join(x for x in (operation, ent_summary) if x) or None

    ts = g("creationtimestampusecs", "opstarttimestampusecs",
           "createdtimeusecs", "creationtime", "timestamp")

    return NormalizedEvent(
        event_time=parse_ts(ts) or parse_ts(env_ts),
        vendor=_VENDOR,
        product=_PRODUCT,
        log_type=(str(record_type).lower() if record_type else "audit"),
        severity=_norm_severity(g("severity"), pri_sev),
        action=(str(operation) if operation else None),
        src_ip=clean_ip(client_ip),
        user_name=(str(user) if user else None),
        host_name=host,
        rule_name=first(g("alertuid"), ent_summary),
        message=(str(msg)[:2000] if msg else None),
        raw=rec,
    )


def _entity_summary(entities: Any) -> Optional[str]:
    """A short 'type:name' from the first affected entity, for grouping/display."""
    if not isinstance(entities, list):
        return None
    for e in entities:
        if isinstance(e, dict):
            name = e.get("name") or e.get("uuid")
            etype = e.get("entityType") or e.get("entity_type") or e.get("type")
            if name or etype:
                return ":".join(str(x) for x in (etype, name) if x)
    return None


# --------------------------------------------------------------------------- #
#  api_audit — REST API call                                                  #
# --------------------------------------------------------------------------- #
def _from_api(payload: str, pri_sev: Optional[str], env_ts: Optional[str],
              host: Optional[str]) -> NormalizedEvent:
    level = None
    inner_ts = None
    rest = payload
    m = _API_HDR.match(payload.strip())
    if m:
        level = m.group("level")
        inner_ts = m.group("ts").replace(",", ".")   # 06:27:13,742 -> .742
        rest = m.group("rest")

    kv = _kv_double_pipe(rest)

    def g(*names: str) -> Optional[str]:
        for n in names:
            v = kv.get(n.lower())
            if v not in (None, ""):
                return v
        return None

    method = g("httpmethod", "method")
    endpoint = g("restendpoint", "endpoint", "uri", "url")
    client_ip = g("clientip", "remoteip", "sourceip", "remoteaddr")
    user = g("username", "user")
    message = " ".join(x for x in (method, endpoint) if x) or (rest.strip() or None)

    return NormalizedEvent(
        event_time=parse_ts(inner_ts) or parse_ts(env_ts),
        vendor=_VENDOR,
        product=_PRODUCT,
        log_type="api_audit",
        severity=_severity_word(level, pri_sev),
        action=(str(method) if method else None),
        src_ip=clean_ip(client_ip),
        app="prism-api",
        user_name=(str(user) if user else None),
        host_name=host,
        rule_name=endpoint,
        message=message,
        raw={"module": "api_audit", "level": level,
             "clientType": g("clienttype"), "userName": user,
             "nutanixApiVersion": g("nutanixapiversion", "apiversion"),
             "httpMethod": method, "restEndpoint": endpoint,
             "entityUuid": g("entityuuid"), "queryParams": g("queryparams"),
             "payload": g("payload"), "clientIp": client_ip, "attributes": kv},
    )


def _kv_double_pipe(rest: str) -> dict[str, str]:
    """Parse Nutanix ``key=value||key=value`` (the api_audit payload) into a
    lowercased dict. Falls back to a single message when no key=value is found."""
    out: dict[str, str] = {}
    tokens = rest.split("||") if "||" in rest else rest.split()
    for tok in tokens:
        if "=" in tok:
            key, _, val = tok.partition("=")
            key = key.strip().lower()
            if key:
                out[key] = val.strip()
    return out


# --------------------------------------------------------------------------- #
#  flow-hitCount — Flow Network Security microsegmentation hit                 #
# --------------------------------------------------------------------------- #
def _from_flow(payload: str, pri_sev: Optional[str], env_ts: Optional[str],
               host: Optional[str]) -> NormalizedEvent:
    m = _FLOW_HDR.match(payload.strip())
    level = policy = state = rule_uuid = None
    inner_ts = None
    rest = payload
    if m:
        level = m.group("level")
        inner_ts = m.group("ts")
        rule_uuid = m.group("rule_uuid")
        policy = m.group("policy")
        state = m.group("state")
        rest = m.group("rest")

    kv = {k.upper(): v for k, v in _FLOW_KV.findall(rest)}
    orig = _FLOW_ORIG.search(rest)
    reply = _FLOW_REPLY.search(rest)
    ob = to_int(orig.group(2)) if orig else None
    rb = to_int(reply.group(2)) if reply else None
    bytes_total = (ob or 0) + (rb or 0) if (ob or rb) else to_int(kv.get("BYTES"))

    action = (kv.get("ACTION") or "").lower() or None
    proto = (kv.get("PROTO") or "").lower() or None
    src, dst = clean_ip(kv.get("SRC")), clean_ip(kv.get("DST"))

    parts = [policy, f"[{state}]" if state else None, action,
             f"{src}:{kv.get('SPORT')}" if src else None,
             "->", f"{dst}:{kv.get('DPORT')}" if dst else None, proto]
    message = " ".join(str(p) for p in parts if p) or rest.strip() or None

    return NormalizedEvent(
        event_time=parse_ts(inner_ts) or parse_ts(env_ts),
        vendor=_VENDOR,
        product=_PRODUCT,
        log_type="flow",
        severity=_severity_word(level, pri_sev),
        action=action,
        src_ip=src,
        dst_ip=dst,
        src_port=to_port(kv.get("SPORT")),
        dst_port=to_port(kv.get("DPORT")),
        protocol=proto,
        app="flow",
        host_name=host,
        rule_name=policy,
        bytes_total=bytes_total,
        message=message,
        raw={"module": "flow", "level": level, "rule_uuid": rule_uuid,
             "policy": policy, "state": state,
             "orig_pkts": to_int(orig.group(1)) if orig else None, "orig_bytes": ob,
             "reply_pkts": to_int(reply.group(1)) if reply else None, "reply_bytes": rb,
             "attributes": kv, "line": payload},
    )


# --------------------------------------------------------------------------- #
#  Fallback — an unrecognized Nutanix module line, kept whole                  #
# --------------------------------------------------------------------------- #
def _generic(tag: Optional[str], payload: str, pri_sev: Optional[str],
             env_ts: Optional[str], host: Optional[str]) -> NormalizedEvent:
    return NormalizedEvent(
        event_time=parse_ts(env_ts),
        vendor=_VENDOR,
        product=_PRODUCT,
        log_type=(str(tag).lower() if tag else "prism-central"),
        severity=pri_sev,
        host_name=host,
        app=(str(tag) if tag else None),
        message=(payload.strip() or None),
        raw={"module": tag, "message": payload.strip(), "host": host},
    )
