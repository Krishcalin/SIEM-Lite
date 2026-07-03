"""Nutanix Files / Data Lens parser — file-access audit events.

Nutanix Files (Nutanix Unified Storage) audits SMB/NFS file activity and streams
it to a **partner server** (`usage_type: NOTIFICATION`, `vendor_name: syslog`,
TCP/UDP :1468) — the same event stream **Data Lens** analyses for ransomware and
anomaly detection. Each audit record carries a documented file **operation** and
the who/what/where of the access:

  * **operation** — ``FILE_CREATE`` / ``FILE_DELETE`` / ``FILE_READ`` /
    ``FILE_WRITE`` / ``DIRECTORY_CREATE`` / ``DIRECTORY_DELETE`` / ``RENAME`` /
    ``SECURITY`` (permission change)
  * **object** — the file/directory path (and the old path, for a rename)
  * **user** (``DOMAIN\\user``), **client IP**, **share / export**, **protocol**
    (SMB / NFS), **status**, and a microsecond **timestamp**

Records arrive as JSON — a partner-server notification (bare object / array /
NDJSON), a File-Analytics / Data-Lens export, or a JSON payload inside a syslog
envelope (``<PRI>ts host tag: {json}``). The exact on-wire key *spelling* varies
by Files version, so the mapper folds case + underscores and accepts the common
snake_case and camelCase names for each field; the full record is kept in ``raw``.

The **operation** is normalized into ``action`` (create / delete / read / write /
rename / security-change …) so detection rules and the mass-delete / ransomware
correlations match regardless of the source's key spelling.
"""
from __future__ import annotations

import re
from typing import Any, Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, iter_json_records, json_or_none, parse_ts

_SEVERITY = {0: "emergency", 1: "alert", 2: "critical", 3: "error",
             4: "warning", 5: "notice", 6: "informational", 7: "debug"}

_PRI = re.compile(r"^<(\d{1,3})>")
# Syslog envelope (<PRI> already stripped): ISO-8601 or BSD ts, host, tag ':'.
_HDR = re.compile(
    r"^(?:(?P<iso>\d{4}-\d{2}-\d{2}T\S+)|"
    r"(?P<bsd>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}))\s+"
    r"(?P<host>\S+)\s+(?P<tag>[A-Za-z][\w.\-]*)(?:\[\d+\])?:\s*(?P<payload>.*)$")

# operation enum -> normalized action.
_OP = {
    "FILE_CREATE": "create", "FILE_DELETE": "delete", "FILE_READ": "read",
    "FILE_WRITE": "write", "FILE_OPEN": "open", "FILE_CLOSE": "close",
    "DIRECTORY_CREATE": "dir-create", "DIRECTORY_DELETE": "dir-delete",
    "MKDIR": "dir-create", "RMDIR": "dir-delete",
    "RENAME": "rename", "MOVE": "rename",
    "SECURITY": "security-change", "SET_SECURITY": "security-change",
    "PERMISSION_CHANGED": "security-change", "SETATTR": "set-attr",
    "SYMLINK_CREATE": "symlink-create",
}
# Fallback: substring -> normalized action, for a spelling we didn't enumerate.
_OP_CONTAINS = (("delete", "delete"), ("create", "create"), ("write", "write"),
                ("read", "read"), ("rename", "rename"), ("move", "rename"),
                ("security", "security-change"), ("permission", "security-change"),
                ("setattr", "set-attr"))

_DENY = {"access_denied", "permission_denied", "denied", "failure", "failed",
         "error", "no_access", "notpermitted", "eacces"}
_VENDOR = "nutanix"


def _norm_op(value: Any) -> Optional[str]:
    if value in (None, ""):
        return None
    key = str(value).strip().upper().replace("-", "_").replace(" ", "_")
    if key in _OP:
        return _OP[key]
    low = str(value).strip().lower()
    for token, norm in _OP_CONTAINS:
        if token in low:
            return norm
    return low or None


def _index(rec: dict) -> dict[str, Any]:
    """Case/underscore-insensitive key index (snake_case + camelCase both resolve)."""
    low: dict[str, Any] = {}
    for k, v in rec.items():
        lk = str(k).lower()
        low.setdefault(lk, v)
        low.setdefault(lk.replace("_", ""), v)
    return low


def parse(content: str) -> Iterator[NormalizedEvent]:
    text = content.strip()
    if text[:1] in ("{", "["):
        for rec in iter_json_records(content, "audit_records", "auditRecords",
                                     "events", "entities", "data", "records"):
            ev = _from_record(rec, None, None)
            if ev is not None:
                yield ev
        return

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        env_ts = host = None
        body = line
        pm = _PRI.match(line)
        if pm:
            body = line[pm.end():].lstrip()
        hm = _HDR.match(body)
        if hm:
            env_ts = hm.group("iso") or hm.group("bsd")
            host = hm.group("host")
            body = hm.group("payload")
        rec = json_or_none(body.strip())
        if isinstance(rec, dict):
            ev = _from_record(rec, env_ts, host)
            if ev is not None:
                yield ev


def _from_record(rec: dict, env_ts: Optional[str],
                 env_host: Optional[str]) -> Optional[NormalizedEvent]:
    if not isinstance(rec, dict):
        return None
    low = _index(rec)

    def g(*names: str) -> Any:
        for n in names:
            v = low.get(n.lower())
            if v not in (None, ""):
                return v
        return None

    operation = g("operation", "audit_type", "event_type", "operationtype",
                  "file_operation", "optype", "action")
    alert_type = g("alerttype", "anomalytype", "threattype", "detectiontype")
    is_ransomware = _looks_ransomware(alert_type) or _looks_ransomware(g("category"))

    path = g("objectname", "object", "objectpath", "path", "filepath",
             "file_path", "name", "target")
    old_path = g("oldobjectname", "oldpath", "oldname", "sourcepath",
                 "sourcename", "previouspath", "from")
    user = g("username", "userwithdomain", "user", "actor", "principal",
             "useraccount", "account")
    client_ip = g("clientip", "ipaddress", "sourceip", "remoteip", "clientaddress")
    share = g("sharename", "share", "exportname", "export", "sharepath")
    protocol = g("protocoltype", "protocol", "proto", "accessprotocol")
    status = g("status", "result", "operationstatus", "auditstatus", "resultcode")
    server = g("fileservername", "fileserver", "server", "fsvm", "hostname", "host")
    ts = g("audittimestampusecs", "eventtimeusecs", "eventtimestamp",
           "audit_timestamp", "operationdate", "timestamp", "time", "eventdate")

    action = _norm_op(operation)
    if is_ransomware or (action is None and alert_type):
        return _ransomware_alert(rec, low, g, user, client_ip, share, server,
                                 parse_ts(ts) or parse_ts(env_ts), env_host)

    denied = str(status).strip().lower() in _DENY if status else False
    severity = "warning" if denied else "informational"

    if action == "rename" and old_path and path:
        body = f"renamed {old_path} -> {path}"
    elif action and path:
        body = f"{action} {path}"
    else:
        body = path or (str(operation) if operation else None)
    suffix = []
    if status:
        suffix.append(f"[{status}]")
    if protocol:
        suffix.append(f"via {protocol}")
    message = " ".join(str(x) for x in ([user, body] + suffix) if x) or None

    return NormalizedEvent(
        event_time=parse_ts(ts) or parse_ts(env_ts),
        vendor=_VENDOR,
        product="files",
        log_type="file-audit",
        severity=severity,
        action=action,
        src_ip=clean_ip(client_ip),
        protocol=(str(protocol).lower() if protocol else None),
        app=(str(share) if share else "nutanix-files"),
        user_name=(str(user) if user else None),
        host_name=first(server, env_host),
        rule_name=(str(path) if path else None),
        message=(message[:2000] if message else None),
        raw=rec,
    )


def _looks_ransomware(value: Any) -> bool:
    return bool(value) and "ransom" in str(value).lower()


def _ransomware_alert(rec: dict, low: dict, g, user, client_ip, share, server,
                      when, env_host) -> NormalizedEvent:
    """A Data Lens ransomware / anomaly alert riding the same audit stream."""
    detail = g("message", "description", "defaultmsg", "details", "reason",
               "alerttype", "anomalytype")
    count = g("affectedfiles", "affectedfilecount", "filecount", "impactedfiles")
    parts = ["Data Lens ransomware/anomaly alert"]
    if detail:
        parts.append(str(detail))
    if count:
        parts.append(f"({count} files affected)")
    return NormalizedEvent(
        event_time=when,
        vendor=_VENDOR,
        product="data-lens",
        log_type="ransomware-alert",
        severity="critical",
        action="ransomware",
        src_ip=clean_ip(client_ip),
        app=(str(share) if share else "nutanix-files"),
        user_name=(str(user) if user else None),
        host_name=first(server, env_host),
        rule_name=(str(g("objectname", "path", "policyname")) if
                   g("objectname", "path", "policyname") else None),
        message=" ".join(parts)[:2000],
        raw=rec,
    )
