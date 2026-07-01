"""Windows Security Event Log parser (CSV or JSON export).

Accepts the two shapes analysts produce without extra tooling:
  * **JSON** — ``Get-WinEvent -LogName Security | ConvertTo-Json`` (array, single
    object, or NDJSON).
  * **CSV** — ``Get-WinEvent … | Export-Csv`` or Event Viewer "Save All Events As CSV".

The security-relevant detail (target account, logon type, source IP) lives in the
human-readable ``Message`` for both shapes, so we resolve top-level fields by
candidate name and extract the rest from the message text. The full record is
kept in ``raw``.
"""
from __future__ import annotations

import csv
import io
import json
import re
from typing import Any, Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, json_or_none, parse_ts, to_int

# Event ID -> short action label (the security-relevant ones).
_ACTION = {
    4624: "logon", 4625: "failed-logon", 4634: "logoff", 4647: "logoff",
    4648: "explicit-logon", 4672: "special-logon", 4688: "process-create",
    4689: "process-exit", 4720: "user-created", 4722: "user-enabled",
    4725: "user-disabled", 4726: "user-deleted", 4740: "account-locked",
    4768: "kerberos-tgt", 4769: "kerberos-service", 4776: "credential-validation",
    1102: "audit-log-cleared", 4719: "audit-policy-changed",
}
_ACCT = re.compile(r"Account Name:\s*([^\r\n\t]+)")
_DOMAIN = re.compile(r"Account Domain:\s*([^\r\n\t]+)")
_SRCADDR = re.compile(r"Source Network Address:\s*([0-9A-Fa-f:.]+)")
_LOGONTYPE = re.compile(r"Logon Type:\s*(\d+)")
_WKSTN = re.compile(r"Workstation Name:\s*([^\r\n\t]+)")


def _g(rec: dict, *names: str) -> Optional[Any]:
    low = {str(k).strip().lower(): v for k, v in rec.items()}
    for n in names:
        v = low.get(n.lower())
        if v not in (None, ""):
            return v
    return None


def _last(values: list[str]) -> Optional[str]:
    """Last meaningful value (Windows lists the target account after the subject)."""
    for v in reversed(values):
        v = v.strip()
        if v and v not in ("-", "NULL SID"):
            return v
    return None


def _iter_records(content: str) -> Iterator[dict]:
    text = content.strip()
    if text[:1] in ("{", "["):
        obj = json_or_none(text)
        if obj is not None:
            if isinstance(obj, list):
                yield from (r for r in obj if isinstance(r, dict))
            elif isinstance(obj, dict):
                yield obj
            return
        for line in text.splitlines():          # NDJSON fallback
            line = line.strip().rstrip(",")
            if not line:
                continue
            r = json_or_none(line)
            if isinstance(r, dict):
                yield r
        return
    for row in csv.DictReader(io.StringIO(content)):
        if any((v or "").strip() for v in row.values()):
            yield {k: v for k, v in row.items() if k}


def parse(content: str) -> Iterator[NormalizedEvent]:
    for rec in _iter_records(content):
        msg = str(_g(rec, "message", "description") or "")
        event_id = to_int(_g(rec, "id", "event id", "eventid"))

        user = _last(_ACCT.findall(msg))
        domain = _last(_DOMAIN.findall(msg))
        if user and domain and "\\" not in user:
            user = f"{domain}\\{user}"
        src_ip = clean_ip(m.group(1)) if (m := _SRCADDR.search(msg)) else None
        summary = next((ln.strip() for ln in re.split(r"[\r\n]", msg) if ln.strip()), None)

        yield NormalizedEvent(
            event_time=parse_ts(_g(rec, "timecreated", "date and time", "date", "time created")),
            vendor="microsoft",
            product="windows",
            log_type="security",
            severity=(str(_g(rec, "leveldisplayname", "level") or "").lower() or None),
            action=_ACTION.get(event_id) if event_id else None,
            src_ip=src_ip,
            user_name=user,
            host_name=_g(rec, "machinename", "computername", "computer"),
            rule_name=f"Event {event_id}" if event_id else _g(rec, "providername", "source"),
            message=first(summary, _g(rec, "providername", "source")),
            raw=rec,
        )
