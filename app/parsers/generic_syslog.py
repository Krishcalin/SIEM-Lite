"""Generic syslog parser — RFC 3164 (BSD) and RFC 5424.

A catch-all for plain syslog lines that aren't a more specific vendor format.
The leading ``<PRI>`` (facility*8 + severity) is decoded into facility/severity
names, then the header (timestamp / host / app / pid) and message. Both layouts
are handled::

    <36>1 2026-06-15T10:00:00Z host app 2143 ID47 - message text     (RFC 5424)
    <85>Jun 15 10:01:12 host app[2210]: message text                 (RFC 3164)

Lines without a recognizable header are kept whole as the message so nothing is
dropped. The full parsed header set is stored in ``raw``.
"""
from __future__ import annotations

import re
from typing import Iterator, Optional

from ..models import NormalizedEvent
from ..util import parse_ts

_SEVERITY = {0: "emergency", 1: "alert", 2: "critical", 3: "error",
             4: "warning", 5: "notice", 6: "informational", 7: "debug"}
_FACILITY = {0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 5: "syslog",
             6: "lpr", 7: "news", 8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
             12: "ntp", 13: "audit", 14: "console", 15: "solaris-cron",
             16: "local0", 17: "local1", 18: "local2", 19: "local3",
             20: "local4", 21: "local5", 22: "local6", 23: "local7"}

_PRI = re.compile(r"^<(\d{1,3})>")
_RFC5424 = re.compile(
    r"^(?P<version>\d{1,2})\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+"
    r"(?P<pid>\S+)\s+(?P<msgid>\S+)\s+(?P<rest>.*)$")
_RFC3164 = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<rest>.*)$")
_TAG = re.compile(r"^(?P<tag>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
_SD = re.compile(r"^(?:-|(?:\[[^\]]*\])+)\s*")   # RFC 5424 structured-data block


def _nz(v: Optional[str]) -> Optional[str]:
    return v if v not in (None, "", "-") else None


def parse(content: str) -> Iterator[NormalizedEvent]:
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        pri = facility = severity = None
        body = line
        pm = _PRI.match(line)
        if pm:
            pri = int(pm.group(1))
            facility = _FACILITY.get(pri // 8)
            severity = _SEVERITY.get(pri % 8)
            body = line[pm.end():].lstrip()

        ts = host = app = procid = msgid = sd = None
        msg = body

        m5 = _RFC5424.match(body)
        if m5 and not m5.group("ts")[:1].isalpha():
            ts = m5.group("ts")
            host, app = _nz(m5.group("host")), _nz(m5.group("app"))
            procid, msgid = _nz(m5.group("pid")), _nz(m5.group("msgid"))
            rest = m5.group("rest")
            sdm = _SD.match(rest)
            if sdm:
                sd = _nz(rest[:sdm.end()].strip())
                msg = rest[sdm.end():].strip()
            else:
                msg = rest.strip()
        else:
            m3 = _RFC3164.match(body)
            if m3:
                ts, host = m3.group("ts"), _nz(m3.group("host"))
                rest = m3.group("rest")
                tm = _TAG.match(rest)
                if tm:
                    app, procid, msg = _nz(tm.group("tag")), _nz(tm.group("pid")), tm.group("msg")
                else:
                    msg = rest

        raw = {"pri": pri, "facility": facility, "severity": severity,
               "timestamp": ts, "host": host, "app": app, "procid": procid,
               "msgid": msgid, "structured_data": sd, "message": msg, "line": line}

        yield NormalizedEvent(
            event_time=parse_ts(ts),
            vendor="syslog",
            product=None,
            log_type=facility,
            severity=severity,
            host_name=host,
            app=app,
            rule_name=msgid,
            message=msg or None,
            raw=raw,
        )
