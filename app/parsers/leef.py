"""Generic LEEF (Log Event Extended Format) parser.

LEEF is IBM QRadar's structured log format and the format **Tripwire Log Center**
(and Tripwire Enterprise via the Event Sender) uses to forward File-Integrity,
correlation and security events to a SIEM. Many other products emit it too
(Juniper, Check Point, Kaspersky, McAfee, NXLog, ...). One event per line:

    [optional syslog header] LEEF:Version|Vendor|Product|Version|EventID|[Delim]|attrs

The header is pipe-delimited (a literal pipe inside a field is escaped ``\\|``).
The trailing ``attrs`` is a list of ``key=value`` pairs:

  * **LEEF 1.0** — 5 header fields; attributes are **tab**-separated.
  * **LEEF 2.0** — a 6th header field names the attribute delimiter, a single
    character (e.g. ``^``) or a hex value (``x09`` / ``0x09`` for tab, ``x5E``
    for caret). An empty 6th field means tab.

If the event arrives over syslog, the syslog header (``<PRI>timestamp host``)
precedes the LEEF header, separated by a single space — so LEEF-over-syslog is
picked up on the online (syslog receiver / API) path too. We keep the real
device vendor/product on the normalized event, fall back to the syslog header's
host/time when the payload omits them, and stash the full header + parsed
attributes in ``raw`` so nothing is lost.
"""
from __future__ import annotations

import re
from typing import Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, parse_ts, to_int

_LEEF_START = re.compile(r"LEEF:\s*(\d+(?:\.\d+)?)\s*\|", re.IGNORECASE)
_UNESC_PIPE = re.compile(r"(?<!\\)\|")
# Fallback attribute-key boundary: start-of-string or whitespace, a key token, '='.
# Used only when the declared delimiter is absent (e.g. tabs mangled to spaces
# by a syslog relay), mirroring the CEF extension parser's tolerance.
_ATTR_KEY = re.compile(r"(?:^|\s)([A-Za-z][A-Za-z0-9_.\-]*)=")
_PRI = re.compile(r"^<\d{1,3}>")
_LEEF_VER_DIGIT = re.compile(r"^\d{1,2}\s+")   # RFC 5424 version digit before the timestamp

# Numeric IANA protocol numbers seen in firewall LEEF -> names.
_PROTO = {"1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp",
          "58": "ipv6-icmp"}


def _unescape_hdr(s: str) -> str:
    return s.replace("\\|", "|").replace("\\\\", "\\")


def _resolve_delim(spec: str) -> str:
    """LEEF 2.0 delimiter field -> the actual separator char (tab if unspecified)."""
    s = (spec or "").strip()
    if not s:
        return "\t"
    m = re.fullmatch(r"0?x([0-9A-Fa-f]{1,4})", s)   # hex: x09 / 0x09 / x5E
    if m:
        try:
            return chr(int(m.group(1), 16))
        except (ValueError, OverflowError):
            return "\t"
    return s[0]


def _boundary_split(attrs: str) -> list[str]:
    """Split on ``<space>key=`` boundaries — tolerant fallback for LEEF whose
    tab separators were flattened to spaces in transit."""
    keys = list(_ATTR_KEY.finditer(attrs))
    if len(keys) <= 1:
        return [attrs]
    out = []
    for i, m in enumerate(keys):
        start = m.start(1)
        end = keys[i + 1].start(1) if i + 1 < len(keys) else len(attrs)
        out.append(attrs[start:end].strip())
    return out


def _parse_attrs(attrs: str, delim: str) -> dict[str, str]:
    tokens = attrs.split(delim) if (delim and delim in attrs) else _boundary_split(attrs)
    out: dict[str, str] = {}
    for tok in tokens:
        if "=" in tok:
            key, _, val = tok.partition("=")
            key = key.strip()
            if key:
                out[key] = val.strip()
    return out


def _sev_name(value: Optional[str]) -> Optional[str]:
    """LEEF ``sev`` is 1-10 (10 highest). Map the numeric scale to a name; pass
    through a word severity."""
    if value is None:
        return None
    s = str(value).strip()
    if s.isdigit():
        n = int(s)
        return "low" if n <= 3 else "medium" if n <= 6 else "high" if n <= 8 else "very-high"
    return s.lower() or None


def _syslog_prefix(prefix: str) -> tuple[Optional[str], Optional[str]]:
    """Best-effort (host, time_str) from a syslog header preceding the LEEF one.
    The host is the token right before the LEEF header; the timestamp is what sits
    between the ``<PRI>`` and the host (RFC 3164 or 5424)."""
    s = _PRI.sub("", prefix.strip()).strip()
    if not s:
        return None, None
    toks = s.split()
    if not toks:
        return None, None
    host = toks[-1]
    time_str = _LEEF_VER_DIGIT.sub("", " ".join(toks[:-1]).strip()).strip()
    return host, (time_str or None)


def parse(content: str) -> Iterator[NormalizedEvent]:
    for line in content.splitlines():
        m = _LEEF_START.search(line)
        if not m:
            continue
        syslog_host, syslog_time = _syslog_prefix(line[:m.start()])
        parts = _UNESC_PIPE.split(line[m.start():])
        ver = parts[0].split(":", 1)[1].strip() if ":" in parts[0] else ""

        if ver.startswith("2"):
            if len(parts) < 7:
                continue
            delim_spec = parts[5]
            delim = _resolve_delim(delim_spec)
            attrs_raw = "|".join(parts[6:])
        else:
            if len(parts) < 6:
                continue
            delim_spec = ""
            delim = "\t"
            attrs_raw = "|".join(parts[5:])

        vendor = _unescape_hdr(parts[1]).strip()
        product = _unescape_hdr(parts[2]).strip()
        dev_ver = _unescape_hdr(parts[3]).strip()
        event_id = _unescape_hdr(parts[4]).strip()
        attrs = _parse_attrs(attrs_raw, delim)
        low = {k.lower(): v for k, v in attrs.items()}

        def g(*names: str) -> Optional[str]:
            for n in names:
                v = low.get(n.lower())
                if v not in (None, ""):
                    return v
            return None

        proto_raw = g("proto", "protocol")
        protocol = _PROTO.get(proto_raw, proto_raw.lower()) if proto_raw else None

        sb, db = to_int(g("srcbytes", "bytesin", "in")), to_int(g("dstbytes", "bytesout", "out"))
        bytes_total = (sb or 0) + (db or 0) if (sb or db) else to_int(g("totalbytes", "bytes"))

        yield NormalizedEvent(
            event_time=parse_ts(first(g("devTime"), syslog_time)),
            vendor=vendor.lower() or "leef",
            product=product.lower() or None,
            log_type=str(first(g("cat"), event_id) or "leef").lower(),
            severity=_sev_name(g("sev", "severity")),
            action=g("action", "act"),
            src_ip=clean_ip(g("src", "srcIP", "sourceAddress")),
            dst_ip=clean_ip(g("dst", "dstIP", "destinationAddress")),
            src_port=to_int(g("srcPort", "spt", "sourcePort")),
            dst_port=to_int(g("dstPort", "dpt", "destinationPort")),
            protocol=protocol,
            app=g("appName", "application", "app"),
            user_name=first(g("usrName", "accountName", "user", "suser", "identUserName")),
            host_name=first(g("identHostName", "Hostname", "host", "dhost", "shost"),
                            syslog_host),
            rule_name=first(g("policy", "rule", "ruleName"), event_id or None),
            bytes_total=bytes_total,
            message=first(g("msg", "Message"), event_id),
            raw={"leef_version": ver, "device_vendor": vendor, "device_product": product,
                 "device_version": dev_ver, "event_id": event_id, "delimiter": delim_spec,
                 "attributes": attrs, "syslog_host": syslog_host, "syslog_time": syslog_time},
        )
