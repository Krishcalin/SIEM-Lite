"""Generic CEF (Common Event Format) parser.

CEF is emitted by a wide range of security products (ArcSight SmartConnectors,
many firewalls, WAFs, proxies, AV/EDR). One event per line:

    [optional syslog header] CEF:Version|Vendor|Product|Version|SigID|Name|Severity|extension

The seven header fields are pipe-delimited (a literal pipe inside a field is
escaped as ``\\|``). The extension is space-separated ``key=value`` pairs (a
literal ``=`` inside a value is escaped as ``\\=``). We keep the real device
vendor/product on the normalized event and stash the full header + parsed
extension in ``raw`` so nothing is lost.
"""
from __future__ import annotations

import re
from typing import Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, parse_ts, to_int

_CEF_START = re.compile(r"CEF:\s*\d+\s*\|", re.IGNORECASE)
_UNESC_PIPE = re.compile(r"(?<!\\)\|")
# Extension key boundary: start-of-string or whitespace, then a key token, then '='.
_EXT_KEY = re.compile(r"(?:^|\s)([A-Za-z][A-Za-z0-9_.\-]*)=")


def _unescape_hdr(s: str) -> str:
    return s.replace("\\|", "|").replace("\\\\", "\\")


def _unescape_ext(s: str) -> str:
    return (s.replace("\\=", "=").replace("\\n", "\n")
             .replace("\\r", "\r").replace("\\\\", "\\"))


def _parse_extension(ext: str) -> dict[str, str]:
    out: dict[str, str] = {}
    matches = list(_EXT_KEY.finditer(ext))
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(ext)
        out[m.group(1)] = _unescape_ext(ext[start:end].strip())
    return out


def _sev_name(value: Optional[str]) -> Optional[str]:
    """CEF severity is 0–10 (or a word). Map the numeric scale to a name."""
    if value is None:
        return None
    s = str(value).strip()
    if s.isdigit():
        n = int(s)
        return "low" if n <= 3 else "medium" if n <= 6 else "high" if n <= 8 else "very-high"
    return s.lower() or None


def parse(content: str) -> Iterator[NormalizedEvent]:
    for line in content.splitlines():
        m = _CEF_START.search(line)
        if not m:
            continue
        body = line[m.start():]
        parts = _UNESC_PIPE.split(body, 7)
        if len(parts) < 7:
            continue
        cef_ver = parts[0].split(":", 1)[1].strip() if ":" in parts[0] else ""
        vendor = _unescape_hdr(parts[1]).strip()
        product = _unescape_hdr(parts[2]).strip()
        dev_ver = _unescape_hdr(parts[3]).strip()
        sig_id = _unescape_hdr(parts[4]).strip()
        name = _unescape_hdr(parts[5]).strip()
        hdr_sev = parts[6].strip()
        ext = _parse_extension(parts[7]) if len(parts) >= 8 else {}

        def g(*names: str) -> Optional[str]:
            for n in names:
                v = ext.get(n)
                if v not in (None, ""):
                    return v
            return None

        bytes_in, bytes_out = to_int(g("in")), to_int(g("out"))
        bytes_total = (bytes_in or 0) + (bytes_out or 0) if (bytes_in or bytes_out) else to_int(g("bytes"))
        proto = g("proto", "transportProtocol")

        yield NormalizedEvent(
            event_time=parse_ts(first(g("rt", "deviceReceiptTime"), g("end"), g("start"))),
            vendor=vendor.lower() or "cef",
            product=product.lower() or None,
            log_type=str(first(g("cat", "deviceEventCategory"), sig_id) or "cef").lower(),
            severity=_sev_name(first(g("severity"), hdr_sev)),
            action=g("act", "deviceAction"),
            src_ip=clean_ip(g("src", "sourceAddress")),
            dst_ip=clean_ip(g("dst", "destinationAddress")),
            src_port=to_int(g("spt", "sourcePort")),
            dst_port=to_int(g("dpt", "destinationPort")),
            protocol=proto.lower() if proto else None,
            app=g("app", "applicationProtocol"),
            user_name=first(g("suser", "sourceUserName"), g("duser", "destinationUserName")),
            host_name=first(g("shost", "sourceHostName"), g("dhost", "destinationHostName"),
                            g("dvchost", "deviceHostName")),
            rule_name=name or sig_id or None,
            bytes_total=bytes_total,
            message=first(g("msg"), name),
            raw={"cef_version": cef_ver, "device_vendor": vendor, "device_product": product,
                 "device_version": dev_ver, "signature_id": sig_id, "name": name,
                 "severity": hdr_sev, "extension": ext},
        )
