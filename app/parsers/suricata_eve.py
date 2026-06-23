"""Suricata EVE JSON parser (IDS/IPS).

Suricata's ``eve.json`` is NDJSON (one JSON object per line); manual exports may
also be a JSON array. Each record has an ``event_type`` (alert / flow / dns /
http / tls / fileinfo / …); we normalize the network 5-tuple and lift the most
useful per-type detail into the message, keeping the whole record in ``raw``.
"""
from __future__ import annotations

import json
from typing import Any, Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, parse_ts, to_int

# Suricata alert severity: 1 = high, 2 = medium, 3 = low.
_SEV = {1: "high", 2: "medium", 3: "low"}


def _iter_records(content: str) -> Iterator[dict]:
    text = content.strip()
    if not text:
        return
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        obj = None
    if obj is not None:
        if isinstance(obj, list):
            yield from (r for r in obj if isinstance(r, dict))
        elif isinstance(obj, dict):
            yield obj
        return
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict):
            yield rec


def _message(etype: str, rec: dict) -> Optional[str]:
    if etype == "alert" and isinstance(rec.get("alert"), dict):
        a = rec["alert"]
        sig, cat = a.get("signature"), a.get("category")
        return f"{sig} ({cat})" if sig and cat else (sig or cat)
    if etype == "dns" and isinstance(rec.get("dns"), dict):
        d = rec["dns"]
        return f"DNS {d.get('type', '')} {d.get('rrname', '')}".strip()
    if etype == "http" and isinstance(rec.get("http"), dict):
        h = rec["http"]
        return f"HTTP {h.get('http_method', '')} {h.get('hostname', '')}{h.get('url', '')}".strip()
    if etype == "tls" and isinstance(rec.get("tls"), dict):
        return f"TLS {rec['tls'].get('sni', '')}".strip()
    return etype or None


def parse(content: str) -> Iterator[NormalizedEvent]:
    for rec in _iter_records(content):
        etype = str(rec.get("event_type") or "event").lower()
        alert = rec.get("alert") if isinstance(rec.get("alert"), dict) else {}
        flow = rec.get("flow") if isinstance(rec.get("flow"), dict) else {}
        proto = rec.get("proto")

        bytes_total: Optional[int] = None
        ts, tc = to_int(flow.get("bytes_toserver")), to_int(flow.get("bytes_toclient"))
        if ts is not None or tc is not None:
            bytes_total = (ts or 0) + (tc or 0)

        yield NormalizedEvent(
            event_time=parse_ts(rec.get("timestamp")),
            vendor="suricata",
            product="eve",
            log_type=etype,
            severity=_SEV.get(to_int(alert.get("severity"))) if alert else None,
            action=alert.get("action") if alert else None,
            src_ip=clean_ip(rec.get("src_ip")),
            dst_ip=clean_ip(rec.get("dest_ip")),
            src_port=to_int(rec.get("src_port")),
            dst_port=to_int(rec.get("dest_port")),
            protocol=str(proto).lower() if proto else None,
            app=rec.get("app_proto") if rec.get("app_proto") not in (None, "", "failed") else None,
            host_name=None,
            rule_name=alert.get("signature") if alert else None,
            bytes_total=bytes_total,
            message=_message(etype, rec),
            raw=rec,
        )
