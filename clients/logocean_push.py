"""Tiny client for pushing logs / findings into LogOcean's ingest API.

Copy this into another tool (e.g. an RHEL/Windows/SBOM/AWS audit scanner) to feed
its output to LogOcean agentlessly — no agent, just an HTTP POST. Stdlib only.

    from logocean_push import push

    findings = [{"timestamp": "...", "severity": "high", "rule.name": "CIS-1.1",
                 "host.name": "web-1", "message": "World-writable file /etc/..."}]
    push("http://logocean:8000", "lo_...", findings)   # NDJSON -> generic_json

Create the API key in LogOcean's Admin page. JSON/dict records are sent as NDJSON
and parsed by the generic_json catch-all (map your fields onto ECS-ish names like
source.ip / event.action / user.name / host.name for best normalization), or pass
fmt="<format key>" for a specific parser. Raw text (e.g. a syslog blob) is sent
as-is with fmt="auto" or an explicit format.
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Iterable, Optional, Union


def push(base_url: str, api_key: str,
         data: Union[str, dict, Iterable[dict]],
         fmt: str = "auto", filename: Optional[str] = None,
         timeout: int = 30) -> dict:
    """POST `data` to {base_url}/api/v1/ingest and return the JSON result.

    `data` may be raw text, a single dict, or an iterable of dicts (sent as NDJSON).
    """
    if isinstance(data, str):
        body = data.encode("utf-8")
    elif isinstance(data, dict):
        body = json.dumps(data).encode("utf-8")
    else:
        body = "\n".join(json.dumps(r) for r in data).encode("utf-8")

    qs = {"format": fmt}
    if filename:
        qs["filename"] = filename
    url = f"{base_url.rstrip('/')}/api/v1/ingest?" + urllib.parse.urlencode(qs)
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "X-API-Key": api_key})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))
