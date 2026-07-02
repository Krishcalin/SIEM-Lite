"""Agentless response playbooks.

A playbook matches certain alerts (by rule id, minimum severity, and/or MITRE
technique) and runs an action. Actions are **agentless**: a structured webhook
POST to your automation / SOAR / firewall / IAM endpoint (`RESPONSE_WEBHOOK_URL`)
carrying the intent (e.g. ``block_ip`` + the target), or a ``log`` action that
only records. Every execution is written to ``response_actions`` as an audit
trail. A background worker thread processes alerts off the ingest path.

Playbook YAML (under ``playbooks/``)::

    title: Block brute-force source IP
    id: pb-block-bruteforce
    match: { rule_id: [lo-corr-bruteforce-logon], min_level: high }
    action: { type: block_ip, target: src_ip }
    revert_after: 600        # seconds (reserved for future auto-revert)
"""
from __future__ import annotations

import json
import logging
import queue
import threading
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import yaml

from .. import db
from ..config import settings
from ..notify.channels import meets_min   # reuse the severity ordering

log = logging.getLogger("logocean")
_SENTINEL = object()

_ALERT_FIELDS = ("id", "rule_id", "rule_title", "level", "techniques", "src_ip",
                 "dst_ip", "user_name", "host_name", "message")


@dataclass
class Playbook:
    id: str
    title: str
    description: str
    rule_ids: set            # match any of these rule ids (empty = any rule)
    min_level: str
    techniques: set          # match any of these techniques (empty = any)
    action_type: str         # block_ip | disable_user | isolate_host | log | ...
    target_field: Optional[str]
    revert_after: Optional[int]
    source: str = ""
    enabled: bool = True


def load_playbooks(playbooks_dir) -> list[Playbook]:
    out: list[Playbook] = []
    base = Path(playbooks_dir)
    if not base.is_dir():
        return out
    for path in sorted(list(base.glob("*.yml")) + list(base.glob("*.yaml"))):
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if not isinstance(doc, dict) or "action" not in doc:
                continue
            m = doc.get("match") or {}
            a = doc.get("action") or {}
            rid = m.get("rule_id") or []
            tech = m.get("techniques") or []
            out.append(Playbook(
                id=str(doc.get("id") or doc.get("title") or path.name),
                title=str(doc.get("title") or "untitled"),
                description=str(doc.get("description") or ""),
                rule_ids=set(rid if isinstance(rid, list) else [rid]),
                min_level=str(m.get("min_level") or "informational").lower(),
                techniques={str(t).upper() for t in (tech if isinstance(tech, list) else [tech])},
                action_type=str(a.get("type") or "log").lower(),
                target_field=a.get("target"),
                revert_after=a.get("revert_after") or doc.get("revert_after"),
                source=path.name))
    return out


def matches(pb: Playbook, alert: dict) -> bool:
    if not pb.enabled:
        return False
    if pb.rule_ids and alert.get("rule_id") not in pb.rule_ids:
        return False
    if not meets_min(alert.get("level"), pb.min_level):
        return False
    if pb.techniques and not (pb.techniques & set(alert.get("techniques") or [])):
        return False
    return True


def _payload(pb: Playbook, alert: dict, target_value) -> dict:
    return {"playbook_id": pb.id, "action": pb.action_type,
            "target_field": pb.target_field, "target": target_value,
            "alert": {k: alert.get(k) for k in _ALERT_FIELDS}}


def execute(pb: Playbook, alert: dict) -> dict:
    """Run a playbook's action and return the audit record (does not write it)."""
    target_value = alert.get(pb.target_field) if pb.target_field else None
    revert_at = None
    if pb.revert_after:
        revert_at = datetime.now(timezone.utc) + timedelta(seconds=int(pb.revert_after))
    rec = {"alert_id": alert.get("id"), "playbook_id": pb.id,
           "action_type": pb.action_type,
           "target": str(target_value) if target_value is not None else None,
           "status": "skipped", "detail": None, "revert_at": revert_at}

    if pb.action_type == "log":
        rec["status"], rec["detail"] = "success", "recorded"
        return rec
    url = settings.response_webhook_url
    if not url:
        rec["detail"] = "no RESPONSE_WEBHOOK_URL configured"
        return rec
    try:
        data = json.dumps(_payload(pb, alert, target_value), default=str).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, method="POST", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10):  # nosec B310 — operator-configured URL
            pass
        rec["status"], rec["detail"] = "success", "posted to automation endpoint"
    except Exception as exc:  # noqa: BLE001
        rec["status"], rec["detail"] = "failed", str(exc)[:300]
    return rec


class ResponseEngine:
    def __init__(self, playbooks: list[Playbook], maxsize: int):
        self.playbooks = playbooks
        self._q: queue.Queue = queue.Queue(maxsize=maxsize)
        self._thread: Optional[threading.Thread] = None
        self.executed = 0
        self.failed = 0
        self.dropped = 0

    def submit(self, alert: dict) -> None:
        try:
            self._q.put_nowait(alert)
        except queue.Full:
            self.dropped += 1

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="response", daemon=True)
        self._thread.start()
        log.info("response engine started: %d playbook(s)", len(self.playbooks))

    def stop(self) -> None:
        self._q.put(_SENTINEL)
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def _run(self) -> None:
        while True:
            item = self._q.get()
            if item is _SENTINEL:
                break
            for pb in self.playbooks:
                if not matches(pb, item):
                    continue
                try:
                    rec = execute(pb, item)
                    db.insert_response_action(rec)
                    self.executed += 1
                    if rec["status"] == "failed":
                        self.failed += 1
                except Exception:  # noqa: BLE001
                    self.failed += 1
                    log.exception("response playbook %s failed", pb.id)

    def stats(self) -> dict:
        return {"executed": self.executed, "failed": self.failed,
                "dropped": self.dropped, "queued": self._q.qsize()}


_engine: Optional[ResponseEngine] = None


def get_engine() -> Optional[ResponseEngine]:
    return _engine


def set_engine(e: Optional[ResponseEngine]) -> None:
    global _engine
    _engine = e


def submit_alerts(alerts: list[dict]) -> None:
    e = _engine
    if e is None or not alerts:
        return
    for a in alerts:
        e.submit(a)


def build_engine(playbooks_dir) -> ResponseEngine:
    return ResponseEngine(load_playbooks(playbooks_dir), settings.response_queue_max)
