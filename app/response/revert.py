# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Stateful auto-revert for time-boxed response actions.

A playbook with ``revert_after`` takes a *temporary* containment action — block
an IP for 10 minutes, disable a user for an hour. ``engine.execute`` stamps the
action's ``revert_at`` (now + revert_after) when it runs. This module closes the
loop: a background scheduler periodically finds actions whose ``revert_at`` has
passed and fires the **inverse** action (``block_ip`` -> ``unblock_ip``, …) —
another agentless webhook POST to ``RESPONSE_WEBHOOK_URL``, or a ``log`` marker —
then stamps ``reverted_at`` so each action is undone exactly once.

As with the rest of the response subsystem the network call is isolated and the
intent-mapping / payload building are pure, so they unit-test without a network.
"""
from __future__ import annotations

import asyncio
import json
import logging
import urllib.request
from datetime import datetime, timezone
from typing import Optional

from starlette.concurrency import run_in_threadpool

from .. import db
from ..config import settings

log = logging.getLogger("logocean")

# Inverse of each containment action. Anything not listed is undone with a
# generic ``revert_<action>`` intent so a custom action still round-trips.
_REVERT_MAP = {
    "block_ip": "unblock_ip",
    "disable_user": "enable_user",
    "isolate_host": "unisolate_host",
    "quarantine_file": "release_file",
    "revoke_session": "restore_session",
    "log": "log",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def revert_action_type(action_type: str) -> str:
    """The inverse intent used to undo ``action_type``."""
    at = (action_type or "").lower()
    return _REVERT_MAP.get(at, f"revert_{at}" if at else "revert")


def revert_payload(row: dict) -> dict:
    """The webhook body sent to the automation endpoint to undo one action."""
    return {
        "playbook_id": row.get("playbook_id"),
        "action": revert_action_type(row.get("action_type")),
        "reverts_action_id": row.get("id"),
        "target": row.get("target"),
        "alert_id": row.get("alert_id"),
    }


def _post(url: str, payload: dict) -> None:
    data = json.dumps(payload, default=str).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST", headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10):  # nosec B310 — operator-configured URL
        pass


def execute_revert(row: dict) -> dict:
    """Undo one response action; return the audit record for the revert (does
    not write it). Mirrors ``engine.execute``: ``log`` just records, webhook
    actions POST the inverse intent; a missing URL is a skip, not a failure."""
    revert_type = revert_action_type(row.get("action_type"))
    rec = {"alert_id": row.get("alert_id"), "playbook_id": row.get("playbook_id"),
           "action_type": revert_type, "target": row.get("target"),
           "status": "skipped", "detail": None, "revert_at": None}

    if (row.get("action_type") or "").lower() == "log":
        rec["status"], rec["detail"] = "success", "reverted (log)"
        return rec
    url = settings.response_webhook_url
    if not url:
        rec["detail"] = "no RESPONSE_WEBHOOK_URL configured"
        return rec
    try:
        _post(url, revert_payload(row))
        rec["status"], rec["detail"] = "success", "revert posted to automation endpoint"
    except Exception as exc:  # noqa: BLE001
        rec["status"], rec["detail"] = "failed", str(exc)[:300]
    return rec


def process_due_reverts(now: Optional[datetime] = None, limit: int = 200) -> int:
    """Revert every action past its revert_at. Each is stamped reverted_at even
    if the webhook is skipped/failed, so a bad endpoint can't wedge the loop into
    reverting the same action forever (the attempt is audited either way).
    Returns the number processed."""
    now = now or _now()
    due = db.due_reverts(now, limit)
    for row in due:
        try:
            rec = execute_revert(row)
            db.insert_response_action(rec)
        except Exception:  # noqa: BLE001
            log.exception("revert of action %s failed", row.get("id"))
        finally:
            db.mark_reverted(row["id"], now)
    return len(due)


class RevertScheduler:
    """Fires due auto-reverts on a fixed interval in the background."""

    def __init__(self, interval: int):
        self.interval = max(interval, 10)
        self.reverted = 0
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._loop())
        log.info("revert scheduler started: every %ds", self.interval)

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _loop(self) -> None:
        while True:
            await asyncio.sleep(self.interval)
            try:
                self.reverted += await run_in_threadpool(process_due_reverts)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("revert run failed")

    def stats(self) -> dict:
        return {"reverted": self.reverted, "interval": self.interval}


_scheduler: Optional[RevertScheduler] = None


def get_scheduler() -> Optional[RevertScheduler]:
    return _scheduler


def set_scheduler(s: Optional[RevertScheduler]) -> None:
    global _scheduler
    _scheduler = s
