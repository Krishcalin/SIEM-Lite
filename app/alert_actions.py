"""Coordinator for actions taken on newly-raised alerts.

`dispatch()` fans alerts out to notifications and response playbooks; `active()`
tells the ingest pipeline whether to bother collecting newly-inserted alerts (it
only pays the RETURNING cost when at least one consumer is running).
"""
from __future__ import annotations

from . import notify
from .response import engine as response_engine


def active() -> bool:
    return notify.get_dispatcher() is not None or response_engine.get_engine() is not None


def dispatch(alerts: list[dict]) -> None:
    notify.submit_alerts(alerts)
    response_engine.submit_alerts(alerts)
