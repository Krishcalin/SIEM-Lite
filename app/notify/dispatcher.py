"""Background notification dispatcher.

Producers (the ingest threadpool workers and the correlation scheduler) call
``submit_alerts()`` after their transaction commits. Submission is non-blocking
and thread-safe; a single daemon worker thread drains the queue and delivers each
alert to every configured channel, so slow SMTP/HTTP never stalls ingestion.
Alerts below ``notify_min_level`` are filtered out at submit time.
"""
from __future__ import annotations

import logging
import queue
import threading
from typing import Optional

from ..config import settings
from .channels import build_channels, meets_min

log = logging.getLogger("logocean")
_SENTINEL = object()


class NotificationDispatcher:
    def __init__(self, channels: list, min_level: str, maxsize: int):
        self.channels = channels
        self.min_level = min_level
        self._q: queue.Queue = queue.Queue(maxsize=maxsize)
        self._thread: Optional[threading.Thread] = None
        self.sent = 0
        self.dropped = 0
        self.errors = 0

    def submit(self, alert: dict) -> None:
        if not meets_min(alert.get("level"), self.min_level):
            return
        try:
            self._q.put_nowait(alert)
        except queue.Full:
            self.dropped += 1

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="notify", daemon=True)
        self._thread.start()
        log.info("notification dispatcher started: %d channel(s), min level=%s",
                 len(self.channels), self.min_level)

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
            for ch in self.channels:
                try:
                    ch.send(item)
                    self.sent += 1
                except Exception:  # noqa: BLE001 — one bad channel must not stop the rest
                    self.errors += 1
                    log.exception("notify channel %s failed", getattr(ch, "name", "?"))

    def stats(self) -> dict:
        return {"sent": self.sent, "dropped": self.dropped,
                "errors": self.errors, "queued": self._q.qsize()}


_dispatcher: Optional[NotificationDispatcher] = None


def get_dispatcher() -> Optional[NotificationDispatcher]:
    return _dispatcher


def set_dispatcher(d: Optional[NotificationDispatcher]) -> None:
    global _dispatcher
    _dispatcher = d


def submit_alerts(alerts: list[dict]) -> None:
    """Submit newly-raised alerts for delivery (no-op if no dispatcher is active)."""
    d = _dispatcher
    if d is None or not alerts:
        return
    for a in alerts:
        d.submit(a)


def build_dispatcher() -> NotificationDispatcher:
    return NotificationDispatcher(build_channels(), settings.notify_min_level,
                                  settings.notify_queue_max)
