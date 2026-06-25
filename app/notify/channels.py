"""Notification channels: webhook (Slack/Teams/generic) and email (SMTP).

Each channel exposes ``send(alert: dict)``. Payload/summary builders are pure so
they are unit-testable without doing any network I/O. The webhook channel uses
the stdlib ``urllib`` so no extra dependency is needed.
"""
from __future__ import annotations

import json
import logging
import smtplib
import urllib.request
from email.message import EmailMessage
from typing import Optional

from ..config import settings

log = logging.getLogger("logocean")

_LEVELS = ["informational", "low", "medium", "high", "critical"]


def level_rank(level: Optional[str]) -> int:
    """Severity ordering; unknown/empty ranks lowest."""
    try:
        return _LEVELS.index((level or "").lower())
    except ValueError:
        return 0


def meets_min(level: Optional[str], minimum: Optional[str]) -> bool:
    return level_rank(level) >= level_rank(minimum)


def alert_summary(a: dict) -> str:
    """One- or two-line human summary used by the webhook + email bodies."""
    head = f"[{(a.get('level') or '').upper()}] {a.get('rule_title') or a.get('rule_id')}"
    who = a.get("src_ip") or a.get("user_name") or a.get("host_name")
    if who:
        head += f" · {who}"
    if a.get("techniques"):
        head += " · " + ", ".join(a["techniques"])
    msg = a.get("message")
    return f"{head}\n{msg}" if msg else head


def slack_payload(a: dict) -> dict:
    return {"text": "🚨 *LogOcean alert*\n" + alert_summary(a)}


_JSON_FIELDS = ("id", "rule_id", "rule_title", "level", "tactics", "techniques",
                "vendor", "src_ip", "dst_ip", "user_name", "host_name", "message",
                "event_time", "created_at", "status")


def json_payload(a: dict) -> dict:
    return {k: a.get(k) for k in _JSON_FIELDS}


class WebhookChannel:
    name = "webhook"

    def __init__(self, url: str, style: str = "slack"):
        self.url = url
        self.style = style

    def send(self, alert: dict) -> None:
        payload = slack_payload(alert) if self.style == "slack" else json_payload(alert)
        data = json.dumps(payload, default=str).encode("utf-8")
        req = urllib.request.Request(
            self.url, data=data, method="POST",
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10):  # nosec B310 — operator-configured URL
            pass


class EmailChannel:
    name = "email"

    def __init__(self, host: str, port: int, sender: str, recipients: list[str],
                 user: str = "", password: str = "", use_tls: bool = True):
        self.host, self.port = host, port
        self.sender, self.recipients = sender, recipients
        self.user, self.password, self.use_tls = user, password, use_tls

    def send(self, alert: dict) -> None:
        msg = EmailMessage()
        msg["Subject"] = (f"[LogOcean] {(alert.get('level') or '').upper()} — "
                          f"{alert.get('rule_title') or alert.get('rule_id')}")
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.recipients)
        msg.set_content(alert_summary(alert))
        with smtplib.SMTP(self.host, self.port, timeout=15) as s:
            if self.use_tls:
                s.starttls()
            if self.user:
                s.login(self.user, self.password)
            s.send_message(msg)


def build_channels() -> list:
    """Construct the channels that are fully configured via env settings."""
    channels: list = []
    if settings.webhook_url:
        channels.append(WebhookChannel(settings.webhook_url, settings.webhook_style))
    recipients = [r.strip() for r in settings.smtp_to.split(",") if r.strip()]
    if settings.smtp_host and settings.smtp_from and recipients:
        channels.append(EmailChannel(
            settings.smtp_host, settings.smtp_port, settings.smtp_from, recipients,
            settings.smtp_user, settings.smtp_password, settings.smtp_tls))
    return channels
