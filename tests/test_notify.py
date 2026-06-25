"""Unit tests for notification routing + payloads + the dispatcher thread."""
import time

from app.notify.channels import (alert_summary, json_payload, level_rank,
                                  meets_min, slack_payload)
from app.notify.dispatcher import NotificationDispatcher


def test_level_ranking_and_min():
    assert level_rank("critical") == 4 and level_rank("low") == 1
    assert level_rank("bogus") == 0                  # unknown ranks lowest
    assert meets_min("high", "high") and meets_min("critical", "medium")
    assert not meets_min("low", "high")


def test_payload_builders():
    a = {"level": "high", "rule_title": "RDP Allowed", "src_ip": "1.2.3.4",
         "techniques": ["T1021.001"], "message": "allowed 3389"}
    s = alert_summary(a)
    assert all(x in s for x in ("HIGH", "RDP Allowed", "1.2.3.4", "T1021.001", "allowed 3389"))
    assert slack_payload(a)["text"].startswith("\U0001F6A8")   # 🚨
    jp = json_payload(a)
    assert jp["level"] == "high" and jp["rule_title"] == "RDP Allowed"


class _Capture:
    name = "capture"

    def __init__(self):
        self.sent = []

    def send(self, alert):
        self.sent.append(alert)


def test_dispatcher_filters_by_min_level_and_delivers():
    cap = _Capture()
    d = NotificationDispatcher([cap], min_level="high", maxsize=100)
    d.start()
    try:
        d.submit({"level": "low", "rule_title": "x"})        # below min -> ignored
        d.submit({"level": "critical", "rule_title": "y"})
        d.submit({"level": "high", "rule_title": "z"})
        time.sleep(0.25)
    finally:
        d.stop()
    assert {a["rule_title"] for a in cap.sent} == {"y", "z"}
    assert d.stats()["sent"] == 2


def test_dispatcher_one_bad_channel_does_not_stop_others():
    class _Boom:
        name = "boom"

        def send(self, alert):
            raise RuntimeError("down")

    cap = _Capture()
    d = NotificationDispatcher([_Boom(), cap], min_level="informational", maxsize=100)
    d.start()
    try:
        d.submit({"level": "high", "rule_title": "y"})
        time.sleep(0.25)
    finally:
        d.stop()
    assert [a["rule_title"] for a in cap.sent] == ["y"]      # good channel still delivered
    assert d.stats()["errors"] == 1
