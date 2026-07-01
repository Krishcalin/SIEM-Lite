"""Regression tests for the audit hardening fixes (no database needed)."""
import io
import time
from datetime import datetime, timezone

from app.db import _row
from app.detection.engine import DetectionEngine, Rule
from app.models import NormalizedEvent
from app.parsers import crowdstrike_json, linux_auditd, suricata_eve, sysmon, windows_security
from app.util import json_or_none, read_capped, to_int, to_port

_BOMB = "{" + '"a":{' * 5000 + '"x":1' + "}" * 5000 + "}"


# ── bounded coercion (int64 / port domain) ──────────────────────────────────
def test_to_int_rejects_out_of_int64():
    assert to_int("65535") == 65535 and to_int("-5") == -5
    assert to_int(str(2 ** 63)) is None            # would overflow bigint
    assert to_int(str(-(2 ** 63) - 1)) is None
    assert to_int("99999999999999999999") is None


def test_to_port_clamps_to_domain():
    assert to_port("443") == 443 and to_port(0) == 0 and to_port("65535") == 65535
    assert to_port("9999999999") is None           # would overflow the int32 port column
    assert to_port("-1") is None and to_port("70000") is None and to_port("x") is None


def test_row_nulls_out_of_range_ports():
    ev = NormalizedEvent(event_time=datetime(2026, 1, 1, tzinfo=timezone.utc), vendor="v",
                         src_port=9999999999, dst_port=443)
    r = _row(ev, batch_id=1)
    assert r["src_port"] is None and r["dst_port"] == 443   # hostile port -> NULL, not a crash


# ── JSON depth-bomb guard across the parsers with private _iter_records ───────
def test_json_or_none_guards_depth_and_recursion():
    assert json_or_none(_BOMB) is None             # too deep -> None (no RecursionError)
    assert json_or_none('{"a":1}') == {"a": 1}
    assert json_or_none("not json") is None and json_or_none("") is None


def test_parsers_do_not_crash_on_deep_json():
    # explicit-format ingest bypasses detect's guard; the parsers must still be safe
    for mod in (suricata_eve, sysmon, crowdstrike_json, windows_security):
        assert list(mod.parse(_BOMB)) == []


# ── remote-read cap ──────────────────────────────────────────────────────────
def test_read_capped_bounds_memory():
    assert read_capped(io.BytesIO(b"x" * 10), 100) == b"x" * 10
    try:
        read_capped(io.BytesIO(b"x" * 200), 100)
        assert False, "expected ValueError"
    except ValueError:
        pass


# ── auditd argc CPU-DoS is bounded by the args actually present ───────────────
def test_auditd_argc_is_bounded():
    line = ('type=EXECVE msg=audit(1782648000.1:1): argc=999999999 '
            'a0="curl" a1="-O" a2="http://x/y"')
    start = time.time()
    ev = next(linux_auditd.parse(line))
    assert time.time() - start < 5           # old code looped ~1e9 times (minutes)
    assert ev.message == "curl -O http://x/y"


# ── detection engine isolates a bad rule ─────────────────────────────────────
def test_detection_isolates_invalid_regex_rule():
    bad = Rule(id="bad", title="bad", level="low", description="", logsource={},
               detection={"s": {"message|re": "("}, "condition": "s"})   # invalid regex
    good = Rule(id="good", title="good", level="low", description="", logsource={},
                detection={"s": {"message|contains": "hi"}, "condition": "s"})
    eng = DetectionEngine([bad, good])
    hits = {r.id for r in eng.evaluate_event(
        NormalizedEvent(event_time=None, vendor="v", message="hi there"))}
    assert hits == {"good"}                   # bad rule neither crashes nor matches
