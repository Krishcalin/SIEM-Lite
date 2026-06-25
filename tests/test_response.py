"""Unit tests for response playbooks: loading, matching, execution (no network)."""
from pathlib import Path
from types import SimpleNamespace

import app.response.engine as re_engine
from app.response.engine import (Playbook, ResponseEngine, execute,
                                 load_playbooks, matches)

PLAYBOOKS_DIR = Path(__file__).resolve().parent.parent / "playbooks"


def _pb(**kw) -> Playbook:
    base = dict(id="pb", title="pb", description="", rule_ids=set(), min_level="low",
                techniques=set(), action_type="log", target_field=None, revert_after=None)
    base.update(kw)
    return Playbook(**base)


def test_load_playbooks():
    pbs = {p.id: p for p in load_playbooks(PLAYBOOKS_DIR)}
    assert "pb-block-bruteforce" in pbs and "pb-log-high" in pbs
    bf = pbs["pb-block-bruteforce"]
    assert bf.rule_ids == {"lo-corr-bruteforce-logon"} and bf.action_type == "block_ip"
    assert bf.target_field == "src_ip" and bf.min_level == "high" and bf.revert_after == 600


def test_matches_by_rule_level_technique():
    pb = _pb(rule_ids={"lo-corr-bruteforce-logon"}, min_level="high", techniques={"T1110"})
    assert matches(pb, {"rule_id": "lo-corr-bruteforce-logon", "level": "high",
                        "techniques": ["T1110"]})
    assert not matches(pb, {"rule_id": "other", "level": "high", "techniques": ["T1110"]})
    assert not matches(pb, {"rule_id": "lo-corr-bruteforce-logon", "level": "low",
                            "techniques": ["T1110"]})          # below min level
    assert not matches(pb, {"rule_id": "lo-corr-bruteforce-logon", "level": "high",
                            "techniques": ["T9999"]})          # technique mismatch
    assert not matches(_pb(enabled=False), {"level": "critical"})


def test_execute_log_action_records_success():
    rec = execute(_pb(action_type="log"), {"id": 5, "level": "high"})
    assert rec["status"] == "success" and rec["action_type"] == "log" and rec["alert_id"] == 5


def test_execute_webhook_without_url_is_skipped(monkeypatch):
    monkeypatch.setattr(re_engine, "settings", SimpleNamespace(response_webhook_url=""))
    rec = execute(_pb(action_type="block_ip", target_field="src_ip"),
                  {"id": 9, "level": "high", "src_ip": "45.83.122.7"})
    assert rec["status"] == "skipped" and rec["target"] == "45.83.122.7"
    assert "no RESPONSE_WEBHOOK_URL" in rec["detail"]


def test_engine_worker_runs_matching_playbooks(monkeypatch):
    written = []
    monkeypatch.setattr(re_engine.db, "insert_response_action", lambda rec: written.append(rec))
    eng = ResponseEngine([_pb(id="pb-log", action_type="log", min_level="high")], maxsize=50)
    eng.start()
    try:
        eng.submit({"id": 1, "level": "critical", "rule_id": "x"})   # matches
        eng.submit({"id": 2, "level": "low", "rule_id": "y"})        # below min -> no action
        import time
        time.sleep(0.25)
    finally:
        eng.stop()
    assert [r["alert_id"] for r in written] == [1]
    assert eng.stats()["executed"] == 1
