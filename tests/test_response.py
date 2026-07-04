# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Unit tests for response playbooks: loading, matching, execution (no network)."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import app.response.engine as re_engine
import app.response.revert as revert
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


# --------------------------------------------------------------------------- #
#  Stateful auto-revert                                                        #
# --------------------------------------------------------------------------- #
def test_revert_action_type_maps_inverse():
    assert revert.revert_action_type("block_ip") == "unblock_ip"
    assert revert.revert_action_type("disable_user") == "enable_user"
    assert revert.revert_action_type("isolate_host") == "unisolate_host"
    assert revert.revert_action_type("log") == "log"
    assert revert.revert_action_type("custom_thing") == "revert_custom_thing"   # fallback
    assert revert.revert_action_type("") == "revert"


def test_revert_payload_carries_inverse_and_provenance():
    row = {"id": 7, "playbook_id": "pb-block", "action_type": "block_ip",
           "target": "45.83.122.7", "alert_id": 3}
    p = revert.revert_payload(row)
    assert p["action"] == "unblock_ip" and p["target"] == "45.83.122.7"
    assert p["reverts_action_id"] == 7 and p["alert_id"] == 3


def test_execute_revert_log_records_success():
    rec = revert.execute_revert({"action_type": "log", "playbook_id": "pb", "alert_id": 1})
    assert rec["status"] == "success" and rec["action_type"] == "log"
    assert rec["revert_at"] is None                      # a revert is never itself reverted


def test_execute_revert_webhook_without_url_is_skipped(monkeypatch):
    monkeypatch.setattr(revert, "settings", SimpleNamespace(response_webhook_url=""))
    rec = revert.execute_revert({"action_type": "block_ip", "target": "1.2.3.4",
                                 "playbook_id": "pb", "alert_id": 2})
    assert rec["status"] == "skipped" and rec["action_type"] == "unblock_ip"
    assert "no RESPONSE_WEBHOOK_URL" in rec["detail"]


def test_execute_revert_webhook_posts_inverse(monkeypatch):
    posted = {}
    monkeypatch.setattr(revert, "settings", SimpleNamespace(response_webhook_url="http://soar"))
    monkeypatch.setattr(revert, "_post", lambda url, payload: posted.update(url=url, payload=payload))
    rec = revert.execute_revert({"action_type": "block_ip", "target": "1.2.3.4",
                                 "playbook_id": "pb", "alert_id": 2, "id": 9})
    assert rec["status"] == "success"
    assert posted["url"] == "http://soar" and posted["payload"]["action"] == "unblock_ip"


def test_process_due_reverts_undoes_and_stamps_each_once(monkeypatch):
    due = [{"id": 1, "action_type": "log", "playbook_id": "pb", "alert_id": 1,
            "target": None},
           {"id": 2, "action_type": "log", "playbook_id": "pb", "alert_id": 2,
            "target": None}]
    inserted, marked = [], []
    monkeypatch.setattr(revert.db, "due_reverts", lambda now, limit=200: due)
    monkeypatch.setattr(revert.db, "insert_response_action", lambda rec: inserted.append(rec))
    monkeypatch.setattr(revert.db, "mark_reverted", lambda aid, when: marked.append(aid))
    n = revert.process_due_reverts(datetime(2026, 7, 3, tzinfo=timezone.utc))
    assert n == 2
    assert [r["alert_id"] for r in inserted] == [1, 2]
    assert marked == [1, 2]                               # every due action stamped exactly once


def test_process_due_reverts_stamps_even_when_action_write_fails(monkeypatch):
    # A failing revert must still be stamped so the loop can't spin on it forever.
    monkeypatch.setattr(revert.db, "due_reverts",
                        lambda now, limit=200: [{"id": 5, "action_type": "block_ip",
                                                 "playbook_id": "pb", "target": "1.1.1.1"}])
    def boom(rec):
        raise RuntimeError("db down")
    marked = []
    monkeypatch.setattr(revert, "execute_revert", lambda row: {"x": 1})
    monkeypatch.setattr(revert.db, "insert_response_action", boom)
    monkeypatch.setattr(revert.db, "mark_reverted", lambda aid, when: marked.append(aid))
    n = revert.process_due_reverts(datetime(2026, 7, 3, tzinfo=timezone.utc))
    assert n == 1 and marked == [5]                      # stamped despite the write error
