# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""The WIRE-phase contracts: the seams where a shared file must agree with a module.

Every assertion here failed at least once during the Phase-2 onboarding wave, or would
have shipped a silent defect if it had not been written. They are all DB-free.
"""
from __future__ import annotations

import re
import threading
from pathlib import Path

import pytest

import app.db as db
from app import contentpack, ingest_actions, pipeline
from app.cim import registry as cim_registry
from app.collectors import runner
from app.config import Settings, settings
from app.detect import detect_format
from app.models import NormalizedEvent
from app.parsers import FORMAT_LABELS, PARSERS

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"


# ── the parser registry ───────────────────────────────────────────────────────
def test_every_parser_key_has_a_label_and_a_parse_function():
    """A key in PARSERS with no FORMAT_LABELS entry renders as a blank option in the
    upload dropdown; a module with no `parse` is a ValueError mid-batch."""
    assert sorted(PARSERS) == sorted(FORMAT_LABELS)
    for key, module in PARSERS.items():
        assert callable(getattr(module, "parse", None)), key


# ── collectors -> parsers ─────────────────────────────────────────────────────
def _all_collectors(monkeypatch):
    """Every shipped collector, with credentials forced so `configured()` is True."""
    env = {
        "aws_region": "us-east-1", "aws_access_key_id": "AK",
        "aws_secret_access_key": "SK", "aws_sqs_queue_url": "https://sqs/q",
        "aws_route53_log_group": "/aws/route53/x", "aws_guardduty_enabled": True,
        "aws_securityhub_enabled": True, "aws_config_compliance_enabled": True,
        "azure_tenant_id": "t", "azure_client_id": "c", "azure_client_secret": "s",
        "m365_enabled": True, "defender_enabled": True,
        "okta_domain": "https://x.okta.com", "okta_token": "t",
        "github_org": "o", "github_token": "t",
        "gitlab_url": "https://gl", "gitlab_token": "t",
        "gcp_project_id": "p", "gcp_client_email": "e@x", "gcp_private_key": "k",
        "cortex_client_id": "ci", "cortex_client_secret": "cs",
        "cortex_refresh_token": "rt",
        "qualys_base_url": "https://q", "qualys_username": "u", "qualys_password": "p",
        "tenable_access_key": "a", "tenable_secret_key": "b",
        "rapid7_base_url": "https://r", "rapid7_username": "u", "rapid7_password": "p",
        "crowdstrike_client_id": "ci", "crowdstrike_client_secret": "cs",
        "crowdstrike_streams_enabled": True, "crowdstrike_incidents_enabled": True,
        "crowdstrike_fdr_queue_url": "https://sqs/f",
        "crowdstrike_fdr_access_key": "a", "crowdstrike_fdr_secret_key": "b",
    }
    fake = Settings(**{**{f.name: getattr(settings, f.name)
                         for f in Settings.__dataclass_fields__.values()}, **env})
    monkeypatch.setattr(runner, "settings", fake)
    monkeypatch.setattr(runner.vault, "get", lambda i, n, env_value="": env_value)
    return runner.build_collectors()


def test_every_collector_names_a_registered_parser(monkeypatch):
    """THE wiring failure this phase was built to avoid: `fmt` is looked up in PARSERS
    only at ingest time, so an unregistered key means `pipeline.parse_events` raises
    ValueError, `run_collector` swallows it into last_status='error', and the collector
    polls forever without ever advancing its cursor. Nothing else notices."""
    built = _all_collectors(monkeypatch)
    assert len(built) >= 20, [c.name for c in built]
    for c in built:
        assert c.fmt in PARSERS, f"{c.name} -> unregistered format {c.fmt!r}"


def test_collector_names_are_unique(monkeypatch):
    """`db.get_collector` / `update_collector` key on the name, so two collectors
    sharing one would share a cursor and each would skip the other's data."""
    names = [c.name for c in _all_collectors(monkeypatch)]
    assert len(names) == len(set(names)), sorted(names)


def test_no_collector_registers_without_credentials():
    """Every collector must self-gate: an empty environment configures nothing, so a
    default install does not sit there erroring against APIs it has no keys for."""
    assert runner.build_collectors() == []


# ── the vault slot table ──────────────────────────────────────────────────────
def test_every_known_slot_names_a_real_setting():
    """`migrate_env_secrets` does `getattr(settings, env_name.lower(), "")`, so a slot
    whose env name does not lower-case to the attribute name migrates NOTHING — and
    silently, because the missing attribute defaults to "" and the slot is skipped."""
    for integration, name, env_name in runner.KNOWN_SLOTS:
        assert hasattr(settings, env_name.lower()), \
            f"{integration}/{name}: no settings.{env_name.lower()}"


def test_every_collector_secret_is_resolved_through_the_vault(monkeypatch):
    """The charter rule, asserted rather than reviewed: a credential must reach a
    collector through `_cred` -> `vault.get`, never straight off `settings`.

    Reading `settings.x` directly still WORKS — the env var is the vault's own fallback —
    so the bug is invisible in every functional test and in a passing deployment. What it
    breaks is the vault: that one integration silently keeps using the plaintext
    environment variable, so rotating the sealed secret changes nothing and an operator
    who has removed the variable finds the collector dead with no explanation.

    Every plaintext fallback named by KNOWN_SLOTS is set to a unique sentinel and the
    vault is stubbed to return a different one. A sentinel reaching a collector's
    attributes means that credential bypassed the vault.
    """
    slots = {env.lower(): (integration, name)
             for integration, name, env in runner.KNOWN_SLOTS}
    base = {f.name: getattr(settings, f.name)
            for f in Settings.__dataclass_fields__.values()}
    # Non-secret settings that must still be set for `configured()` to return True.
    base.update({
        "aws_region": "us-east-1", "aws_sqs_queue_url": "https://sqs/q",
        "aws_route53_log_group": "/aws/route53/x", "aws_guardduty_enabled": True,
        "aws_securityhub_enabled": True, "aws_config_compliance_enabled": True,
        "azure_tenant_id": "t", "azure_client_id": "c", "m365_enabled": True,
        "defender_enabled": True, "okta_domain": "https://x.okta.com",
        "github_org": "o", "gitlab_url": "https://gl", "gcp_project_id": "p",
        "gcp_client_email": "e@x", "cortex_client_id": "ci",
        "qualys_base_url": "https://q", "qualys_username": "u",
        "rapid7_base_url": "https://r", "rapid7_username": "u",
        "crowdstrike_client_id": "ci", "crowdstrike_streams_enabled": True,
        "crowdstrike_incidents_enabled": True,
        "crowdstrike_fdr_queue_url": "https://sqs/f",
        "crowdstrike_fdr_region": "us-west-1",
    })
    for attr in slots:
        base[attr] = f"PLAINTEXT-{attr}"
    monkeypatch.setattr(runner, "settings", Settings(**base))
    monkeypatch.setattr(runner.vault, "get",
                        lambda integration, name, env_value="": f"VAULT-{integration}-{name}")
    leaked = []
    for c in runner.build_collectors():
        for attr, value in vars(c).items():
            if isinstance(value, str) and value.startswith("PLAINTEXT-"):
                leaked.append(f"{c.name}.{attr} = {value} (bypassed the vault)")
    assert not leaked, leaked


def test_known_slots_holds_one_row_per_credential_not_per_collector():
    """Six AWS collectors share three `aws` slots and four Microsoft collectors share
    `azure/client_secret`. A duplicate row would make the admin page overstate how many
    secrets an operator must supply and double-count in `migrate_env_secrets`."""
    keys = [(i, n) for i, n, _ in runner.KNOWN_SLOTS]
    assert len(keys) == len(set(keys)), sorted(keys)


# ── Settings <-> .env.example ─────────────────────────────────────────────────
def test_env_example_documents_every_setting():
    """An undocumented setting is one an operator cannot discover. Read from the SOURCE
    of app/config.py rather than the dataclass, because the env var name is what an
    operator sets and it is only visible in the `os.getenv` / `_bool` call."""
    src = (ROOT / "app" / "config.py").read_text(encoding="utf-8")
    env_names = (set(re.findall(r'os\.getenv\("([A-Z0-9_]+)"', src))
                 | set(re.findall(r'_bool\("([A-Z0-9_]+)"', src)))
    doc = (ROOT / ".env.example").read_text(encoding="utf-8")
    documented = {m.group(1) for m in
                  re.finditer(r"^\s*#?\s*([A-Z][A-Z0-9_]+)=", doc, re.M)}
    assert env_names - documented == set(), sorted(env_names - documented)
    assert documented - env_names == set(), sorted(documented - env_names)


# ── format auto-detection ─────────────────────────────────────────────────────
#: The sample -> format routing every Phase-2 source depends on. Each of these was
#: measured against the real detector; before the detect.py edits, the JSON ones fell
#: through to `generic_json` (wrong vendor, wrong CIM tags), `cisco_ftd.log` was claimed
#: by `cisco_asa` (the Lina grammar, which would parse it as something else entirely)
#: and `qualys_detection.xml` matched nothing at all and returned None.
_ROUTING = {
    "aws_guardduty.json": "aws_guardduty",
    "aws_securityhub.json": "aws_securityhub",
    "cisco_ftd.log": "cisco_ftd",
    "cortex_prisma_access.csv": "paloalto_csv",
    "defender_xdr.json": "defender_xdr",
    "netflow.json": "netflow",
    "qualys_detection.xml": "qualys",
    "rapid7_insightvm.json": "rapid7",
    "tenable_vulns.json": "tenable",
}


@pytest.mark.parametrize("name", sorted(_ROUTING))
def test_detect_routes_each_phase2_sample_to_its_own_parser(name):
    path = SAMPLES / name
    assert path.exists(), f"{name} is missing from samples/"
    fmt = detect_format(name, path.read_text(encoding="utf-8"))
    assert fmt == _ROUTING[name]
    assert fmt in PARSERS


def test_the_new_detectors_did_not_steal_an_existing_source():
    """A greedy new predicate ahead of an established one is the classic detect.py
    regression: it is invisible until someone notices a vendor's events are tagged as
    another vendor's. Pinned here as well as in test_cim's corpus, because this names
    the FILE that moved rather than reporting a golden-count drift."""
    established = {
        "aws_cloudtrail.json": "aws_cloudtrail", "cisco_asa.log": "cisco_asa",
        "cisco_ios.log": "cisco_ios", "crowdstrike_events.json": "crowdstrike_json",
        "entra_signin.json": "entra_signin", "generic_json.json": "generic_json",
        "m365_audit.json": "m365_audit", "meraki.log": "meraki",
        "paloalto_traffic.csv": "paloalto_csv", "suricata_eve.json": "suricata_eve",
        "sysmon.json": "sysmon", "windows_security.json": "windows_security",
    }
    for name, want in established.items():
        got = detect_format(name, (SAMPLES / name).read_text(encoding="utf-8"))
        assert got == want, f"{name}: {want} -> {got}"


# ── the ingest-action seam ────────────────────────────────────────────────────
def _drop_everything_from(vendor: str) -> ingest_actions.ActionIndex:
    return ingest_actions.ActionIndex([ingest_actions.action_from_dict({
        "id": "t-drop", "action": "drop", "logsource": {"vendor": vendor},
    })])


def test_the_ingest_action_hook_sits_on_the_one_path_every_source_shares(monkeypatch):
    """Upload, the HTTP API, the HEC shim, syslog, NetFlow and every collector all
    funnel through `pipeline.write_stream`, which is why the hook is there and not in
    `ingest.ingest` — the live queue path does not go through `ingest.ingest` at all, so
    hooking that would have left syslog and NetFlow unfiltered.
    """
    stored = []
    monkeypatch.setattr(db, "insert_events", lambda conn, chunk, bid: stored.extend(chunk))
    monkeypatch.setattr(db, "insert_alerts", lambda conn, a, return_inserted=False: [])
    monkeypatch.setattr(ingest_actions, "_index", _drop_everything_from("noisy"))
    events = [NormalizedEvent(event_time=None, vendor="noisy", log_type="x"),
              NormalizedEvent(event_time=None, vendor="keepme", log_type="x")]
    result = pipeline.write_stream(conn=None, events=iter(events), batch_id=1)
    assert [e.vendor for e in stored] == ["keepme"]
    assert (result.total, result.dropped) == (2, 1)


@pytest.mark.parametrize("module,call", [("ingest", "ingest"), ("streaming", "_write_group")])
def test_a_dropped_event_is_not_reported_as_a_duplicate(monkeypatch, module, call):
    """`duplicates = total - inserted` counts every dropped event as a duplicate, which
    reads to an operator as "we already had this data" rather than "a rule deleted it".
    Both write paths must subtract `dropped`, and must record it in its own column so
    `total == inserted + duplicates + dropped` holds.

    THIS RUNS THE CODE. It used to read the two modules as TEXT and assert that the
    string `result.total - result.dropped - inserted` appeared in them, which cannot
    tell an expression being evaluated from one merely present in the file: reverting
    either call site to `max(result.total - inserted, 0)` while leaving the old
    expression behind in a comment passed the whole suite, and so did deleting
    `dropped_rows=result.dropped` outright, since the greps never looked at it. The
    behavioural coverage that did exist was integration-only, and this repo's build
    discipline forbids agents from running integration tests — so a regression here was
    invisible to every gate until the serial green phase.
    """
    import contextlib
    import importlib

    mod = importlib.import_module(f"app.{module}")
    updates: list[dict] = []

    class _Result:
        total, dropped, alerts, events = 10, 3, [], []

    class _Conn:
        def commit(self):
            pass

        def rollback(self):
            pass

    @contextlib.contextmanager
    def _connection():
        yield _Conn()

    class _Pool:
        connection = staticmethod(_connection)

    monkeypatch.setattr(mod.db, "pool", lambda: _Pool())
    monkeypatch.setattr(mod.db, "create_batch", lambda *a, **k: 1)
    monkeypatch.setattr(mod.db, "count_batch_rows", lambda batch_id: 5)
    monkeypatch.setattr(mod.db, "update_batch",
                        lambda batch_id, **kw: updates.append(kw))
    monkeypatch.setattr(mod.pipeline, "write_stream", lambda *a, **k: _Result())
    monkeypatch.setattr(mod.alert_actions, "dispatch", lambda alerts: None)

    if module == "ingest":
        monkeypatch.setattr(mod.db, "find_batch_by_sha", lambda sha: None)
        mod.ingest("{}", "generic_json")
    else:
        mod._write_group([], "generic_json", "syslog", "198.51.100.4", "json")

    done = [u for u in updates if u.get("status") == "done"]
    assert done, "the batch was never marked done"
    kw = done[-1]
    assert kw["dropped_rows"] == 3, "the drop count never reached the batch row"
    assert kw["duplicate_rows"] == 2, "a dropped event was counted as a duplicate"
    assert kw["total_rows"] == kw["inserted_rows"] + kw["duplicate_rows"] + kw["dropped_rows"]


def test_custom_parser_runs_before_the_mask_can_be_undone():
    """`custom_parser.apply` fills any column that is None or "" out of `raw`, so a mask
    that NULLs a typed column (inet / integer) is silently REFILLED if it still runs
    afterwards. The hoist above the ingest-action seam is what prevents that."""
    src = (ROOT / "app" / "pipeline.py").read_text(encoding="utf-8")
    assert src.index("custom_parser.apply(evt)") < src.index("ingest_actions.apply(evt)")
    # ...and exactly once: a leftover second call inside the try would undo the mask.
    assert src.count("custom_parser.apply(evt)") == 1


# ── the content-pack CIM overlay ──────────────────────────────────────────────
def test_the_pack_overlay_never_re_enters_the_registry_lock(monkeypatch):
    """A HANG, not a failure, is what this prevents, which is why it is asserted with a
    timeout instead of an exception.

    `app/cim/registry.py:get_registry` holds a plain non-reentrant `threading.Lock`
    while it builds the registry, and the pack overlay runs inside it. If the overlay
    parses a stored pack without `known_models`, `contentpack.parse` resolves the model
    list by calling `get_registry` again — and the process deadlocks on the first
    startup after any pack is installed. Nothing is raised, so nothing is logged: it
    just stops.
    """
    doc = ("pack: 1\nname: probe\nversion: 1.0.0\ncim:\n  - model: network\n"
           "    membership:\n      - {vendor: [acme], log_type: [widgetflow]}\n")
    monkeypatch.setattr(db, "list_content_packs",
                        lambda: [{"name": "probe", "document": doc}])
    monkeypatch.setattr(cim_registry, "_cache", None)
    monkeypatch.setattr(cim_registry, "_failure", None)
    box: dict = {}
    done = threading.Event()

    def run():
        try:
            box["reg"] = cim_registry.get_registry()
        except Exception as exc:                       # noqa: BLE001
            box["err"] = exc
        finally:
            done.set()

    threading.Thread(target=run, daemon=True).start()
    assert done.wait(20), "get_registry() deadlocked with a content pack installed"
    assert "err" not in box, box.get("err")
    # And the overlay actually applied: this event matches ONLY the pack's clause.
    from app.cim import match as cim_match
    evt = NormalizedEvent(event_time=None, vendor="acme", log_type="widgetflow")
    assert "network" in cim_match.tags_for(evt, box["reg"])
    cim_registry.reload()                              # restore the shipped registry


def test_installed_packs_requires_the_caller_to_supply_known_models():
    """The signature IS the guard — see the test above for what re-entrance costs."""
    import inspect
    sig = inspect.signature(contentpack.installed_packs)
    assert "known_models" in sig.parameters
    src = inspect.getsource(contentpack.overlay_registry)
    assert "registry_model_names(registry)" in src


# ── routers ───────────────────────────────────────────────────────────────────
def test_the_hec_router_keeps_its_absolute_splunk_paths():
    """Nesting the HEC router under api.router's /api/v1 prefix would relocate it to
    /api/v1/services/collector, which no Splunk HEC sender will ever call — and the
    symptom is a 404 on a path the operator cannot change."""
    import app.main as main
    paths = set(main.app.openapi()["paths"])
    assert {"/services/collector", "/services/collector/event",
            "/services/collector/raw", "/services/collector/health"} <= paths
    assert not any(p.startswith("/api/v1/services") for p in paths)


def test_hec_is_exempt_from_the_session_redirect_and_the_csrf_check():
    """Under AUTH_ENABLED the middleware 303s unauthenticated requests to /login. A HEC
    sender reads that as an opaque failure, so the prefix must be exempt — it does its
    own `Authorization: Splunk <key>` -> db.verify_api_key check, exactly like /api/."""
    src = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
    guard = src[src.index("async def auth_guard"):src.index("def _ctx(")]
    assert guard.count('"/services/collector"') == 2, guard


def test_content_pack_writes_are_not_reachable_with_an_ingest_api_key():
    """An `api_keys` row has no role, so any enabled key passes `require_api_key`. A
    pack installs detection rules and parsers, so the write half lives on the console
    behind require_role('admin') — /api/v1 keeps only the side-effect-free routes."""
    import app.main as main
    paths = main.app.openapi()["paths"]
    api_pack_routes = {p: set(m) for p, m in paths.items() if p.startswith("/api/v1/packs")}
    for path, methods in api_pack_routes.items():
        assert "delete" not in methods, path
        assert not path.endswith("/import"), path
    assert "/packs/import" in paths and "/packs/uninstall" in paths
