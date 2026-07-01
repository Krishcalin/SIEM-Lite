"""Detection-engineering workbench (pure, unit-testable).

Three analyst tools over the detection rule pack, all dependency-free:

* **Rule tester** — evaluate a Sigma-subset rule against a sample event with the
  *same* engine the pipeline uses, and show per-selection + condition results so
  you can see exactly why a rule did or didn't fire.
* **Coverage map** — which ATT&CK tactics/techniques the *enabled* rules cover,
  and where the gaps are (techniques only a disabled rule would catch, or none).
* **Rule health** — never-fired, noisy, and stale rules, so the pack can be tuned.

The coverage/health functions take the plain rule dicts returned by
``db.rule_stats`` / ``db.list_rules`` so they stay pure and testable.
"""
from __future__ import annotations

from typing import Any, Optional

import yaml

from . import killchain
from .detection import engine as de
from .models import NormalizedEvent


# --------------------------------------------------------------------------- #
#  Rule tester                                                                #
# --------------------------------------------------------------------------- #
def event_from_json(data: dict) -> NormalizedEvent:
    """Build a NormalizedEvent from a plain dict: recognised normalized-field
    names populate the typed attributes, and the whole dict is kept as ``raw`` so
    vendor-specific fields remain matchable (exactly like a parsed event)."""
    kwargs: dict[str, Any] = {"event_time": None, "vendor": str(data.get("vendor") or ""),
                              "raw": data}
    for f in de._NORMALIZED_FIELDS:
        if f == "vendor":
            continue
        if f in data and data[f] is not None:
            kwargs[f] = data[f]
    return NormalizedEvent(**kwargs)


def test_rule(rule_yaml: str, event_json: str) -> dict:
    """Evaluate a rule (YAML) against an event (JSON) with the production engine.

    Returns a result dict: ``ok`` (parsed cleanly), ``error`` (message if not),
    ``matched`` (final verdict), ``logsource_ok``, ``selections`` (per-named
    selection booleans), ``condition`` (the rule's condition expression), and the
    parsed ``techniques`` / ``tactics``. Never raises on bad input.
    """
    import json

    result: dict[str, Any] = {
        "ok": False, "error": None, "matched": False, "logsource_ok": None,
        "selections": {}, "condition": "", "techniques": [], "tactics": [],
    }
    try:
        doc = yaml.safe_load(rule_yaml)
    except yaml.YAMLError as e:
        result["error"] = f"Rule YAML parse error: {e}"
        return result
    if not isinstance(doc, dict) or not doc.get("detection"):
        result["error"] = "Rule must be a mapping with a 'detection' block."
        return result
    try:
        event = json.loads(event_json)
    except json.JSONDecodeError as e:
        result["error"] = f"Event JSON parse error: {e}"
        return result
    if not isinstance(event, dict):
        result["error"] = "Event must be a JSON object."
        return result

    try:
        rule = de.rule_from_dict(doc, "workbench")
        flat = de.flatten_event(event_from_json(event))
        det = rule.detection
        selections = {name: de._eval_selection(flat, body)
                      for name, body in det.items() if name != "condition"}
        condition = str(det.get("condition", ""))
        logsource_ok = de._logsource_matches(rule.logsource, flat)
        matched = de.match_rule(rule, flat)
    except Exception as e:  # noqa: BLE001 — surface any evaluator error to the UI
        result["error"] = f"Evaluation error: {e}"
        return result

    result.update(ok=True, matched=matched, logsource_ok=logsource_ok,
                  selections=selections, condition=condition,
                  techniques=rule.techniques, tactics=rule.tactics)
    return result


# --------------------------------------------------------------------------- #
#  ATT&CK coverage map                                                        #
# --------------------------------------------------------------------------- #
def coverage_map(rules: list[dict]) -> dict:
    """Summarise ATT&CK coverage from the rule registry.

    Each rule dict needs ``tactics``, ``techniques`` and ``enabled``. A technique
    is *covered* when an enabled rule maps to it; *uncovered* when it only appears
    on disabled rules. Tactics are returned in kill-chain order.
    """
    by_tactic: dict[str, dict] = {}
    all_techniques: set[str] = set()
    covered_techniques: set[str] = set()
    untagged = 0

    for r in rules:
        tactics = [killchain.normalize_tactic(t) for t in (r.get("tactics") or [])]
        techs = [str(t).upper() for t in (r.get("techniques") or [])]
        enabled = bool(r.get("enabled"))
        if not techs and not tactics:
            untagged += 1
        for t in techs:
            all_techniques.add(t)
            if enabled:
                covered_techniques.add(t)
        for tac in (tactics or ["(untagged)"]):
            slot = by_tactic.setdefault(tac, {
                "tactic": tac, "title": killchain.tactic_title(tac) if tac != "(untagged)" else "(untagged)",
                "covered": set(), "uncovered": set(), "rules": 0, "enabled_rules": 0})
            slot["rules"] += 1
            if enabled:
                slot["enabled_rules"] += 1
            for t in techs:
                slot["covered" if enabled else "uncovered"].add(t)

    tactics_out = []
    for slot in by_tactic.values():
        # a technique enabled on any rule is covered — drop it from uncovered
        slot["uncovered"] -= slot["covered"]
        slot["covered"] = sorted(slot["covered"])
        slot["uncovered"] = sorted(slot["uncovered"])
        tactics_out.append(slot)
    tactics_out.sort(key=lambda s: killchain.tactic_rank(s["tactic"]))

    total = len(all_techniques)
    covered = len(covered_techniques)
    return {
        "tactics": tactics_out,
        "total_techniques": total,
        "covered_techniques": covered,
        "uncovered_techniques": sorted(all_techniques - covered_techniques),
        "coverage_pct": round(100.0 * covered / total, 1) if total else 0.0,
        "untagged_rules": untagged,
    }


# --------------------------------------------------------------------------- #
#  Rule health                                                                #
# --------------------------------------------------------------------------- #
def rule_health(rules: list[dict], noisy_window_threshold: int = 50) -> dict:
    """Bucket rules by operational health.

    Each rule dict needs ``enabled``, ``fired_total`` (all-time alert count),
    ``fired_window`` (alerts in the analysis window) and ``last_fired``.

    * **never_fired** — enabled but has never raised an alert (untested / dead).
    * **noisy** — raised ≥ ``noisy_window_threshold`` alerts in the window.
    * **stale** — enabled and fired historically but silent in the window.
    * **disabled** — turned off in the registry.
    """
    def _int(r, k):
        try:
            return int(r.get(k) or 0)
        except (TypeError, ValueError):
            return 0

    never_fired, noisy, stale, disabled = [], [], [], []
    for r in rules:
        enabled = bool(r.get("enabled"))
        total = _int(r, "fired_total")
        window = _int(r, "fired_window")
        if not enabled:
            disabled.append(r)
            continue
        if total == 0:
            never_fired.append(r)
        elif window >= noisy_window_threshold:
            noisy.append(r)
        elif window == 0:
            stale.append(r)

    noisy.sort(key=lambda r: _int(r, "fired_window"), reverse=True)
    return {
        "never_fired": never_fired,
        "noisy": noisy,
        "stale": stale,
        "disabled": disabled,
        "counts": {
            "total": len(rules),
            "enabled": sum(1 for r in rules if r.get("enabled")),
            "never_fired": len(never_fired),
            "noisy": len(noisy),
            "stale": len(stale),
            "disabled": len(disabled),
        },
        "threshold": noisy_window_threshold,
    }
