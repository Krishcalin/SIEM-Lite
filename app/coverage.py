# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Detection-coverage scoreboard (pure, DB-free).

Computes, from the loaded rule registry, how much of **MITRE ATT&CK** (Enterprise
+ ICS) and **MITRE ATLAS** (adversarial AI) the pack can practically detect —
rolled up by tactic, fidelity and data source — plus MITRE ATT&CK **Navigator**
layers scored by *rule coverage* (not alert volume). This is the Phase-0
scoreboard for the detection-coverage programme; see
``docs/DETECTION_COVERAGE_ROADMAP.md``.

The functions take any objects exposing the rule metadata attributes (``id`` /
``techniques`` / ``atlas_techniques`` / ``tactics`` / ``fidelity`` /
``data_source`` / ``enabled``) — i.e. both ``engine.Rule`` and
``correlation.CorrelationRule`` — so it stays pure and unit-testable.
"""
from __future__ import annotations

from typing import Any, Iterable

from . import killchain, navigator

_FIDELITY_RANK = {"high": 3, "medium": 2, "hunt": 1}

# Approximate technique totals (ATT&CK v14, incl. sub-techniques) — used only to
# render a soft "~%" on the scoreboard; the absolute covered counts are exact.
ATTACK_ENTERPRISE_TOTAL = 625
ATTACK_ICS_TOTAL = 95

# MITRE ATLAS — curated, detection-relevant subset (every ID verified against the
# MISP ATLAS galaxy). The scoreboard renders this matrix so the adversarial-AI gap
# stays visible at 0% until the Phase-7 LLM / AI-gateway telemetry lands.
ATLAS_MATRIX: tuple[dict[str, Any], ...] = (
    {"tactic": "resource-development", "title": "Resource Development", "techniques": (
        ("AML.T0010", "ML Supply Chain Compromise"),
        ("AML.T0020", "Poison Training Data"),
        ("AML.T0058", "Publish Poisoned Models"),
    )},
    {"tactic": "initial-access", "title": "Initial Access", "techniques": (
        ("AML.T0051", "LLM Prompt Injection"),
        ("AML.T0051.000", "Direct Prompt Injection"),
        ("AML.T0051.001", "Indirect Prompt Injection"),
        ("AML.T0012", "Valid Accounts"),
        ("AML.T0049", "Exploit Public-Facing Application"),
        ("AML.T0052", "Phishing"),
        ("AML.T0015", "Evade ML Model"),
    )},
    {"tactic": "ml-model-access", "title": "ML Model Access", "techniques": (
        ("AML.T0040", "AI Model Inference API Access"),
        ("AML.T0041", "Physical Environment Access"),
        ("AML.T0044", "Full ML Model Access"),
        ("AML.T0047", "ML-Enabled Product or Service"),
    )},
    {"tactic": "execution", "title": "Execution", "techniques": (
        ("AML.T0011", "User Execution"),
        ("AML.T0050", "Command and Scripting Interpreter"),
        ("AML.T0053", "LLM Plugin Compromise"),
    )},
    {"tactic": "defense-evasion", "title": "Defense Evasion", "techniques": (
        ("AML.T0054", "LLM Jailbreak"),
        ("AML.T0061", "LLM Prompt Self-Replication"),
    )},
    {"tactic": "credential-access", "title": "Credential Access", "techniques": (
        ("AML.T0055", "Unsecured Credentials"),
    )},
    {"tactic": "exfiltration", "title": "Exfiltration", "techniques": (
        ("AML.T0024", "Exfiltration via ML Inference API"),
        ("AML.T0024.002", "Extract ML Model"),
        ("AML.T0057", "LLM Data Leakage"),
        ("AML.T0056", "LLM Meta Prompt Extraction"),
        ("AML.T0025", "Exfiltration via Cyber Means"),
    )},
    {"tactic": "impact", "title": "Impact", "techniques": (
        ("AML.T0029", "Denial of ML Service"),
        ("AML.T0031", "Erode ML Model Integrity"),
        ("AML.T0034", "Cost Harvesting"),
        ("AML.T0046", "Spamming ML System with Chaff Data"),
        ("AML.T0048", "External Harms"),
        ("AML.T0059", "Erode Dataset Integrity"),
    )},
)
_ATLAS_TOTAL = sum(len(t["techniques"]) for t in ATLAS_MATRIX)


def _best_fidelity(a: str, b: str) -> str:
    return a if _FIDELITY_RANK.get(a, 0) >= _FIDELITY_RANK.get(b, 0) else b


def _record(rule: Any) -> dict[str, Any]:
    return {
        "id": getattr(rule, "id", ""),
        "techniques": [str(t).upper() for t in getattr(rule, "techniques", []) or []],
        "atlas": [str(t).upper() for t in getattr(rule, "atlas_techniques", []) or []],
        "tactics": [killchain.normalize_tactic(t) for t in getattr(rule, "tactics", []) or []],
        "fidelity": getattr(rule, "fidelity", "medium") or "medium",
        "data_source": list(getattr(rule, "data_source", []) or []),
        "enabled": bool(getattr(rule, "enabled", True)),
    }


def _pct(n: int, total: int) -> float:
    return round(100.0 * n / total, 1) if total else 0.0


def attack_coverage(rules: Iterable[Any]) -> dict[str, Any]:
    """Per-technique + per-tactic ATT&CK coverage, split into enterprise vs ICS."""
    recs = [_record(r) for r in rules]

    tech_index: dict[str, dict] = {}
    by_tactic: dict[str, dict] = {}
    fidelity_counts = {"high": 0, "medium": 0, "hunt": 0}
    data_source_counts: dict[str, set] = {}
    untagged = 0

    for rec in recs:
        techs = rec["techniques"]
        if not techs and not rec["tactics"] and not rec["atlas"]:
            untagged += 1
        for tech in techs:
            slot = tech_index.setdefault(tech, {
                "technique": tech, "rules": [], "data_sources": set(),
                "enabled": False, "fidelity": "hunt",
                "domain": "ics-attack" if navigator.is_ics_technique(tech) else "enterprise-attack"})
            slot["rules"].append(rec["id"])
            slot["data_sources"].update(rec["data_source"])
            slot["enabled"] = slot["enabled"] or rec["enabled"]
            slot["fidelity"] = _best_fidelity(slot["fidelity"], rec["fidelity"])
        for tac in (rec["tactics"] or (["(untagged)"] if techs else [])):
            slot = by_tactic.setdefault(tac, {
                "tactic": tac,
                "title": killchain.tactic_title(tac) if tac != "(untagged)" else "(untagged)",
                "techniques": set(), "enabled_techniques": set(), "rules": 0})
            slot["rules"] += 1
            slot["techniques"].update(techs)
            if rec["enabled"]:
                slot["enabled_techniques"].update(techs)

    # technique-level fidelity + data-source rollups (per distinct covered technique)
    for slot in tech_index.values():
        if slot["enabled"]:
            fidelity_counts[slot["fidelity"]] = fidelity_counts.get(slot["fidelity"], 0) + 1
        for ds in slot["data_sources"]:
            data_source_counts.setdefault(ds, set()).add(slot["technique"])

    tactics_out = []
    for slot in sorted(by_tactic.values(), key=lambda s: killchain.tactic_rank(s["tactic"])):
        tactics_out.append({
            "tactic": slot["tactic"], "title": slot["title"], "rules": slot["rules"],
            "techniques": sorted(slot["techniques"]),
            "enabled_techniques": sorted(slot["enabled_techniques"]),
            "gaps": sorted(slot["techniques"] - slot["enabled_techniques"]),
        })

    ent = sorted(t for t, s in tech_index.items() if s["domain"] == "enterprise-attack" and s["enabled"])
    ics = sorted(t for t, s in tech_index.items() if s["domain"] == "ics-attack" and s["enabled"])
    techniques_out = {t: {
        "rules": sorted(set(s["rules"])), "fidelity": s["fidelity"],
        "data_sources": sorted(s["data_sources"]), "enabled": s["enabled"], "domain": s["domain"],
    } for t, s in sorted(tech_index.items())}

    return {
        "tactics": tactics_out,
        "techniques": techniques_out,
        "enterprise_covered": len(ent),
        "ics_covered": len(ics),
        "enterprise_pct": _pct(len(ent), ATTACK_ENTERPRISE_TOTAL),
        "ics_pct": _pct(len(ics), ATTACK_ICS_TOTAL),
        "fidelity": fidelity_counts,
        "data_sources": {ds: len(techs) for ds, techs in sorted(data_source_counts.items())},
        "untagged_rules": untagged,
    }


def atlas_coverage(rules: Iterable[Any]) -> dict[str, Any]:
    """Coverage of the curated ATLAS matrix (0% until AI/LLM telemetry lands)."""
    covered: dict[str, list[str]] = {}
    for r in rules:
        for tech in getattr(r, "atlas_techniques", []) or []:
            covered.setdefault(str(tech).upper(), []).append(getattr(r, "id", ""))

    tactics = []
    total_covered = 0
    for tac in ATLAS_MATRIX:
        techs = []
        for tid, name in tac["techniques"]:
            hit = sorted(set(covered.get(tid.upper(), [])))
            if hit:
                total_covered += 1
            techs.append({"id": tid, "name": name, "covered": bool(hit), "rules": hit})
        tactics.append({"tactic": tac["tactic"], "title": tac["title"], "techniques": techs})

    return {
        "tactics": tactics,
        "covered": total_covered,
        "total": _ATLAS_TOTAL,
        "coverage_pct": _pct(total_covered, _ATLAS_TOTAL),
    }


def coverage_report(det_rules: Iterable[Any],
                    corr_rules: Iterable[Any] = ()) -> dict[str, Any]:
    """The full scoreboard: ATT&CK (enterprise + ICS) + ATLAS + rule/fidelity stats."""
    det_rules = list(det_rules)
    corr_rules = list(corr_rules)
    all_rules = det_rules + corr_rules
    return {
        "attack": attack_coverage(all_rules),
        "atlas": atlas_coverage(all_rules),
        "rules": {
            "total": len(all_rules),
            "detection": len(det_rules),
            "correlation": len(corr_rules),
            "enabled": sum(1 for r in all_rules if getattr(r, "enabled", True)),
        },
    }


def navigator_layer(rules: Iterable[Any], domain: str = "enterprise-attack") -> dict:
    """A MITRE ATT&CK Navigator layer scored by *rules per technique* (coverage)."""
    counts: dict[str, int] = {}
    for r in rules:
        for tech in getattr(r, "techniques", []) or []:
            counts[str(tech).upper()] = counts.get(str(tech).upper(), 0) + 1
    label = "ICS" if domain == "ics-attack" else "Enterprise"
    return navigator.build_layer(
        counts, name=f"LogOcean detection coverage ({label})", domain=domain,
        description="Rules per MITRE ATT&CK technique in the LogOcean detection "
                    "pack (coverage, not alert volume).",
        comment_suffix="rule(s)")
