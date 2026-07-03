"""MITRE ATT&CK Navigator layer export (pure).

Turns per-technique alert counts into a Navigator layer JSON document that can be
loaded at https://mitre-attack.github.io/attack-navigator/ to visualize which
techniques are firing. No dependencies — just a dict the route serializes.
"""
from __future__ import annotations

from typing import Optional


def is_ics_technique(technique_id: str) -> bool:
    """ATT&CK for ICS technique IDs are ``T0NNN`` (Enterprise are T1/T2/…)."""
    return str(technique_id or "").upper().startswith("T0")


def _in_domain(technique_id: str, domain: str) -> bool:
    return is_ics_technique(technique_id) if domain == "ics-attack" \
        else not is_ics_technique(technique_id)


def build_layer(technique_counts: dict, days: int = 30,
                attack_version: str = "14", name: Optional[str] = None,
                domain: str = "enterprise-attack",
                description: Optional[str] = None,
                comment_suffix: str = "alert(s)") -> dict:
    """A Navigator (layer format 4.5) document scoring each technique by a count.

    ``domain`` selects the ATT&CK matrix: ``enterprise-attack`` (default) or
    ``ics-attack``. Techniques are filtered to the chosen domain by ID prefix
    (ICS = ``T0NNN``), so one call yields a clean single-domain layer. The default
    scoring is alert volume; pass ``description`` / ``comment_suffix`` to reuse the
    same builder for rule-coverage layers.
    """
    label = "ICS " if domain == "ics-attack" else ""
    techniques = sorted((t, int(n)) for t, n in (technique_counts or {}).items()
                        if t and _in_domain(t, domain))
    max_score = max((n for _, n in techniques), default=0)
    return {
        "name": name or f"LogOcean {label}alerts (last {days}d)".replace("  ", " "),
        "versions": {"attack": attack_version, "navigator": "4.9.0", "layer": "4.5"},
        "domain": domain,
        "description": description or
        "Alert volume per MITRE ATT&CK technique, from LogOcean detections.",
        "techniques": [
            {"techniqueID": t, "score": n, "comment": f"{n} {comment_suffix}",
             "color": "", "enabled": True}
            for t, n in techniques
        ],
        "gradient": {"colors": ["#ffe6e6", "#ff3333"], "minValue": 0,
                     "maxValue": max_score or 1},
        "legendItems": [],
        "metadata": [{"name": "source", "value": "LogOcean"}],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#2b3a4a",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "hideDisabled": False,
    }
