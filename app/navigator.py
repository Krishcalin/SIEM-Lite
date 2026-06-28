"""MITRE ATT&CK Navigator layer export (pure).

Turns per-technique alert counts into a Navigator layer JSON document that can be
loaded at https://mitre-attack.github.io/attack-navigator/ to visualize which
techniques are firing. No dependencies — just a dict the route serializes.
"""
from __future__ import annotations

from typing import Optional


def build_layer(technique_counts: dict, days: int = 30,
                attack_version: str = "14", name: Optional[str] = None) -> dict:
    """A Navigator (layer format 4.5) document scoring each technique by alert volume."""
    techniques = sorted((t, int(n)) for t, n in (technique_counts or {}).items() if t)
    max_score = max((n for _, n in techniques), default=0)
    return {
        "name": name or f"LogOcean alerts (last {days}d)",
        "versions": {"attack": attack_version, "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Alert volume per MITRE ATT&CK technique, from LogOcean detections.",
        "techniques": [
            {"techniqueID": t, "score": n, "comment": f"{n} alert(s)",
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
