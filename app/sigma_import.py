"""Import community **SigmaHQ** rules into LogOcean's native detection engine.

The thousands of open, ATT&CK-tagged Sigma rules are the fastest way to grow
coverage (Phase 1 of ``docs/DETECTION_COVERAGE_ROADMAP.md``). This module
translates a Sigma rule (the SigmaHQ YAML schema) into our own rule dict — the
same shape ``engine.rule_from_dict`` consumes — so imported rules run on the
telemetry our parsers already produce.

How the translation works
-------------------------
* **logsource → a gate selection.** Sigma's ``logsource`` (category / product /
  service) is mapped to a selection over our normalized fields (``action`` /
  ``log_type`` / ``vendor`` / ``product``) and AND-ed into the condition, so a
  ``process_creation`` rule only fires on process-create events (Sysmon EID 1 /
  Windows 4688 both normalize ``action=process-create``), a ``registry_set`` rule
  only on registry writes, etc.
* **fields pass through.** Sigma field names (``Image`` / ``CommandLine`` /
  ``TargetObject`` / ``DestinationPort`` …) are kept — our Sysmon / endpoint
  parsers lift these onto ``raw``, and the engine resolves raw keys
  case-insensitively, so they match as-is.
* **honest skips.** Anything we can't faithfully run is skipped *with a reason*
  (not silently imported dead): an unmapped logsource, an unsupported field
  modifier (``utf16`` / ``wide`` / ``expand`` / ``gzip`` …), a Sigma
  aggregation/correlation, or a deprecated / unsupported rule.

Attribution: SigmaHQ rules are under the Detection Rule License (DRL). The
original ``id`` / ``author`` and a source reference are preserved on each import.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterator, Optional

import yaml

# Field modifiers the engine.py evaluator supports (plus the re flag suffixes).
_SUPPORTED_MODS = {
    "contains", "startswith", "endswith", "all", "cased", "re",
    "cidr", "lt", "lte", "gt", "gte", "exists", "fieldref",
    "base64", "base64offset", "windash", "i", "m", "s",
}

# Windows/Sysmon category -> (gate selection over our fields, data-source key).
_WIN_CATEGORY = {
    "process_creation": ({"action": "process-create"}, "process_creation"),
    "registry_set": ({"action": ["registry-set", "registry-add-delete", "registry-rename"]}, "registry"),
    "registry_add": ({"action": ["registry-add-delete", "registry-set"]}, "registry"),
    "registry_delete": ({"action": ["registry-add-delete"]}, "registry"),
    "registry_event": ({"action": ["registry-set", "registry-add-delete", "registry-rename"]}, "registry"),
    "network_connection": ({"action": "network-connect"}, "network_connection"),
    "dns_query": ({"action": "dns-query"}, "dns"),
    "image_load": ({"action": "image-load"}, "image_load"),
    "file_event": ({"action": ["file-create", "file-delete"]}, "file_event"),
    "file_change": ({"action": ["file-create", "file-delete", "file-time-change"]}, "file_event"),
    "file_delete": ({"action": ["file-delete", "file-delete-detected"]}, "file_event"),
    "create_remote_thread": ({"action": "create-remote-thread"}, "process"),
    "process_access": ({"action": "process-access"}, "process"),
    "pipe_created": ({"action": "pipe-create"}, "named_pipe"),
    "wmi_event": ({"action": ["wmi-filter", "wmi-consumer", "wmi-binding"]}, "wmi"),
}
# product -> gate selection, for service/cloud logs identified by product alone.
_CLOUD_PRODUCT = {
    "aws": {"vendor": "aws"}, "gcp": {"vendor": "gcp"},
    "okta": {"vendor": "okta"}, "github": {"vendor": "github"},
    "azure": {"vendor": "microsoft"}, "m365": {"vendor": "microsoft"},
    "microsoft365": {"vendor": "microsoft"},
}

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _map_logsource(ls: dict) -> tuple[Optional[dict], Optional[str], Optional[str]]:
    """(gate_selection, data_source, skip_reason) for a Sigma logsource."""
    cat = str(ls.get("category") or "").lower()
    product = str(ls.get("product") or "").lower()
    service = str(ls.get("service") or "").lower()

    if cat in _WIN_CATEGORY and product in ("", "windows"):
        sel, ds = _WIN_CATEGORY[cat]
        return dict(sel), ds, None
    if product == "linux":
        if cat == "process_creation":
            return {"vendor": "linux", "action": "process-create"}, "linux", None
        if service == "auditd" or (not cat and not service):
            return {"vendor": "linux"}, "linux", None
        return None, None, f"unmapped-logsource:linux/{cat or service}"
    if product == "windows":
        if service in ("security", "wineventlog"):
            return {"vendor": "microsoft", "log_type": "security"}, "windows_security", None
        if service == "sysmon":
            return {"product": "sysmon"}, "sysmon", None
        if not cat and not service:
            return {"vendor": "microsoft"}, "windows", None
        return None, None, f"unmapped-logsource:windows/{service or cat}"
    if product in _CLOUD_PRODUCT:
        return dict(_CLOUD_PRODUCT[product]), product, None
    return None, None, f"unmapped-logsource:{product or '_'}/{cat or service or '_'}"


def _iter_mod_reasons(body: Any) -> Iterator[str]:
    """Yield a skip reason for any unsupported field modifier in a selection body."""
    if isinstance(body, dict):
        for key in body:
            for mod in str(key).split("|")[1:]:
                if mod.lower() not in _SUPPORTED_MODS:
                    yield f"unsupported-modifier:{mod.lower()}"
    elif isinstance(body, list):
        for item in body:
            yield from _iter_mod_reasons(item)


def _slug(text: str) -> str:
    return _SLUG_RE.sub("-", str(text).lower()).strip("-") or "rule"


def _rule_id(doc: dict, source: str) -> str:
    sid = str(doc.get("id") or "").strip()
    return f"sigma-{sid}" if sid else f"sigma-{_slug(doc.get('title') or Path(source).stem)}"


def _description(doc: dict) -> str:
    desc = str(doc.get("description") or "").strip()
    author = str(doc.get("author") or "").strip()
    sid = str(doc.get("id") or "").strip()
    note = f"[Imported from SigmaHQ (DRL). id: {sid or 'n/a'}; author: {author or 'n/a'}.]"
    return f"{desc}\n\n{note}" if desc else note


def _references(doc: dict) -> list[str]:
    refs = [str(r) for r in (doc.get("references") or []) if str(r).strip()]
    return refs + ["https://github.com/SigmaHQ/sigma"]


def translate(doc: dict, source: str = "") -> tuple[Optional[dict], Optional[str]]:
    """Translate a Sigma rule dict to a LogOcean rule dict, or (None, reason)."""
    if not isinstance(doc, dict):
        return None, "not-a-mapping"
    if doc.get("correlation"):
        return None, "sigma-correlation"          # temporal/aggregation — Phase 5
    detection = doc.get("detection")
    if not isinstance(detection, dict) or not detection:
        return None, "no-detection"
    status = str(doc.get("status") or "").lower()
    if status in ("deprecated", "unsupported"):
        return None, f"status-{status}"

    ls = doc.get("logsource")
    gate, data_source, reason = _map_logsource(ls if isinstance(ls, dict) else {})
    if reason:
        return None, reason

    for name, body in detection.items():
        if name == "condition":
            continue
        for r in _iter_mod_reasons(body):
            return None, r

    condition = detection.get("condition")
    if isinstance(condition, list):               # a list of conditions = OR
        condition = " or ".join(f"({c})" for c in condition)
    condition = str(condition or "").strip()
    if not condition:
        return None, "no-condition"
    if "|" in condition:                          # count()/near aggregation — unsupported
        return None, "aggregation-condition"

    gate_name = "_lo_logsource"
    new_detection = {k: v for k, v in detection.items() if k != "condition"}
    while gate_name in new_detection:
        gate_name += "_"
    new_detection[gate_name] = gate
    new_detection["condition"] = f"({condition}) and {gate_name}"

    tags = [str(t) for t in (doc.get("tags") or [])
            if str(t).lower().startswith(("attack.", "atlas."))]

    return {
        "id": _rule_id(doc, source),
        "title": str(doc.get("title") or "Untitled Sigma rule"),
        "level": str(doc.get("level") or "medium").lower(),
        "fidelity": "medium",
        "data_source": [data_source] if data_source else [],
        "description": _description(doc),
        "logsource": {},                          # gate lives in detection
        "detection": new_detection,
        "tags": tags,
        "references": _references(doc),
    }, None


def translate_dir(src) -> tuple[list[dict], dict]:
    """Translate every Sigma rule under ``src``. Returns (rules, report)."""
    rules: list[dict] = []
    reasons: dict[str, int] = {}
    scanned = 0
    base = Path(src)
    for path in sorted(base.rglob("*.yml")) + sorted(base.rglob("*.yaml")):
        try:
            docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        except (yaml.YAMLError, OSError):
            reasons["yaml-error"] = reasons.get("yaml-error", 0) + 1
            continue
        for doc in docs:
            if not isinstance(doc, dict) or not doc.get("detection"):
                continue
            scanned += 1
            rule, reason = translate(doc, source=str(path))
            if rule is not None:
                rules.append(rule)
            else:
                reasons[reason or "unknown"] = reasons.get(reason or "unknown", 0) + 1
    # de-duplicate by id (keep first)
    seen: set[str] = set()
    deduped = []
    for r in rules:
        if r["id"] not in seen:
            seen.add(r["id"])
            deduped.append(r)
    report = {
        "scanned": scanned,
        "imported": len(deduped),
        "skipped": sum(reasons.values()),
        "duplicates": len(rules) - len(deduped),
        "reasons": dict(sorted(reasons.items(), key=lambda kv: kv[1], reverse=True)),
    }
    return deduped, report


def dump_rule(rule: dict) -> str:
    """Serialize a translated rule to YAML with an attribution header comment."""
    header = ("# Imported from SigmaHQ (Detection Rule License). Do not edit by hand;\n"
              "# regenerate with scripts/import_sigma.py. See references: in the rule.\n")
    return header + yaml.safe_dump(rule, sort_keys=False, allow_unicode=True, width=100)
