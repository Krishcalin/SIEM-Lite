"""Prompt construction and response parsing for the AI SOC copilot (pure).

Everything here is dependency-free (except pyyaml, already a project dep) and
side-effect-free, so the prompt shapes and the Sigma-extraction logic are fully
unit-testable without an API key or network. The client wrapper in
``client.py`` turns these (system, user) pairs into Claude calls.
"""
from __future__ import annotations

import re
from typing import Any, Optional

import yaml

_MAX = 1500  # per-field character clamp so a hostile/huge value can't blow the prompt


def _clip(value: Any, limit: int = _MAX) -> str:
    s = "" if value is None else str(value)
    return s if len(s) <= limit else s[:limit] + " …[truncated]"


def _fmt_list(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value) or "—"
    return str(value) if value not in (None, "") else "—"


# --------------------------------------------------------------------------- #
#  Alert / case briefs                                                        #
# --------------------------------------------------------------------------- #
def alert_brief(alert: dict) -> str:
    """A compact, model-friendly rendering of one alert."""
    return "\n".join([
        f"- rule: {_clip(alert.get('rule_title') or alert.get('rule_id'))} "
        f"({alert.get('rule_id')})",
        f"- severity: {alert.get('level')}",
        f"- tactics: {_fmt_list(alert.get('tactics'))}",
        f"- techniques: {_fmt_list(alert.get('techniques'))}",
        f"- vendor: {alert.get('vendor') or '—'}",
        f"- src_ip: {alert.get('src_ip') or '—'}  dst_ip: {alert.get('dst_ip') or '—'}",
        f"- user: {alert.get('user_name') or '—'}  host: {alert.get('host_name') or '—'}",
        f"- event_time: {alert.get('event_time') or alert.get('created_at')}",
        f"- message: {_clip(alert.get('message'))}",
    ])


SOC_SYSTEM = (
    "You are a senior SOC analyst assistant embedded in a SIEM called LogOcean. "
    "You explain security alerts and incidents clearly and concisely for a Tier-1/2 "
    "analyst. Be specific and practical. Ground every statement in the data provided; "
    "if something is unknown or ambiguous, say so rather than inventing details. "
    "Never fabricate IPs, users, CVEs, or log fields that are not present. Prefer short "
    "paragraphs and tight bullet lists over long prose."
)


def build_alert_explain(alert: dict, related: Optional[list[dict]] = None) -> tuple[str, str]:
    """(system, user) asking Claude to triage one alert."""
    parts = [
        "Explain this security alert for an analyst triaging it right now.",
        "",
        "ALERT:",
        alert_brief(alert),
    ]
    if related:
        parts += ["", f"RELATED ALERTS (same entity, recent) — {len(related)} shown:"]
        for r in related[:8]:
            parts.append(
                f"  • [{r.get('level')}] {_clip(r.get('rule_title'), 80)} "
                f"(user={r.get('user_name') or '—'}, host={r.get('host_name') or '—'}, "
                f"src={r.get('src_ip') or '—'})"
            )
    parts += [
        "",
        "Answer with these sections (use the exact headings):",
        "What happened — 1-2 sentences in plain language.",
        "Why it fired — what the rule detects and what in this event matched.",
        "Severity & likelihood — is this likely a true positive or a false positive, and why.",
        "Triage steps — 3-5 concrete next actions for the analyst.",
        "Keep the whole response under ~250 words.",
    ]
    return SOC_SYSTEM, "\n".join(parts)


def build_case_summary(
    case: dict, alerts: list[dict], notes: Optional[list[dict]] = None
) -> tuple[str, str]:
    """(system, user) asking Claude to summarize an investigation case."""
    parts = [
        "Summarize this investigation case for a handoff / incident report.",
        "",
        f"CASE: {_clip(case.get('title'), 200)}",
        f"- severity: {case.get('severity')}  status: {case.get('status')}",
        f"- summary: {_clip(case.get('summary')) or '—'}",
        "",
        f"MEMBER ALERTS ({len(alerts)}):",
    ]
    for a in alerts[:25]:
        parts.append(
            f"  • [{a.get('level')}] {_clip(a.get('rule_title'), 80)} — "
            f"user={a.get('user_name') or '—'}, host={a.get('host_name') or '—'}, "
            f"src={a.get('src_ip') or '—'}, tactics={_fmt_list(a.get('tactics'))}"
        )
    if notes:
        parts += ["", "ANALYST NOTES:"]
        for n in notes[:10]:
            parts.append(f"  • {_clip(n.get('note'), 200)}")
    parts += [
        "",
        "Answer with these sections (use the exact headings):",
        "Summary — what this incident appears to be, in 2-3 sentences.",
        "Attack narrative — the likely sequence of events across the alerts, in ATT&CK order.",
        "Impacted entities — the users/hosts/IPs involved.",
        "Recommended actions — prioritized containment / investigation steps.",
        "Keep the whole response under ~300 words.",
    ]
    return SOC_SYSTEM, "\n".join(parts)


# --------------------------------------------------------------------------- #
#  Sigma-from-natural-language                                                 #
# --------------------------------------------------------------------------- #
SIGMA_SYSTEM = (
    "You are a detection engineer who writes Sigma rules for the LogOcean SIEM. "
    "LogOcean uses a Sigma SUBSET evaluated per event over normalized fields plus the "
    "raw record. Supported detection features: named selections with field matches, "
    "field modifiers |contains |startswith |endswith |re |cidr |all, numeric "
    "|lt |lte |gt |gte, |exists, |base64, |windash, list values (OR), and a "
    "'condition' combining selections with and/or/not/1 of/all of. Normalized field "
    "names include: vendor, product, log_type, severity, action, src_ip, dst_ip, "
    "src_port, dst_port, user_name, host_name, message. Optional logsource.product "
    "(windows/linux/aws/gcp/azure). Tag with attack.<tactic> and attack.<technique> "
    "when known. Output ONLY a single ```yaml code block containing the rule — no prose."
)


def build_sigma_from_nl(description: str, sample_event: Optional[str] = None) -> tuple[str, str]:
    parts = [
        "Write one Sigma-subset rule for LogOcean that detects the following:",
        "",
        _clip(description, 2000),
    ]
    if sample_event:
        parts += ["", "A sample event it should match (JSON):", _clip(sample_event, 1500)]
    parts += [
        "",
        "Include: title, id (kebab-case), level, logsource (if a product applies), "
        "detection (with a 'condition'), and tags. Output only the ```yaml block.",
    ]
    return SIGMA_SYSTEM, "\n".join(parts)


_FENCE_RE = re.compile(r"```(?:ya?ml)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)


def extract_yaml(text: str) -> Optional[str]:
    """Pull a YAML rule out of a model response.

    Prefers a fenced ```yaml block; falls back to the whole text if it parses as a
    mapping with a 'detection' key. Returns None if nothing rule-shaped is found.
    """
    if not text:
        return None
    for m in _FENCE_RE.finditer(text):
        body = m.group(1).strip()
        if body:
            return body
    stripped = text.strip()
    try:
        doc = yaml.safe_load(stripped)
    except yaml.YAMLError:
        return None
    if isinstance(doc, dict) and doc.get("detection"):
        return stripped
    return None


def valid_sigma(yaml_text: str) -> tuple[bool, str]:
    """Cheap structural check that extracted YAML is a usable rule."""
    if not yaml_text or not yaml_text.strip():
        return False, "empty rule"
    try:
        doc = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        return False, f"YAML parse error: {e}"
    if not isinstance(doc, dict):
        return False, "rule is not a YAML mapping"
    if not doc.get("detection"):
        return False, "rule has no 'detection' block"
    det = doc["detection"]
    if not isinstance(det, dict) or "condition" not in det:
        return False, "detection block has no 'condition'"
    return True, "ok"
