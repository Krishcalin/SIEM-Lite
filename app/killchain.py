"""Kill-chain / attack-story reconstruction (pure, unit-testable).

Individual alerts describe single steps; an intrusion is a *sequence* of steps
by the same actor across ATT&CK tactics over time. This module stitches related
alerts into ordered **attack stories**:

* alerts are linked when they share an entity (user / host / ip) and fall within
  a time gap of one another (single-linkage along each entity's timeline);
* a linked group only qualifies as a story when it spans **multiple distinct
  ATT&CK tactics** — i.e. it shows progression along the kill chain, not just a
  burst of one behaviour;
* a qualifying group is summarised into kill-chain-ordered *stages*, the pivot
  entities that tie it together, a rolled-up severity, a time span, and a plain
  narrative — ready to become an investigation case.

Everything here is dependency-free and operates on plain alert dicts, so the
whole reconstruction is testable without a database.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from .severity import max_severity

# ATT&CK Enterprise tactics in kill-chain order. Stored alert tactics use the
# space/underscore lowercase form (e.g. "credential access"); we normalise to
# the hyphenated key below.
KILL_CHAIN_TACTICS: tuple[str, ...] = (
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion",
    "credential-access", "discovery", "lateral-movement", "collection",
    "command-and-control", "exfiltration", "impact",
)
_TACTIC_RANK = {t: i for i, t in enumerate(KILL_CHAIN_TACTICS)}
_UNKNOWN_RANK = len(KILL_CHAIN_TACTICS)

# Alert column an entity of each type is attributed by (mirrors risk.ENTITY_COLUMN).
_ENTITY_FIELDS = (("user", "user_name"), ("host", "host_name"), ("ip", "src_ip"))


def normalize_tactic(tactic: Any) -> str:
    """Canonicalise a tactic label to its hyphenated kill-chain key.

    Handles the stored form ("credential access"), Sigma tags ("attack.
    credential_access"), and already-hyphenated values.
    """
    s = str(tactic or "").strip().lower()
    if s.startswith("attack."):
        s = s.split(".", 1)[1]
    return s.replace("_", "-").replace(" ", "-")


def tactic_rank(tactic: Any) -> int:
    """Kill-chain position of a tactic (unknown/empty sort last)."""
    return _TACTIC_RANK.get(normalize_tactic(tactic), _UNKNOWN_RANK)


def tactic_title(tactic: Any) -> str:
    """Human label for a normalised tactic key, e.g. 'credential-access' →
    'Credential Access'."""
    return normalize_tactic(tactic).replace("-", " ").title()


def alert_tactics(alert: dict) -> list[str]:
    """Distinct, known, kill-chain-ordered tactics attributed to an alert."""
    seen = {normalize_tactic(t) for t in (alert.get("tactics") or [])}
    known = [t for t in seen if t in _TACTIC_RANK]
    return sorted(known, key=tactic_rank)


def alert_entities(alert: dict) -> set[tuple[str, str]]:
    """The (type, value) actors an alert touches (user / host / ip)."""
    out: set[tuple[str, str]] = set()
    for etype, field in _ENTITY_FIELDS:
        val = alert.get(field)
        if val not in (None, ""):
            out.add((etype, str(val)))
    return out


def _epoch(value: Any) -> Optional[float]:
    """Best-effort conversion of an alert timestamp to epoch seconds."""
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return datetime.fromisoformat(str(value)).timestamp()
    except ValueError:
        return None


def alert_time(alert: dict) -> Optional[float]:
    """Epoch seconds for an alert, preferring event_time over created_at."""
    return _epoch(alert.get("event_time")) or _epoch(alert.get("created_at"))


class _DisjointSet:
    """Minimal union-find over hashable ids."""

    def __init__(self) -> None:
        self._parent: dict[Any, Any] = {}

    def add(self, x: Any) -> None:
        self._parent.setdefault(x, x)

    def find(self, x: Any) -> Any:
        root = x
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[x] != root:      # path compression
            self._parent[x], x = root, self._parent[x]
        return root

    def union(self, a: Any, b: Any) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self._parent[ra] = rb


def build_chains(
    alerts: Iterable[dict],
    *,
    max_gap_seconds: float = 3600.0,
    min_tactics: int = 2,
) -> list[list[dict]]:
    """Group alerts into kill-chains.

    Two alerts are linked when they share an entity and occur within
    ``max_gap_seconds`` of each other; linkage is single-linkage, so a long
    campaign chained through intermediate alerts stays one chain. Only groups
    spanning at least ``min_tactics`` distinct ATT&CK tactics are returned.

    Returns a list of chains (each a list of the original alert dicts), ordered
    by descending member count then earliest activity.
    """
    items = [a for a in alerts if a.get("id") is not None]
    ds = _DisjointSet()
    for a in items:
        ds.add(a["id"])

    ts = {a["id"]: (alert_time(a) or 0.0) for a in items}

    # For each entity, walk its alerts in time order and union neighbours that
    # fall within the gap — O(sum k log k) rather than O(n^2).
    entity_members: dict[tuple[str, str], list[Any]] = {}
    for a in items:
        for ent in alert_entities(a):
            entity_members.setdefault(ent, []).append(a["id"])

    for members in entity_members.values():
        members.sort(key=lambda i: ts[i])
        for prev, cur in zip(members, members[1:]):
            if ts[cur] - ts[prev] <= max_gap_seconds:
                ds.union(prev, cur)

    groups: dict[Any, list[dict]] = {}
    for a in items:
        groups.setdefault(ds.find(a["id"]), []).append(a)

    chains: list[list[dict]] = []
    for members in groups.values():
        tactics = {t for a in members for t in alert_tactics(a)}
        if len(tactics) >= min_tactics:
            chains.append(members)

    chains.sort(key=lambda c: (-len(c), min(ts[a["id"]] for a in c)))
    return chains


def _pivot_entities(alerts: list[dict]) -> list[dict]:
    """Entities shared by two or more alerts — what ties the chain together."""
    counts: dict[tuple[str, str], int] = {}
    for a in alerts:
        for ent in alert_entities(a):
            counts[ent] = counts.get(ent, 0) + 1
    shared = [(etype, val, n) for (etype, val), n in counts.items() if n >= 2]
    shared.sort(key=lambda t: (-t[2], t[0], t[1]))
    return [{"type": e, "value": v, "count": n} for e, v, n in shared]


def summarize_chain(alerts: list[dict]) -> dict:
    """Turn a chain of alerts into a structured attack story.

    The returned dict is JSON-friendly (for templates and tests) and contains:
    ``stages`` (kill-chain-ordered, one per tactic), ``entities`` (pivots),
    ``techniques``, ``severity`` (max of members), ``level`` alias,
    ``alert_ids``, ``first_time`` / ``last_time`` / ``span_seconds``,
    ``alert_count``, ``tactic_count``, ``title``, ``narrative`` and a stable
    ``signature`` (for de-duplicating auto-created cases).
    """
    ordered = sorted(alerts, key=lambda a: (alert_time(a) or 0.0))

    stage_map: dict[str, dict] = {}
    for a in ordered:
        at = alert_time(a)
        for tac in alert_tactics(a):
            st = stage_map.setdefault(tac, {
                "tactic": tac, "title": tactic_title(tac), "rank": tactic_rank(tac),
                "alerts": [], "techniques": set(), "first_time": at, "last_time": at,
            })
            st["alerts"].append(a)
            st["techniques"].update(a.get("techniques") or [])
            if at is not None:
                st["first_time"] = min(st["first_time"] or at, at)
                st["last_time"] = max(st["last_time"] or at, at)

    stages = sorted(stage_map.values(), key=lambda s: s["rank"])
    for st in stages:
        st["techniques"] = sorted(st["techniques"])
        st["count"] = len(st["alerts"])

    techniques = sorted({t for a in ordered for t in (a.get("techniques") or [])})
    severity = max_severity([a.get("level") for a in ordered], default="medium")
    entities = _pivot_entities(ordered)
    times = [t for t in (alert_time(a) for a in ordered) if t is not None]
    first_t, last_t = (min(times), max(times)) if times else (None, None)

    pivot = entities[0] if entities else None
    pivot_label = f"{pivot['type']} {pivot['value']}" if pivot else "shared entity"
    stage_titles = [s["title"] for s in stages]
    flow = " → ".join(stage_titles)
    title = f"{flow} on {pivot_label}"
    narrative = (
        f"{len(ordered)} alerts spanning {len(stages)} ATT&CK tactics "
        f"({flow}) linked by {pivot_label}"
        + (f" and {len(entities) - 1} more entity(ies)" if len(entities) > 1 else "")
        + "."
    )

    alert_ids = sorted(a["id"] for a in ordered)
    signature = hashlib.sha256(
        ("kc|" + ",".join(str(i) for i in alert_ids)).encode("utf-8")
    ).hexdigest()

    return {
        "title": title[:200],
        "narrative": narrative,
        "severity": severity,
        "level": severity,
        "stages": stages,
        "entities": entities,
        "techniques": techniques,
        "alerts": ordered,
        "alert_ids": alert_ids,
        "alert_count": len(ordered),
        "tactic_count": len(stages),
        "first_time": first_t,
        "last_time": last_t,
        "span_seconds": (last_t - first_t) if (first_t is not None and last_t is not None) else None,
        "signature": signature,
    }


def reconstruct(
    alerts: Iterable[dict],
    *,
    max_gap_seconds: float = 3600.0,
    min_tactics: int = 2,
) -> list[dict]:
    """Build and summarise every qualifying attack story from ``alerts``.

    Stories are ordered by rolled-up severity (highest first), then by tactic
    span, then by recency — the order an analyst should triage them in.
    """
    from .severity import severity_rank

    stories = [
        summarize_chain(chain)
        for chain in build_chains(
            alerts, max_gap_seconds=max_gap_seconds, min_tactics=min_tactics)
    ]
    stories.sort(key=lambda s: (
        -severity_rank(s["severity"]),
        -s["tactic_count"],
        -(s["last_time"] or 0.0),
    ))
    return stories
