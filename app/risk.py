"""UEBA / entity-risk core (pure, unit-testable).

Two responsibilities, both dependency-free:

* **Entity extraction** — pull the actors (user / host / ip) and their
  associations (user↔ip, user↔host, host↔ip) out of a NormalizedEvent, so the
  pipeline can maintain first-seen / last-seen baselines incrementally.
* **Risk scoring** — turn an entity's attributed alerts into a single score using
  severity weights with exponential time decay. The weights live here once and are
  rendered into SQL (``weight_case_sql``) so the ranking query and the Python
  scorer can't drift.
"""
from __future__ import annotations

from typing import Iterable

from .models import NormalizedEvent

# Entity type -> the alert/event column an entity of that type is attributed by.
ENTITY_COLUMN = {"user": "user_name", "host": "host_name", "ip": "src_ip"}

SEVERITY_WEIGHT = {"critical": 10.0, "high": 6.0, "medium": 3.0,
                   "low": 1.0, "informational": 0.5}


def severity_weight(level: str | None) -> float:
    return SEVERITY_WEIGHT.get((level or "").strip().lower(), 1.0)


def decay(age_seconds: float, half_life_days: float) -> float:
    """Recency weight in (0, 1]: 1.0 at age 0, 0.5 at one half-life. The SQL in
    ``db.top_risk_entities`` mirrors this with ``power(0.5, age / half_life)``."""
    hl = max(half_life_days, 1e-3) * 86400.0
    return 0.5 ** (max(age_seconds, 0.0) / hl)


def decayed_score(alerts: Iterable[tuple], half_life_days: float = 7.0) -> float:
    """Risk from `(level, age_seconds)` pairs: Σ weight(level) · decay(age)."""
    return sum(severity_weight(level) * decay(age, half_life_days)
               for level, age in alerts)


def weight_case_sql(col: str = "level") -> str:
    """A SQL ``CASE`` mapping a severity column to its weight (constants only)."""
    whens = " ".join(f"WHEN '{k}' THEN {v}" for k, v in SEVERITY_WEIGHT.items())
    return f"CASE lower({col}) {whens} ELSE 1 END"


# --------------------------------------------------------------------------- #
#  Entity / association extraction                                            #
# --------------------------------------------------------------------------- #
def event_entities(evt: NormalizedEvent) -> list[tuple[str, str]]:
    """The (type, value) entities an event touches."""
    out: list[tuple[str, str]] = []
    if evt.user_name:
        out.append(("user", str(evt.user_name)))
    if evt.host_name:
        out.append(("host", str(evt.host_name)))
    if evt.src_ip:
        out.append(("ip", str(evt.src_ip)))
    return out


def event_links(evt: NormalizedEvent) -> list[tuple[str, str, str, str]]:
    """The (type, value, peer_type, peer_value) associations an event implies."""
    u = str(evt.user_name) if evt.user_name else None
    h = str(evt.host_name) if evt.host_name else None
    s = str(evt.src_ip) if evt.src_ip else None
    d = str(evt.dst_ip) if evt.dst_ip else None
    links: list[tuple[str, str, str, str]] = []
    if u and s:
        links.append(("user", u, "ip", s))
    if u and h:
        links.append(("user", u, "host", h))
    if h and d:
        links.append(("host", h, "ip", d))
    return links
