"""Suppression / allowlist matching (pure, unit-testable).

A ``Suppression`` is a set of AND conditions over an alert's ``rule_id`` /
``vendor`` / ``user_name`` / ``host_name`` / ``src_ip``; every non-null condition
must match. ``src_ip`` accepts an exact IP or a CIDR. A suppression with no
conditions matches nothing (guarded), so an empty rule can't silence everything.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional

_CRITERIA = ("rule_id", "vendor", "user_name", "host_name", "src_ip")


@dataclass(frozen=True)
class Suppression:
    id: int
    name: str = ""
    rule_id: Optional[str] = None
    vendor: Optional[str] = None
    user_name: Optional[str] = None
    host_name: Optional[str] = None
    src_ip: Optional[str] = None      # exact IP or CIDR

    def is_empty(self) -> bool:
        return not any(getattr(self, c) for c in _CRITERIA)


def _ci_eq(a: Optional[str], b) -> bool:
    return a is not None and b is not None and str(a).lower() == str(b).lower()


def _ip_match(pattern: str, value) -> bool:
    if value in (None, ""):
        return False
    try:
        net = ipaddress.ip_network(str(pattern).strip(), strict=False)
    except ValueError:
        return str(pattern).strip().lower() == str(value).strip().lower()
    try:
        return ipaddress.ip_address(str(value).strip()) in net
    except ValueError:
        return False


def matches(s: Suppression, alert: dict) -> bool:
    """True if every condition the suppression sets is satisfied by `alert`."""
    if s.is_empty():
        return False
    if s.rule_id and s.rule_id != alert.get("rule_id"):
        return False
    if s.vendor and not _ci_eq(s.vendor, alert.get("vendor")):
        return False
    if s.user_name and not _ci_eq(s.user_name, alert.get("user_name")):
        return False
    if s.host_name and not _ci_eq(s.host_name, alert.get("host_name")):
        return False
    if s.src_ip and not _ip_match(s.src_ip, alert.get("src_ip")):
        return False
    return True


class SuppressionIndex:
    """Holds the enabled suppressions and finds the first one matching an alert."""

    def __init__(self, rules: Optional[list[Suppression]] = None):
        self.rules = [r for r in (rules or []) if not r.is_empty()]

    def add(self, s: Suppression) -> None:
        if not s.is_empty():
            self.rules.append(s)

    def __len__(self) -> int:
        return len(self.rules)

    def match(self, alert: dict) -> Optional[Suppression]:
        for s in self.rules:
            if matches(s, alert):
                return s
        return None
