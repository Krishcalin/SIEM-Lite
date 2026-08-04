# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Alias canonicalization — the half of alias resolution that decides what "the same
identifier" means.

Every alias is normalized ON WRITE, so `asset_aliases.alias_value` and
`identity_aliases.alias_value` hold canonical text and the ingest path does one dict
lookup with no per-row transformation of the stored side. The event side is
normalized by the same functions, which is the only thing that makes the two meet.

WHAT IS DELIBERATELY *NOT* NORMALIZED
-------------------------------------
The temptation in an identity registry is to be helpful: map an email's local part
onto a bare username, strip a domain, guess that `jdoe` and `j.doe` are the same
person. Every one of those is a WRONG-MERGE risk, and a wrong merge here does not
degrade gracefully — it attributes one person's activity to another, in the table a
detection reads to decide who to alert on. So the rules below are all
identity-preserving (case, whitespace, address form, separator style) and none of
them invents a relationship. Two spellings of one person are two ALIASES, declared
by the operator; the registry never guesses at a third.

The one exception is the DOMAIN\\user pair, and it is not a guess: `CORP\\jdoe`
literally contains its own bare form, so both are offered as candidates in a defined
order (qualified first). An operator who declares only `jdoe` still matches, and one
who declares `corp\\jdoe` is not shadowed by a different domain's `jdoe`.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Optional

from .models import ASSET_ALIAS_TYPES, IDENTITY_ALIAS_TYPES

_MAC_SEP = re.compile(r"[^0-9a-fA-F]")
_HEX12 = re.compile(r"^[0-9a-f]{12}$")


def norm_hostname(value: object) -> Optional[str]:
    """Lower-cased, trailing-dot-stripped host label. ``WKS-01.`` -> ``wks-01``."""
    s = str(value or "").strip().rstrip(".").lower()
    return s or None


def norm_fqdn(value: object) -> Optional[str]:
    """Same rules as a hostname; a separate type so an operator can declare
    ``wks-01`` and ``wks-01.corp.example`` as different aliases of one asset without
    either shadowing the other."""
    return norm_hostname(value)


def norm_ip(value: object) -> Optional[str]:
    """Canonical address text, or None.

    Through `ipaddress` rather than a string compare, so ``10.1.1.1`` and
    ``010.1.1.1`` cannot be declared as two separate aliases of two different assets.

    AN IPv4-MAPPED IPv6 ADDRESS IS UNWRAPPED to its IPv4 form. Dual-stack sockets and
    JVM-based servers routinely log ``::ffff:10.1.1.1`` for what is plainly
    ``10.1.1.1``, and Python renders that as ``::ffff:a01:101`` — a third spelling
    that matches neither the readable mapped form nor the address an operator
    actually declared. Without this, a host declared by its IPv4 address is simply
    unresolvable from half its own traffic.
    """
    s = str(value or "").strip()
    if not s:
        return None
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return None
    mapped = getattr(addr, "ipv4_mapped", None)
    return str(mapped if mapped is not None else addr)


def norm_cidr(value: object) -> Optional[str]:
    """Canonical network text, or None. ``strict=False`` so ``10.1.1.5/24`` is
    accepted and stored as ``10.1.1.0/24`` — an operator writing a host address with
    a prefix means the network, and refusing it would be pedantry that costs a
    declared subnet."""
    s = str(value or "").strip()
    if not s:
        return None
    try:
        return str(ipaddress.ip_network(s, strict=False))
    except ValueError:
        return None


def norm_mac(value: object) -> Optional[str]:
    """``AA-BB-CC-DD-EE-FF``, ``aabb.ccdd.eeff`` and ``aa:bb:cc:dd:ee:ff`` all become
    ``aa:bb:cc:dd:ee:ff``. Vendors disagree on the separator and nothing else."""
    raw = _MAC_SEP.sub("", str(value or "")).lower()
    if not _HEX12.match(raw):
        return None
    return ":".join(raw[i:i + 2] for i in range(0, 12, 2))


def norm_email(value: object) -> Optional[str]:
    """Lower-cased address. The local part is case-sensitive per RFC 5321 and
    case-insensitive in every directory anyone actually runs; matching the directory
    is the useful behaviour."""
    s = str(value or "").strip().lower()
    return s if "@" in s and len(s) > 2 else None


def norm_upn(value: object) -> Optional[str]:
    """A userPrincipalName — same shape as an email, kept as its own type because a
    UPN and a mailbox are frequently different strings for one person."""
    return norm_email(value)


def norm_sam(value: object) -> Optional[str]:
    """A down-level logon name. ``CORP\\JDoe`` -> ``corp\\jdoe``; a bare ``JDoe`` ->
    ``jdoe``. The domain is PRESERVED when present — dropping it would merge
    ``corp\\jdoe`` with a partner domain's ``jdoe``, which is the wrong-merge this
    module exists to avoid."""
    s = str(value or "").strip().lower().replace("/", "\\")
    return s or None


def norm_plain(value: object) -> Optional[str]:
    """Trimmed, lower-cased text — for `employee_id` and `cn`, which have no
    structure worth interpreting."""
    s = str(value or "").strip().lower()
    return s or None


_ASSET_NORMALIZERS = {"hostname": norm_hostname, "fqdn": norm_fqdn, "ip": norm_ip,
                      "cidr": norm_cidr, "mac": norm_mac}
_IDENTITY_NORMALIZERS = {"email": norm_email, "upn": norm_upn, "sam": norm_sam,
                         "employee_id": norm_plain, "cn": norm_plain}


def norm_alias(alias_type: str, value: object) -> Optional[str]:
    """Canonicalize one alias for its declared type, or None if it is unusable.

    Returns None for an unknown type rather than falling back to `norm_plain`: an
    unknown type is a typo in an import, and storing it under a lenient
    normalization would create a row that can never be matched by anything.
    """
    t = (alias_type or "").strip().lower()
    fn = _ASSET_NORMALIZERS.get(t) or _IDENTITY_NORMALIZERS.get(t)
    return fn(value) if fn else None


def alias_type_valid(alias_type: str, *, identity: bool = False) -> bool:
    t = (alias_type or "").strip().lower()
    return t in (IDENTITY_ALIAS_TYPES if identity else ASSET_ALIAS_TYPES)


# --------------------------------------------------------------------------- #
#  Candidate extraction: one event value -> the aliases that could match it    #
# --------------------------------------------------------------------------- #
def asset_candidates(value: object) -> list[tuple[str, str]]:
    """``(alias_type, alias_value)`` pairs to try for a host-ish event field, most
    specific first.

    A dotted name yields BOTH the full `fqdn` and its short `hostname` label, so an
    operator who declared only ``wks-01`` still matches an event carrying
    ``wks-01.corp.example`` — and one who declared the FQDN is matched by it first,
    which is what keeps two hosts with the same short name in different domains
    distinguishable.
    """
    s = norm_hostname(value)
    if not s:
        return []
    # An address in a host field is an address, not a name — resolve it as one, or a
    # declared `ip` alias would be unreachable from `host_name`.
    ip = norm_ip(s)
    if ip:
        return [("ip", ip)]
    out = [("fqdn", s)] if "." in s else []
    short = s.split(".", 1)[0]
    if short:
        out.append(("hostname", short))
    return out


def identity_candidates(value: object) -> list[tuple[str, str]]:
    """``(alias_type, alias_value)`` pairs to try for a user-ish event field, most
    specific first.

    Note what is absent: an email's local part is never offered as a `sam`. It looks
    like a free win and it is the classic wrong merge — ``jdoe@partner.example``
    would resolve to the internal ``jdoe``, and every action by an outside party
    would be attributed to an employee.
    """
    s = str(value or "").strip()
    if not s:
        return []
    if "@" in s:
        low = s.lower()
        return [("upn", low), ("email", low)]
    if "\\" in s or "/" in s:
        full = norm_sam(s)
        bare = full.rsplit("\\", 1)[-1] if full else ""
        out = [("sam", full)] if full else []
        if bare and bare != full:
            out.append(("sam", bare))
        return out
    low = norm_plain(s)
    return [("sam", low), ("employee_id", low)] if low else []
