# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""The resolver: one event -> one :class:`Resolution`.

PURE, and that is load-bearing rather than tidy. This exact function runs in two
places — `pipeline.write_stream` when an event is first stored, and
`db.backfill_assets` when history is re-derived after a registry edit. If those two
ever disagreed, a corrected row would differ from an identically-shaped freshly
ingested row for no reason an operator could see. `db.backfill_cim` documents the
same rule for CIM membership and pays a round trip per chunk to honour it; this
module is why the asset side gets it for free.

THE SUBJECT ASSET, and the honest limitation
--------------------------------------------
An event can touch two hosts. `events` carries ONE `asset_id`, resolved in this
order:

    host_name  ->  src_ip  ->  dst_ip

`host_name` first because it names the machine the event is *about* — endpoint
telemetry, authentication, process and file events all fill it, and for those there
is no ambiguity at all. `src_ip` before `dst_ip` because on the records where only
addresses are present (flow, firewall) the source is the actor, and "who did this"
is the question a subject column should answer.

For a flow between two declared hosts that ordering IS a choice, and the losing side
would be invisible if the subject column were the only output. It is not:
`context_tags` carries labels from EVERY side that resolved, role-prefixed — so
``dst:crown-jewel`` is queryable on a row whose subject is the source. That is the
trade the schema comment describes, and it is why the array exists.
"""
from __future__ import annotations

from typing import Any, Mapping, Optional

from .index import AssetIndex
from .models import EMPTY, Asset, Resolution
from .normalize import asset_candidates, identity_candidates, norm_ip

#: (event field, role prefix for context_tags), in subject precedence order.
_ASSET_FIELDS = (("host_name", "host"), ("src_ip", "src"), ("dst_ip", "dst"))


def _field(evt: Any, name: str) -> Any:
    """One field of an event-like object.

    Accepts BOTH a `NormalizedEvent` and a stored row (a mapping), because
    `backfill_assets` re-derives context straight from `SELECT`ed rows and must go
    through this same function — the whole reason this module is pure. `cim.match`
    takes the identical dual shape for the identical reason.
    """
    if isinstance(evt, Mapping):
        return evt.get(name)
    return getattr(evt, name, None)


def _asset_from_host(index: AssetIndex, value: Any) -> Optional[str]:
    for alias_type, alias_value in asset_candidates(value):
        if alias_type == "ip":
            hit = index.asset_for_ip(alias_value)
        else:
            hit = index.asset_for_alias(alias_type, alias_value)
        if hit:
            return hit
    return None


def _asset_from_ip(index: AssetIndex, value: Any) -> Optional[str]:
    ip = norm_ip(value)
    return index.asset_for_ip(ip) if ip else None


def _identity_id(index: AssetIndex, value: Any) -> Optional[str]:
    for alias_type, alias_value in identity_candidates(value):
        hit = index.identity_for_alias(alias_type, alias_value)
        if hit:
            return hit
    return None


def resolve(evt: Any, index: AssetIndex) -> Resolution:
    """Registry context for `evt`. Never raises on a malformed event.

    Returns :data:`models.EMPTY` when nothing is declared, which is the common case
    on an install that has not opened the registry — one boolean per event rather
    than a walk that cannot match anything.
    """
    if index.is_empty():
        return EMPTY

    # ---- every side that resolves, in subject precedence order ------------ #
    seen: dict[str, str] = {}                       # role -> asset_id
    for field, role in _ASSET_FIELDS:
        value = _field(evt, field)
        if not value:
            continue
        hit = (_asset_from_host(index, value) if field == "host_name"
               else _asset_from_ip(index, value))
        if hit:
            seen[role] = hit

    subject_role = next((role for _, role in _ASSET_FIELDS if role in seen), "")
    asset_id = seen.get(subject_role)
    asset: Optional[Asset] = index.asset(asset_id)

    identity_id = _identity_id(index, _field(evt, "user_name"))
    identity = index.identity(identity_id)

    # ---- context labels from EVERY resolved side -------------------------- #
    tags: list[str] = []
    for role, aid in seen.items():
        a = index.asset(aid)
        if a is not None:
            tags.extend(a.context_labels(role))
    if identity is not None:
        tags.extend(identity.context_labels())

    # Sorted + de-duplicated so the stored array is canonical: a row re-derived by
    # `backfill_assets` must be byte-identical to the same row written at ingest, or
    # the backfill would rewrite every heap tuple it touched for no change at all.
    ordered = tuple(sorted(set(tags)))

    return Resolution(
        asset_id=asset_id,
        asset_criticality=asset.criticality if asset is not None else None,
        identity_id=identity_id,
        identity_priority=identity.priority if identity is not None else None,
        context_tags=ordered,
        asset_via=subject_role,
    )
