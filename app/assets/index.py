# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""The in-memory registry index — everything resolution needs, with no database.

Built once from the tables (`registry.py` does the loading) and then read by
`resolve.py` on the ingest hot path. Kept as its own module so the index can be
constructed from literals in a test without a database anywhere near it.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from typing import Iterable, Optional

from .models import Asset, Identity

#: Bound on the negative/positive memo for CIDR resolution. Cleared wholesale rather
#: than evicted LRU: this is a lookaside for repeated addresses within one ingest
#: window, not a cache anyone depends on, and a dict clear is O(1) against the
#: bookkeeping an LRU would cost on every single event.
_MEMO_MAX = 8192


class AssetIndex:
    """Alias -> asset/identity, plus containment for declared CIDRs.

    THREAD SAFETY. The index is immutable after construction except for `_ip_memo`,
    which is a pure lookaside: every entry is derivable from the immutable data, so a
    racing writer can only duplicate work, never produce a wrong answer. `dict`
    get/set/clear are individually atomic under the GIL, and nothing here does a
    read-modify-write across a yield point. That is what lets the ingest workers share
    one index without a lock on the hot path.
    """

    __slots__ = ("assets", "identities", "asset_alias", "identity_alias", "cidrs",
                 "fingerprint", "_ip_memo")

    def __init__(self, assets: Iterable[Asset] = (), identities: Iterable[Identity] = (),
                 asset_alias: Optional[dict[tuple[str, str], str]] = None,
                 identity_alias: Optional[dict[tuple[str, str], str]] = None):
        self.assets: dict[str, Asset] = {a.asset_id: a for a in assets if a.enabled}
        self.identities: dict[str, Identity] = {
            i.identity_id: i for i in identities if i.enabled}

        # An alias pointing at a disabled or deleted row is dropped at build time, so
        # the resolver never has to check `enabled` per event and can never hand back
        # an id with no object behind it.
        self.asset_alias = {k: v for k, v in (asset_alias or {}).items()
                            if v in self.assets}
        self.identity_alias = {k: v for k, v in (identity_alias or {}).items()
                               if v in self.identities}

        # Declared subnets, MOST SPECIFIC FIRST. Sorting by prefix length is what
        # makes containment deterministic: an address inside both 10.0.0.0/8 and
        # 10.1.2.0/24 belongs to the /24, always, rather than to whichever row the
        # database happened to return first.
        nets: list[tuple[ipaddress._BaseNetwork, str]] = []
        for (kind, value), asset_id in self.asset_alias.items():
            if kind != "cidr":
                continue
            try:
                nets.append((ipaddress.ip_network(value, strict=False), asset_id))
            except ValueError:
                continue
        nets.sort(key=lambda pair: (-pair[0].prefixlen, str(pair[0])))
        self.cidrs: tuple[tuple[object, str], ...] = tuple(nets)

        self.fingerprint = self._fingerprint()
        self._ip_memo: dict[str, Optional[str]] = {}

    # ---- lookups ---------------------------------------------------------- #
    def asset_for_alias(self, alias_type: str, value: str) -> Optional[str]:
        return self.asset_alias.get((alias_type, value))

    def identity_for_alias(self, alias_type: str, value: str) -> Optional[str]:
        return self.identity_alias.get((alias_type, value))

    def asset_for_ip(self, value: str) -> Optional[str]:
        """Exact `ip` alias first, then containment against declared CIDRs.

        Exact-before-containment is the whole point: a host declared individually
        must win over the subnet it sits in, or declaring one server inside an
        already-declared /24 would be silently ignored.

        The containment scan is linear in the number of declared CIDRs. That is the
        accepted cost — an operator declares tens of subnets, not thousands — and it
        is why the result is memoized: network traffic revisits the same addresses
        constantly, so the scan runs once per distinct address per reload rather than
        once per event.
        """
        hit = self.asset_alias.get(("ip", value))
        if hit is not None:
            return hit
        if not self.cidrs:
            return None
        memo = self._ip_memo
        if value in memo:
            return memo[value]
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return None
        found: Optional[str] = None
        for net, asset_id in self.cidrs:
            if addr.version == net.version and addr in net:
                found = asset_id
                break
        if len(memo) >= _MEMO_MAX:
            memo.clear()
        memo[value] = found
        return found

    def asset(self, asset_id: Optional[str]) -> Optional[Asset]:
        return self.assets.get(asset_id) if asset_id else None

    def identity(self, identity_id: Optional[str]) -> Optional[Identity]:
        return self.identities.get(identity_id) if identity_id else None

    # ---- bookkeeping ------------------------------------------------------ #
    def __len__(self) -> int:
        return len(self.assets) + len(self.identities)

    def is_empty(self) -> bool:
        """True when nothing is declared. The resolver short-circuits on this, so an
        install that never opens the registry pays one boolean per event."""
        return not self.assets and not self.identities

    def _fingerprint(self) -> str:
        """A stable hash of everything that can change a resolution.

        This is what `asset_meta.backfill_hash` is compared against to answer "has a
        registry edit reached stored history yet?", so it must cover exactly the
        fields that feed `Resolution` and nothing else — including `enabled`, since
        disabling an asset changes every future row, and excluding `notes`/`owner`
        display text, which cannot.
        """
        h = hashlib.sha256()
        for aid in sorted(self.assets):
            a = self.assets[aid]
            h.update(json.dumps([aid, a.criticality, sorted(a.category),
                                 sorted(a.watchlist), a.environment],
                                sort_keys=True).encode("utf-8"))
        for iid in sorted(self.identities):
            i = self.identities[iid]
            h.update(json.dumps([iid, i.priority, sorted(i.watchlist)],
                                sort_keys=True).encode("utf-8"))
        for key in sorted(self.asset_alias):
            h.update(f"a{key[0]}\x00{key[1]}\x00{self.asset_alias[key]}".encode("utf-8"))
        for key in sorted(self.identity_alias):
            h.update(f"i{key[0]}\x00{key[1]}\x00{self.identity_alias[key]}".encode("utf-8"))
        return h.hexdigest()[:32]


EMPTY_INDEX = AssetIndex()
