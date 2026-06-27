"""Suppression runtime: hold the in-memory index and rebuild it from the DB.

The ingest pipeline calls ``get_index()`` per write; the lifespan calls
``reload_index()`` at startup and the UI calls it again after a suppression is
added, toggled or deleted.
"""
from __future__ import annotations

import logging

from .. import db
from .suppression import Suppression, SuppressionIndex

log = logging.getLogger("logocean")

_index = SuppressionIndex()


def get_index() -> SuppressionIndex:
    return _index


def set_index(index: SuppressionIndex) -> None:
    global _index
    _index = index


def reload_index() -> SuppressionIndex:
    """Rebuild the index from the enabled, unexpired suppressions in the DB."""
    index = SuppressionIndex()
    for row in db.enabled_suppressions():
        index.add(Suppression(
            id=row["id"], name=row.get("name") or "", rule_id=row.get("rule_id"),
            vendor=row.get("vendor"), user_name=row.get("user_name"),
            host_name=row.get("host_name"), src_ip=row.get("src_ip")))
    set_index(index)
    log.info("suppression index loaded: %d rule(s)", len(index))
    return index
