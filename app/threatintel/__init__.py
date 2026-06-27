"""Threat-intelligence enrichment: match ingested events against IOC feeds.

Indicators (IPs, CIDRs, domains, file hashes, URLs) are loaded from local files
or remote feeds into the `iocs` table, held in an in-memory index, and matched
against each event inline in the ingest pipeline — a hit raises a threat-intel
alert that flows through the normal alert → notify → response path.
"""
from .matcher import Ioc, IocHit, IocIndex, classify, normalize, ti_alert
from .runtime import get_index, reload_index, set_index, sync_feeds

__all__ = ["Ioc", "IocHit", "IocIndex", "classify", "normalize", "ti_alert",
           "get_index", "set_index", "reload_index", "sync_feeds"]
