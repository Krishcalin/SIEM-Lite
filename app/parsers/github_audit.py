"""GitHub audit log parser (organization / enterprise).

The GitHub audit-log API and exports return JSON entries (array or NDJSON). Each
has an ``action`` (e.g. ``repo.destroy``, ``git.push``), the ``actor`` and their
``actor_ip``, the affected ``org`` / ``repo``, and an ``@timestamp`` (epoch ms).
The full entry is kept in ``raw``.
"""
from __future__ import annotations

from typing import Iterator

from ..models import NormalizedEvent
from ..util import clean_ip, first, iter_json_records, parse_ts


def parse(content: str) -> Iterator[NormalizedEvent]:
    for rec in iter_json_records(content):
        action = rec.get("action")
        repo = first(rec.get("repo"), rec.get("repository"))
        category = str(action).split(".")[0] if action else None

        message = f"{action}" + (f" on {repo}" if repo else "")

        yield NormalizedEvent(
            event_time=parse_ts(first(rec.get("@timestamp"), rec.get("created_at"), rec.get("timestamp"))),
            vendor="github",
            product="audit",
            log_type=category,
            action=action,
            src_ip=clean_ip(rec.get("actor_ip")),
            user_name=first(rec.get("actor"), rec.get("user")),
            host_name=None,
            rule_name=first(repo, rec.get("org"), rec.get("business")),
            message=message or None,
            raw=rec,
        )
