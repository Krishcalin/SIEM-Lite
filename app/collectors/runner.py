# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Collector orchestration: build configured collectors, run one (pull -> ingest
-> persist cursor), and a background scheduler that polls the enabled ones.

`run_collector` feeds the fetched text through the normal ingest path, so pulled
logs get the same parse -> detect -> alert -> notify/respond treatment as uploads.
"""
from __future__ import annotations

import asyncio
import logging

from starlette.concurrency import run_in_threadpool

from .. import db, ingest
from ..config import settings
from .base import Collector
from .cloud import (AwsCloudTrailCollector, EntraSignInCollector,
                    M365AuditCollector)
from .gcp import GcpAuditLogCollector
from .sources import GitHubCollector, GitLabCollector, OktaCollector
from .. import vault

log = logging.getLogger("logocean")


def _cred(integration: str, name: str, env_value: str) -> str:
    """One credential, resolved through the vault with the env var as the fallback.

    Every secret below goes through here rather than reading `settings.*` directly, so
    an operator can migrate integrations into the vault one at a time. `env_value` is
    what this call used to be, passed in so the vault never needs a slot->setting map.
    """
    return vault.get(integration, name, env_value)


def build_collectors() -> list[Collector]:
    """Instantiate the collectors whose credentials are configured.

    Credentials resolve VAULT FIRST, then the plaintext environment variable (see
    `app/vault/resolve.py`). Non-secret settings — domains, org names, regions, the
    lookback window — are read straight off `settings` as before; only the secrets move.
    """
    candidates = [
        OktaCollector(settings.okta_domain,
                      _cred("okta", "token", settings.okta_token),
                      settings.collector_lookback_hours),
        GitHubCollector(settings.github_org,
                        _cred("github", "token", settings.github_token),
                        settings.collector_lookback_hours),
        GitLabCollector(settings.gitlab_url,
                        _cred("gitlab", "token", settings.gitlab_token),
                        settings.collector_lookback_hours),
        AwsCloudTrailCollector(settings.aws_region,
                               _cred("aws", "access_key_id",
                                     settings.aws_access_key_id),
                               _cred("aws", "secret_access_key",
                                     settings.aws_secret_access_key),
                               _cred("aws", "session_token",
                                     settings.aws_session_token),
                               settings.collector_lookback_hours),
        EntraSignInCollector(settings.azure_tenant_id, settings.azure_client_id,
                             _cred("azure", "client_secret",
                                   settings.azure_client_secret),
                             settings.collector_lookback_hours),
        GcpAuditLogCollector(settings.gcp_project_id, settings.gcp_client_email,
                             _cred("gcp", "private_key", settings.gcp_private_key),
                             settings.gcp_token_uri,
                             settings.collector_lookback_hours),
    ]
    if settings.m365_enabled:
        candidates.append(
            M365AuditCollector(settings.azure_tenant_id, settings.azure_client_id,
                               _cred("azure", "client_secret",
                                     settings.azure_client_secret),
                               settings.m365_content_type,
                               settings.collector_lookback_hours))
    return [c for c in candidates if c.configured()]


#: The credential slots the shipped collectors read, for the admin UI's "known slots"
#: list and for the migration helper. Data, not behaviour: adding a collector adds a
#: row here so an operator can see what it needs without reading the code.
KNOWN_SLOTS: tuple[tuple[str, str, str], ...] = (
    ("okta", "token", "OKTA_TOKEN"),
    ("github", "token", "GITHUB_TOKEN"),
    ("gitlab", "token", "GITLAB_TOKEN"),
    ("aws", "access_key_id", "AWS_ACCESS_KEY_ID"),
    ("aws", "secret_access_key", "AWS_SECRET_ACCESS_KEY"),
    ("aws", "session_token", "AWS_SESSION_TOKEN"),
    ("azure", "client_secret", "AZURE_CLIENT_SECRET"),
    ("gcp", "private_key", "GCP_PRIVATE_KEY"),
)


def migrate_env_secrets(updated_by: str = "") -> list[str]:
    """Import any plaintext env-var credential that is set but not yet in the vault.

    Idempotent and non-destructive: a slot already in the vault is left alone (the vault
    is authoritative once populated), and the environment variable is NOT cleared —
    unsetting it is the operator's step, deliberately, so they can verify collectors
    still work before removing their fallback.
    """
    from .. import db
    done = []
    have = {(r["integration"], r["name"]) for r in db.list_secrets()}
    for integration, name, env_name in KNOWN_SLOTS:
        if (integration, name) in have:
            continue
        value = getattr(settings, env_name.lower(), "")
        if value:
            vault.set_secret(integration, name, value, updated_by)
            done.append(f"{integration}/{name}")
    return done


def run_collector(c: Collector) -> int:
    """Pull new records for one collector, ingest them, advance its cursor.
    Returns the number of records fetched. Blocking; runs in a threadpool."""
    state = db.get_collector(c.name) or {}
    cursor = state.get("cursor")
    try:
        result = c.fetch(cursor)
    except Exception as exc:  # noqa: BLE001
        db.update_collector(c.name, last_status="error", last_error=str(exc)[:300])
        log.exception("collector %s fetch failed", c.name)
        return 0
    if result.content and result.content.strip():
        try:
            ingest.ingest(result.content, c.fmt,
                          source_type="collector", source_addr=c.name)
        except Exception as exc:  # noqa: BLE001
            db.update_collector(c.name, last_status="error", last_error=str(exc)[:300])
            log.exception("collector %s ingest failed", c.name)
            return 0
    db.update_collector(c.name, cursor=result.cursor, last_status="ok",
                        last_count=result.count, last_error=None)
    return result.count


class CollectorScheduler:
    """Polls the enabled, configured collectors every `interval` seconds."""

    def __init__(self, collectors: list[Collector], interval: int):
        self.collectors = collectors
        self.interval = max(interval, 30)
        self._task = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._loop())
        log.info("collector scheduler started: %d collector(s), every %ds",
                 len(self.collectors), self.interval)

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _loop(self) -> None:
        while True:
            await asyncio.sleep(self.interval)
            try:
                await run_in_threadpool(self._run_all)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("collector run failed")

    def _run_all(self) -> None:
        enabled = db.enabled_collector_names()
        for c in self.collectors:
            if c.name in enabled:
                try:
                    run_collector(c)
                except Exception:  # noqa: BLE001
                    log.exception("collector %s failed", c.name)


_scheduler = None


def get_scheduler():
    return _scheduler


def set_scheduler(s) -> None:
    global _scheduler
    _scheduler = s
