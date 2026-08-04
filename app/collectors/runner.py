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
from .aws_s3 import AwsS3CloudTrailCollector
from .aws_services import (AwsConfigComplianceCollector, AwsGuardDutyCollector,
                           AwsRoute53ResolverCollector, AwsSecurityHubCollector)
from .base import Collector
from .cloud import (AwsCloudTrailCollector, EntraSignInCollector,
                    M365AuditCollector)
from .cortex import CortexDataLakeCollector
from .crowdstrike import (CrowdStrikeFdrCollector, CrowdStrikeIncidentCollector,
                          CrowdStrikeStreamCollector)
from .defender import DefenderAlertCollector, DefenderIncidentCollector
from .gcp import GcpAuditLogCollector
from .sources import GitHubCollector, GitLabCollector, OktaCollector
from .vuln import (QualysDetectionCollector, Rapid7InsightVmCollector,
                   TenableVulnExportCollector)
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
    # The AWS credential triple is shared by six collectors, so resolve it once —
    # `_cred` reads the vault, and doing it per collector would be six lookups for
    # one secret and six chances to forget the vault on a future addition.
    aws_creds = (settings.aws_region,
                 _cred("aws", "access_key_id", settings.aws_access_key_id),
                 _cred("aws", "secret_access_key", settings.aws_secret_access_key),
                 _cred("aws", "session_token", settings.aws_session_token))
    azure_secret = _cred("azure", "client_secret", settings.azure_client_secret)
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
        AwsCloudTrailCollector(*aws_creds, settings.collector_lookback_hours),
        # CloudTrail at full fidelity (management AND data events) off an SQS
        # notification queue. Self-gating: `configured()` is False without
        # aws_sqs_queue_url, so it may sit here unconditionally. It supersedes the
        # LookupEvents collector above for production use, and the two can run side
        # by side — separate checkpoint rows, and event dedup absorbs the overlap.
        AwsS3CloudTrailCollector(settings.aws_region, settings.aws_sqs_queue_url,
                                 aws_creds[1], aws_creds[2], aws_creds[3],
                                 settings.collector_lookback_hours),
        # Route 53 Resolver query logs, read out of CloudWatch Logs. Gated by
        # `configured()` on the log-group name, so no `if` is needed here.
        AwsRoute53ResolverCollector(*aws_creds, settings.aws_route53_log_group,
                                    settings.collector_lookback_hours),
        EntraSignInCollector(settings.azure_tenant_id, settings.azure_client_id,
                             azure_secret, settings.collector_lookback_hours),
        GcpAuditLogCollector(settings.gcp_project_id, settings.gcp_client_email,
                             _cred("gcp", "private_key", settings.gcp_private_key),
                             settings.gcp_token_uri,
                             settings.collector_lookback_hours),
        # Palo Alto Cortex Data Lake (Prisma Access). Gated by `configured()` on the
        # OAuth2 triple; the reshaped records ride the existing paloalto_csv parser.
        CortexDataLakeCollector(settings.cortex_region, settings.cortex_client_id,
                                _cred("cortex", "client_secret",
                                      settings.cortex_client_secret),
                                _cred("cortex", "refresh_token",
                                      settings.cortex_refresh_token),
                                settings.cortex_tables,
                                settings.collector_lookback_hours),
        # Vulnerability scanners — the sources that finally populate the CIM
        # Vulnerability model. Each gates on its own credentials, and all three
        # additionally hold a scanner-cadence floor so the shared 300s collector
        # tick is a true no-op between real pulls.
        QualysDetectionCollector(settings.qualys_base_url, settings.qualys_username,
                                 _cred("qualys", "password", settings.qualys_password),
                                 settings.collector_lookback_hours,
                                 settings.vuln_min_interval_seconds),
        TenableVulnExportCollector(_cred("tenable", "access_key",
                                         settings.tenable_access_key),
                                   _cred("tenable", "secret_key",
                                         settings.tenable_secret_key),
                                   settings.collector_lookback_hours,
                                   settings.vuln_min_interval_seconds),
        Rapid7InsightVmCollector(settings.rapid7_base_url, settings.rapid7_username,
                                 _cred("rapid7", "password", settings.rapid7_password),
                                 settings.collector_lookback_hours,
                                 settings.vuln_min_interval_seconds),
        # CrowdStrike Falcon Data Replicator. NOTE the credentials are CrowdStrike's
        # OWN AWS keys for the bucket they replicate into — a different account from
        # the customer's aws_* keys above, hence separate vault slots.
        CrowdStrikeFdrCollector(settings.crowdstrike_fdr_queue_url,
                                settings.crowdstrike_fdr_region,
                                _cred("crowdstrike", "fdr_access_key",
                                      settings.crowdstrike_fdr_access_key),
                                _cred("crowdstrike", "fdr_secret_key",
                                      settings.crowdstrike_fdr_secret_key),
                                _cred("crowdstrike", "fdr_session_token",
                                      settings.crowdstrike_fdr_session_token),
                                settings.crowdstrike_fdr_bucket),
    ]
    if settings.m365_enabled:
        candidates.append(
            M365AuditCollector(settings.azure_tenant_id, settings.azure_client_id,
                               azure_secret, settings.m365_content_type,
                               settings.collector_lookback_hours))
    if settings.defender_enabled:
        # Same Entra app registration (and therefore the same vault slot) as the two
        # collectors above; the extra gate is because Graph needs two more APPLICATION
        # permissions granted — SecurityAlert.Read.All / SecurityIncident.Read.All.
        candidates.append(
            DefenderAlertCollector(settings.azure_tenant_id, settings.azure_client_id,
                                   azure_secret, settings.collector_lookback_hours))
        candidates.append(
            DefenderIncidentCollector(settings.azure_tenant_id, settings.azure_client_id,
                                      azure_secret, settings.collector_lookback_hours,
                                      settings.defender_expand_alerts))
    # AWS security services. Coarse gates: the service has to be turned on in the
    # account or every poll errors — the settings.m365_enabled precedent.
    if settings.aws_guardduty_enabled:
        candidates.append(
            AwsGuardDutyCollector(*aws_creds, settings.aws_guardduty_detector_id,
                                  settings.collector_lookback_hours))
    if settings.aws_securityhub_enabled:
        candidates.append(
            AwsSecurityHubCollector(*aws_creds, settings.collector_lookback_hours))
    if settings.aws_config_compliance_enabled:
        candidates.append(
            AwsConfigComplianceCollector(*aws_creds, settings.collector_lookback_hours))
    # CrowdStrike Falcon REST APIs. Both gate on the OAuth2 pair, but Event Streams
    # additionally holds a per-appId session on Falcon's side and Incidents needs a
    # separate scope, so each is opt-in rather than activating on credentials alone.
    if settings.crowdstrike_streams_enabled:
        candidates.append(
            CrowdStrikeStreamCollector(settings.crowdstrike_base_url,
                                       settings.crowdstrike_client_id,
                                       _cred("crowdstrike", "client_secret",
                                             settings.crowdstrike_client_secret),
                                       settings.crowdstrike_app_id,
                                       settings.collector_lookback_hours))
    if settings.crowdstrike_incidents_enabled:
        candidates.append(
            CrowdStrikeIncidentCollector(settings.crowdstrike_base_url,
                                         settings.crowdstrike_client_id,
                                         _cred("crowdstrike", "client_secret",
                                               settings.crowdstrike_client_secret),
                                         settings.collector_lookback_hours))
    return [c for c in candidates if c.configured()]


#: The credential slots the shipped collectors read, for the admin UI's "known slots"
#: list and for the migration helper. Data, not behaviour: adding a collector adds a
#: row here so an operator can see what it needs without reading the code.
#:
#: ONE ROW PER CREDENTIAL, never per collector. Six AWS collectors share the three
#: `aws` slots and three Microsoft collectors share `azure/client_secret`; a duplicate
#: row would make this list lie about how many secrets an operator must supply, and
#: would double-count in `migrate_env_secrets`.
#:
#: INVARIANT: the third element LOWER-CASED must be the exact `Settings` attribute
#: name, because `migrate_env_secrets` does `getattr(settings, env_name.lower())` and
#: a mismatch silently migrates nothing. Pinned by tests/test_wiring.py.
KNOWN_SLOTS: tuple[tuple[str, str, str], ...] = (
    ("okta", "token", "OKTA_TOKEN"),
    ("github", "token", "GITHUB_TOKEN"),
    ("gitlab", "token", "GITLAB_TOKEN"),
    # Shared by AwsCloudTrail, AwsS3CloudTrail, GuardDuty, SecurityHub,
    # ConfigCompliance and Route53Resolver.
    ("aws", "access_key_id", "AWS_ACCESS_KEY_ID"),
    ("aws", "secret_access_key", "AWS_SECRET_ACCESS_KEY"),
    ("aws", "session_token", "AWS_SESSION_TOKEN"),
    # Shared by EntraSignIn, M365Audit and both Defender XDR collectors — one app
    # registration, one secret.
    ("azure", "client_secret", "AZURE_CLIENT_SECRET"),
    ("gcp", "private_key", "GCP_PRIVATE_KEY"),
    ("cortex", "client_secret", "CORTEX_CLIENT_SECRET"),
    ("cortex", "refresh_token", "CORTEX_REFRESH_TOKEN"),
    ("qualys", "password", "QUALYS_PASSWORD"),
    ("tenable", "access_key", "TENABLE_ACCESS_KEY"),
    ("tenable", "secret_key", "TENABLE_SECRET_KEY"),
    ("rapid7", "password", "RAPID7_PASSWORD"),
    # Falcon REST (Streams + Incidents) share one OAuth2 secret; FDR's AWS keys are
    # issued by CrowdStrike for THEIR bucket and are a different credential entirely.
    ("crowdstrike", "client_secret", "CROWDSTRIKE_CLIENT_SECRET"),
    ("crowdstrike", "fdr_access_key", "CROWDSTRIKE_FDR_ACCESS_KEY"),
    ("crowdstrike", "fdr_secret_key", "CROWDSTRIKE_FDR_SECRET_KEY"),
    ("crowdstrike", "fdr_session_token", "CROWDSTRIKE_FDR_SESSION_TOKEN"),
    # Not a collector: the HMAC key that signs and verifies side-loaded content
    # packs. It is a secret and belongs in the vault for the same reasons.
    ("contentpack", "key", "CONTENT_PACK_KEY"),
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
