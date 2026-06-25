"""Concrete token-based REST collectors (Okta, GitHub, GitLab).

Each uses a plain Bearer/token API over stdlib urllib (no SDK), pulls records
since the stored cursor, and feeds the vendor's existing parser. URL builders +
cursor advancement are pure functions so they're unit-tested without network.
"""
from __future__ import annotations

from typing import Optional
from urllib.parse import quote

from .base import Collector, FetchResult, iso_lookback, json_records, max_time_iso


# --------------------------------------------------------------------------- #
#  Okta System Log                                                            #
# --------------------------------------------------------------------------- #
def okta_url(domain: str, since: str) -> str:
    return f"{domain.rstrip('/')}/api/v1/logs?since={quote(since)}&limit=1000"


class OktaCollector(Collector):
    name, fmt, label = "okta", "okta_system_log", "Okta System Log"

    def __init__(self, domain: str, token: str, lookback_hours: int):
        self.domain, self.token, self.lookback = domain, token, lookback_hours

    def configured(self) -> bool:
        return bool(self.domain and self.token)

    def fetch(self, cursor: Optional[str]) -> FetchResult:
        since = cursor or iso_lookback(self.lookback)
        body = self._http_get(okta_url(self.domain, since),
                              {"Authorization": f"SSWS {self.token}",
                               "Accept": "application/json"})
        recs = json_records(body)
        return FetchResult(body, max_time_iso(recs, "published", since), len(recs))


# --------------------------------------------------------------------------- #
#  GitHub audit log (org)                                                     #
# --------------------------------------------------------------------------- #
def github_url(org: str, since_iso: str) -> str:
    phrase = quote(f"created:>={since_iso}")
    return (f"https://api.github.com/orgs/{quote(org)}/audit-log"
            f"?per_page=100&order=asc&phrase={phrase}")


class GitHubCollector(Collector):
    name, fmt, label = "github", "github_audit", "GitHub audit log"

    def __init__(self, org: str, token: str, lookback_hours: int):
        self.org, self.token, self.lookback = org, token, lookback_hours

    def configured(self) -> bool:
        return bool(self.org and self.token)

    def fetch(self, cursor: Optional[str]) -> FetchResult:
        since = cursor or iso_lookback(self.lookback)
        body = self._http_get(github_url(self.org, since),
                              {"Authorization": f"Bearer {self.token}",
                               "Accept": "application/vnd.github+json"})
        recs = json_records(body)
        return FetchResult(body, max_time_iso(recs, "@timestamp", since), len(recs))


# --------------------------------------------------------------------------- #
#  GitLab audit events                                                        #
# --------------------------------------------------------------------------- #
def gitlab_url(base: str, since_iso: str) -> str:
    return (f"{base.rstrip('/')}/api/v4/audit_events"
            f"?per_page=100&created_after={quote(since_iso)}")


class GitLabCollector(Collector):
    name, fmt, label = "gitlab", "gitlab_audit", "GitLab audit events"

    def __init__(self, base_url: str, token: str, lookback_hours: int):
        self.base, self.token, self.lookback = base_url, token, lookback_hours

    def configured(self) -> bool:
        return bool(self.base and self.token)

    def fetch(self, cursor: Optional[str]) -> FetchResult:
        since = cursor or iso_lookback(self.lookback)
        body = self._http_get(gitlab_url(self.base, since),
                              {"PRIVATE-TOKEN": self.token, "Accept": "application/json"})
        recs = json_records(body)
        return FetchResult(body, max_time_iso(recs, "created_at", since), len(recs))
