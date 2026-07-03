# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Unit tests for the audit Medium-severity hardening fixes (no database)."""
import datetime as dt

from app.db import retention_cutoff_key
from app.main import _csrf_same_origin, _SECURITY_HEADERS


class TestCsrfSameOrigin:
    def test_matching_origin_allowed(self):
        assert _csrf_same_origin("logocean:8000", "http://logocean:8000", None)

    def test_cross_origin_blocked(self):
        assert not _csrf_same_origin("logocean:8000", "http://evil.test", None)

    def test_referer_fallback_when_no_origin(self):
        assert _csrf_same_origin("host:9", None, "http://host:9/alerts")
        assert not _csrf_same_origin("host:9", None, "http://evil/x")

    def test_absent_headers_allowed(self):        # SameSite=Lax cookie still applies
        assert _csrf_same_origin("host", None, None)


class TestRetentionCutoff:
    def test_floor_is_enforced(self):
        today = dt.date(2026, 7, 15)
        assert retention_cutoff_key(today, 1, 3) == 202307   # 1yr asked, 3yr floor -> 3yr
        assert retention_cutoff_key(today, 5, 3) == 202107   # larger request honored

    def test_calendar_math_no_leap_drift(self):
        assert retention_cutoff_key(dt.date(2024, 2, 29), 3, 3) == 202102
        assert retention_cutoff_key(dt.date(2026, 1, 1), 3, 0) == 202301


class TestSecurityHeaders:
    def test_hardening_headers_defined(self):
        assert _SECURITY_HEADERS["X-Frame-Options"] == "DENY"
        assert _SECURITY_HEADERS["X-Content-Type-Options"] == "nosniff"
        assert "frame-ancestors 'none'" in _SECURITY_HEADERS["Content-Security-Policy"]
