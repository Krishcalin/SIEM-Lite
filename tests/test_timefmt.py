# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Display-timezone rendering (IST). Storage stays UTC; only presentation converts."""
from __future__ import annotations

from datetime import date, datetime, timezone

from app.util import IST, fmt_ist, to_ist


def test_ist_offset_is_plus_5_30():
    assert IST.utcoffset(None).total_seconds() == 5.5 * 3600


def test_to_ist_converts_aware_utc():
    dt = datetime(2026, 6, 1, 0, 0, tzinfo=timezone.utc)
    ist = to_ist(dt)
    assert (ist.hour, ist.minute) == (5, 30) and ist.date() == date(2026, 6, 1)


def test_to_ist_treats_naive_as_utc():
    naive = datetime(2026, 6, 1, 18, 45)                 # assumed UTC
    assert to_ist(naive).strftime("%Y-%m-%d %H:%M") == "2026-06-02 00:15"   # rolls past midnight


def test_fmt_ist_formats_datetime_in_ist():
    dt = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
    assert fmt_ist(dt, "%Y-%m-%d %H:%M") == "2026-06-01 17:30"


def test_fmt_ist_none_and_empty_render_dash():
    assert fmt_ist(None) == "—"
    assert fmt_ist("") == "—"


def test_fmt_ist_passes_date_through_without_tz_shift():
    # a pure date (e.g. a daily chart label) has no time-of-day to convert
    assert fmt_ist(date(2026, 6, 1), "%m-%d") == "06-01"
