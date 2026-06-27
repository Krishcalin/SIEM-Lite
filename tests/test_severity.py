"""Unit tests for the canonical severity ordering (pure)."""
from app.severity import SEVERITY_ORDER, max_severity, severity_rank


def test_rank_is_monotonic_and_unknown_is_medium():
    ranks = [severity_rank(s) for s in SEVERITY_ORDER]
    assert ranks == sorted(ranks) and len(set(ranks)) == len(SEVERITY_ORDER)
    assert severity_rank("HIGH") > severity_rank("low")          # case-insensitive
    assert severity_rank("bogus") == severity_rank("medium")     # unknown -> medium


def test_max_severity():
    assert max_severity(["low", "critical", "medium"]) == "critical"
    assert max_severity(["High", "high"]) == "high"
    assert max_severity([None, "", "high"]) == "high"            # skips blanks
    assert max_severity([]) == "medium"                          # default
    assert max_severity([], default="low") == "low"
