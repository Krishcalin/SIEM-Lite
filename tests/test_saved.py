# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Unit tests for saved-search pure helpers (no DB, no request)."""
from app import saved


def test_normalize_path_allows_only_known_pages():
    assert saved.normalize_path("/search") == "/search"
    assert saved.normalize_path("/alerts") == "/alerts"
    assert saved.normalize_path("/evil") == "/search"          # fallback
    assert saved.normalize_path("") == "/search"
    assert saved.normalize_path(None) == "/search"


def test_clean_query_drops_paging_and_empties():
    assert saved.clean_query("?q=foo&page=2&blank=&src_ip=1.2.3.4") == "q=foo&src_ip=1.2.3.4"
    assert saved.clean_query("") == ""
    assert saved.clean_query("page=5") == ""                   # only paging -> empty
    # re-encoded canonically (spaces %-encoded)
    assert saved.clean_query("q=a b") == "q=a+b"


def test_clean_name_trims_and_bounds():
    assert saved.clean_name("  My search  ") == "My search"
    assert len(saved.clean_name("x" * 500)) == 120
    assert saved.clean_name(None) == ""


def test_target_url_builds_runnable_link():
    assert saved.target_url("/alerts", "status=open&page=3") == "/alerts?status=open"
    assert saved.target_url("/search", "") == "/search"
    assert saved.target_url("/bad", "q=x") == "/search?q=x"     # path normalized


def test_is_valid_requires_name_and_known_path():
    assert saved.is_valid("mine", "/search")
    assert saved.is_valid("mine", "/alerts")
    assert not saved.is_valid("   ", "/search")                # blank name
    assert not saved.is_valid("mine", "/evil")                 # unknown path
    assert not saved.is_valid(None, "/search")
