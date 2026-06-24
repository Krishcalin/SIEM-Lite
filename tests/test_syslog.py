"""Unit tests for syslog TCP framing + format resolution (no sockets, no DB)."""
from app.receivers.syslog import iter_tcp_messages, resolve_format


def test_newline_framing():
    msgs, rem = iter_tcp_messages(b"<13>msg one\n<13>msg two\n")
    assert msgs == [b"<13>msg one", b"<13>msg two"]
    assert rem == b""


def test_octet_counting_framing():
    m1, m2 = b"<13>hello", b"<13>world!!"
    buf = b"%d " % len(m1) + m1 + b"%d " % len(m2) + m2
    msgs, rem = iter_tcp_messages(buf)
    assert msgs == [m1, m2]
    assert rem == b""


def test_partial_octet_frame_is_remainder():
    m1 = b"<13>hello"
    buf = (b"%d " % len(m1) + m1)[:-3]   # truncated mid-message
    msgs, rem = iter_tcp_messages(buf)
    assert msgs == []
    assert rem == buf                    # held until the rest arrives


def test_partial_newline_line_is_remainder():
    msgs, rem = iter_tcp_messages(b"<13>complete\n<13>partial no newline")
    assert msgs == [b"<13>complete"]
    assert rem == b"<13>partial no newline"


def test_leading_digit_line_not_misframed_as_octet_count():
    # A non-transparent line beginning with a number must split on newline, not be
    # read as an octet count (the byte after "12 " is 'J', not a syslog '<PRI>').
    msgs, rem = iter_tcp_messages(b"12 Jun 10:00:00 host app: hello\n")
    assert msgs == [b"12 Jun 10:00:00 host app: hello"]
    assert rem == b""


def test_resolve_format_fixed_valid_and_invalid():
    assert resolve_format("anything", "cef") == "cef"
    assert resolve_format("anything", "not_a_real_format") is None


def test_resolve_format_auto_falls_back_to_generic_syslog():
    assert resolve_format("plain text with no signature", "auto") == "generic_syslog"
