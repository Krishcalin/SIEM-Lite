"""Microsoft Entra ID (Azure AD) sign-in log parser.

Handles the Microsoft Graph ``auditLogs/signIns`` record shape (camelCase) and
the Azure Monitor diagnostic export (PascalCase, resolved case-insensitively).
Each record has a ``userPrincipalName``, the target ``appDisplayName``, the
caller ``ipAddress`` and a ``status`` whose ``errorCode`` (0 = success) drives
the action. The full record is kept in ``raw``.
"""
from __future__ import annotations

from typing import Any, Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, iter_json_records, parse_ts, to_int

_RISK_HIDDEN = {"none", "hidden", "unknownfuturevalue", ""}


def _g(rec: dict, *names: str) -> Optional[Any]:
    low = {str(k).strip().lower(): v for k, v in rec.items()}
    for n in names:
        v = low.get(n.lower())
        if v not in (None, ""):
            return v
    return None


def parse(content: str) -> Iterator[NormalizedEvent]:
    for rec in iter_json_records(content, "value", "records"):
        status = _g(rec, "status")
        status = status if isinstance(status, dict) else {}
        ec = status.get("errorCode")
        if ec is None:
            ec = status.get("errorcode")
        err = to_int(ec)
        action = None if err is None else ("success" if err == 0 else "failure")

        device = _g(rec, "devicedetail")
        device = device if isinstance(device, dict) else {}
        risk = str(_g(rec, "risklevelduringsignin", "risklevelaggregated") or "").lower()
        app_disp = _g(rec, "appdisplayname")
        reason = status.get("failureReason")

        base = f"Sign-in to {app_disp}" if app_disp else "Sign-in"
        message = (f"{base} — {reason}"
                   if (reason and str(reason).lower() not in ("other.", "other", "")) else base)

        yield NormalizedEvent(
            event_time=parse_ts(_g(rec, "createddatetime")),
            vendor="microsoft",
            product="entra",
            log_type="signin",
            severity=risk if risk not in _RISK_HIDDEN else None,
            action=action,
            src_ip=clean_ip(_g(rec, "ipaddress")),
            user_name=first(_g(rec, "userprincipalname"), _g(rec, "userdisplayname")),
            app=app_disp,
            host_name=first(device.get("displayName"), device.get("displayname")),
            rule_name=_g(rec, "clientappused"),
            message=message,
            raw=rec,
        )
