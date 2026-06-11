"""The common normalized event every parser emits."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass
class NormalizedEvent:
    """Vendor-agnostic event. `raw` keeps the full original parsed record so no
    data is lost and ad-hoc fields remain searchable via the jsonb GIN index."""
    event_time: Optional[datetime]
    vendor: str
    product: Optional[str] = None
    log_type: Optional[str] = None
    severity: Optional[str] = None
    action: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    app: Optional[str] = None
    user_name: Optional[str] = None
    host_name: Optional[str] = None
    rule_name: Optional[str] = None
    bytes_total: Optional[int] = None
    message: Optional[str] = None
    raw: dict[str, Any] = field(default_factory=dict)
