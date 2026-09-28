from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .models import Alert


def create_alert(
    rule_name: str,
    source_ip: str,
    destination_ip: str,
    description: str,
    evidence: dict[str, Any],
    severity: str = "MEDIUM",
    metadata: dict[str, Any] | None = None,
) -> Alert:
    return Alert(
        timestamp=datetime.now(timezone.utc),
        severity=severity,
        rule_name=rule_name,
        source_ip=source_ip,
        destination_ip=destination_ip,
        description=description,
        evidence=evidence,
        metadata=metadata or {},
    )
