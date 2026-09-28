from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class FlowEvent:
    timestamp: datetime | None
    src_ip: str = "unknown"
    dst_ip: str = "unknown"
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = "UNKNOWN"
    tcp_flags: str | None = None
    packet_length: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "tcp_flags": self.tcp_flags,
            "packet_length": self.packet_length,
        }


@dataclass
class Alert:
    id: int | None = None
    timestamp: datetime | None = None
    severity: str = "MEDIUM"
    rule_name: str = "UNKNOWN"
    source_ip: str = "unknown"
    destination_ip: str = "unknown"
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "severity": self.severity,
            "rule_name": self.rule_name,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "description": self.description,
            "evidence": self.evidence,
            "metadata": self.metadata,
        }
