from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .models import FlowEvent


def _safe_int(value: Any, default: int | None = None) -> int | None:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalize_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        cleaned = value.strip()
        for candidate in [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ]:
            try:
                parsed = datetime.strptime(cleaned, candidate)
                if parsed.tzinfo is None:
                    return parsed.replace(tzinfo=timezone.utc)
                return parsed
            except ValueError:
                continue
    return datetime.now(timezone.utc)


def parse_packet(packet: Any) -> FlowEvent:
    if not isinstance(packet, dict):
        return FlowEvent(timestamp=datetime.now(timezone.utc))

    timestamp = _normalize_timestamp(packet.get("timestamp"))
    src_ip = str(packet.get("src_ip") or "unknown")
    dst_ip = str(packet.get("dst_ip") or "unknown")
    protocol = str(packet.get("protocol") or "UNKNOWN").upper()
    flags = packet.get("tcp_flags")
    tcp_flags = str(flags).upper() if flags is not None else None

    return FlowEvent(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=_safe_int(packet.get("src_port")),
        dst_port=_safe_int(packet.get("dst_port")),
        protocol=protocol,
        tcp_flags=tcp_flags,
        packet_length=_safe_int(packet.get("packet_length"), 0) or 0,
    )
