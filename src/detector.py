from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from .alerts import create_alert
from .models import Alert, FlowEvent
from .parser import parse_packet


class BaseDetector:
    def __init__(self, window_seconds: int) -> None:
        self.window_seconds = window_seconds
        self.events: list[FlowEvent] = []

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _prune_old_events(self, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self.window_seconds)
        self.events = [event for event in self.events if event.timestamp and event.timestamp >= cutoff]

    def process_event(self, event: dict[str, Any] | FlowEvent) -> FlowEvent:
        normalized = parse_packet(event) if isinstance(event, dict) else event
        self.events.append(normalized)
        self._prune_old_events(normalized.timestamp or self._now())
        return normalized

    def detect(self) -> list[Alert]:
        raise NotImplementedError


class PortScanDetector(BaseDetector):
    def __init__(self, window_seconds: int = 10, unique_port_threshold: int = 8) -> None:
        super().__init__(window_seconds)
        self.unique_port_threshold = unique_port_threshold

    def detect(self) -> list[Alert]:
        now = self._now()
        self._prune_old_events(now)
        alerts: list[Alert] = []
        grouped: dict[str, list[FlowEvent]] = defaultdict(list)
        for event in self.events:
            if event.src_ip and event.dst_port is not None:
                grouped[event.src_ip].append(event)

        for source_ip, source_events in grouped.items():
            ports = sorted({event.dst_port for event in source_events if event.dst_port is not None})
            if len(ports) < self.unique_port_threshold:
                continue
            target_ip = source_events[0].dst_ip if source_events else "unknown"
            alert = create_alert(
                rule_name="PORT_SCAN",
                source_ip=source_ip,
                destination_ip=target_ip,
                description=f"Detected {len(ports)} unique destination ports from {source_ip} within {self.window_seconds}s.",
                evidence={
                    "source_ip": source_ip,
                    "destination_ip": target_ip,
                    "unique_port_count": len(ports),
                    "time_window_seconds": self.window_seconds,
                    "ports_contacted": ports,
                },
                severity="HIGH" if len(ports) >= self.unique_port_threshold * 2 else "MEDIUM",
                metadata={"detector": "PortScanDetector", "window_seconds": self.window_seconds},
            )
            alerts.append(alert)
        return alerts


class RepeatedConnectionDetector(BaseDetector):
    def __init__(self, window_seconds: int = 15, connection_threshold: int = 5) -> None:
        super().__init__(window_seconds)
        self.connection_threshold = connection_threshold

    def detect(self) -> list[Alert]:
        now = self._now()
        self._prune_old_events(now)
        alerts: list[Alert] = []
        grouped: dict[tuple[str, str, int], list[FlowEvent]] = defaultdict(list)
        for event in self.events:
            if event.src_ip and event.dst_ip and event.dst_port is not None:
                grouped[(event.src_ip, event.dst_ip, event.dst_port)].append(event)

        for (source_ip, target_ip, port), source_events in grouped.items():
            if len(source_events) < self.connection_threshold:
                continue
            alert = create_alert(
                rule_name="REPEATED_CONNECTION",
                source_ip=source_ip,
                destination_ip=target_ip,
                description=f"Repeated connection attempts detected from {source_ip} to {target_ip}:{port}.",
                evidence={
                    "source_ip": source_ip,
                    "target_ip": target_ip,
                    "target_port": port,
                    "connection_count": len(source_events),
                    "time_window_seconds": self.window_seconds,
                },
                severity="HIGH" if len(source_events) >= self.connection_threshold * 2 else "MEDIUM",
                metadata={"detector": "RepeatedConnectionDetector", "window_seconds": self.window_seconds},
            )
            alerts.append(alert)
        return alerts


class TrafficAnomalyDetector(BaseDetector):
    def __init__(self, window_seconds: int = 30, anomaly_multiplier: float = 2.0, anomaly_min_events: int = 5) -> None:
        super().__init__(window_seconds)
        self.anomaly_multiplier = anomaly_multiplier
        self.anomaly_min_events = anomaly_min_events

    def detect(self) -> list[Alert]:
        now = self._now()
        self._prune_old_events(now)
        alerts: list[Alert] = []
        if not self.events:
            return alerts

        recent_by_target: dict[str, list[FlowEvent]] = defaultdict(list)
        for event in self.events:
            if event.dst_ip:
                recent_by_target[event.dst_ip].append(event)

        for target_ip, events in recent_by_target.items():
            if len(events) < self.anomaly_min_events:
                continue

            baseline_events = [
                e for e in self.events
                if e.timestamp < now - timedelta(seconds=self.window_seconds / 2) and e.dst_ip == target_ip
            ]
            baseline_count = len(baseline_events)
            current_count = len(events)
            spike_factor = current_count / max(1, baseline_count)
            if spike_factor >= self.anomaly_multiplier or current_count >= self.anomaly_min_events * 2:
                alert = create_alert(
                    rule_name="TRAFFIC_ANOMALY",
                    source_ip="multiple",
                    destination_ip=target_ip,
                    description=f"Traffic anomaly detected for {target_ip}: {current_count} events in {self.window_seconds}s.",
                    evidence={
                        "destination_ip": target_ip,
                        "event_count": current_count,
                        "baseline_count": baseline_count,
                        "time_window_seconds": self.window_seconds,
                        "spike_factor": round(spike_factor, 2),
                    },
                    severity="HIGH" if current_count >= self.anomaly_min_events * 2 else "MEDIUM",
                    metadata={"detector": "TrafficAnomalyDetector", "window_seconds": self.window_seconds},
                )
                alerts.append(alert)
        return alerts


def build_detector_set() -> dict[str, BaseDetector]:
    from .config import get_settings

    settings = get_settings()
    return {
        "port_scan": PortScanDetector(settings.port_scan_window_seconds, settings.port_scan_unique_port_threshold),
        "repeated_connection": RepeatedConnectionDetector(settings.repeated_connection_window_seconds, settings.repeated_connection_threshold),
        "traffic_anomaly": TrafficAnomalyDetector(settings.anomaly_window_seconds, settings.anomaly_multiplier, settings.anomaly_min_events),
    }
