from __future__ import annotations

from typing import Any, Iterable

from .config import get_settings
from .database import AlertDatabase
from .detector import build_detector_set
from .models import Alert, FlowEvent


class NetworkIDS:
    def __init__(self, database_path: str | None = None) -> None:
        self.settings = get_settings()
        self.database = AlertDatabase(database_path or self.settings.database_path)
        self.detectors = build_detector_set()

    def process_event(self, event: dict[str, Any] | FlowEvent) -> list[Alert]:
        for detector in self.detectors.values():
            detector.process_event(event)

        alerts: list[Alert] = []
        for detector in self.detectors.values():
            alerts.extend(detector.detect())

        persisted: list[Alert] = []
        for alert in alerts:
            if alert.rule_name != "UNKNOWN":
                self.database.add_alert(alert)
                persisted.append(alert)
        return persisted

    def process_events(self, events: Iterable[dict[str, Any] | FlowEvent]) -> list[Alert]:
        all_alerts: list[Alert] = []
        for event in events:
            all_alerts.extend(self.process_event(event))
        return all_alerts

    def recent_alerts(self, limit: int = 20) -> list[dict[str, Any]]:
        return self.database.get_recent_alerts(limit)

    def statistics(self) -> dict[str, int]:
        return self.database.get_statistics()

    def close(self) -> None:
        self.database.close()
