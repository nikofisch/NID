from __future__ import annotations

from src.detector import TrafficAnomalyDetector


def make_anomaly_detector(window_seconds: int = 30, anomaly_multiplier: float = 2.0, anomaly_min_events: int = 5) -> TrafficAnomalyDetector:
    return TrafficAnomalyDetector(
        window_seconds=window_seconds,
        anomaly_multiplier=anomaly_multiplier,
        anomaly_min_events=anomaly_min_events,
    )
