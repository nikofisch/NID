from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os


@dataclass(frozen=True)
class IDSSettings:
    port_scan_window_seconds: int = 10
    port_scan_unique_port_threshold: int = 8
    repeated_connection_window_seconds: int = 15
    repeated_connection_threshold: int = 5
    anomaly_window_seconds: int = 30
    anomaly_multiplier: float = 2.0
    anomaly_min_events: int = 5
    database_path: str = "data/alerts.db"
    capture_interface: str = "eth0"
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 5000


def get_settings() -> IDSSettings:
    base_dir = Path(__file__).resolve().parent.parent
    config = IDSSettings(
        port_scan_window_seconds=int(os.getenv("PORT_SCAN_WINDOW_SECONDS", 10)),
        port_scan_unique_port_threshold=int(os.getenv("PORT_SCAN_UNIQUE_PORT_THRESHOLD", 8)),
        repeated_connection_window_seconds=int(os.getenv("REPEATED_CONNECTION_WINDOW_SECONDS", 15)),
        repeated_connection_threshold=int(os.getenv("REPEATED_CONNECTION_THRESHOLD", 5)),
        anomaly_window_seconds=int(os.getenv("ANOMALY_WINDOW_SECONDS", 30)),
        anomaly_multiplier=float(os.getenv("ANOMALY_MULTIPLIER", 2.0)),
        anomaly_min_events=int(os.getenv("ANOMALY_MIN_EVENTS", 5)),
        database_path=os.getenv("DATABASE_PATH", str(base_dir / "data" / "alerts.db")),
        capture_interface=os.getenv("CAPTURE_INTERFACE", "eth0"),
        dashboard_host=os.getenv("DASHBOARD_HOST", "127.0.0.1"),
        dashboard_port=int(os.getenv("DASHBOARD_PORT", 5000)),
    )
    return config
