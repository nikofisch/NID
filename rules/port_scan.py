from __future__ import annotations

from src.detector import PortScanDetector


def make_port_scan_detector(window_seconds: int = 10, unique_port_threshold: int = 8) -> PortScanDetector:
    return PortScanDetector(window_seconds=window_seconds, unique_port_threshold=unique_port_threshold)
