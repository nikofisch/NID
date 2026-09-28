from __future__ import annotations

from src.detector import RepeatedConnectionDetector


def make_bruteforce_detector(window_seconds: int = 15, connection_threshold: int = 5) -> RepeatedConnectionDetector:
    return RepeatedConnectionDetector(window_seconds=window_seconds, connection_threshold=connection_threshold)
