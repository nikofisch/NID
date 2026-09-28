from datetime import datetime, timedelta, timezone

from src.detector import PortScanDetector, RepeatedConnectionDetector, TrafficAnomalyDetector


def test_port_scan_detector_detects_threshold():
    detector = PortScanDetector(window_seconds=10, unique_port_threshold=3)
    now = datetime.now(timezone.utc)

    for port in [22, 23, 24, 80]:
        detector.process_event({
            "timestamp": now,
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.20",
            "dst_port": port,
            "protocol": "TCP",
            "packet_length": 60,
            "src_port": 4000,
            "tcp_flags": "SYN",
        })

    alerts = detector.detect()
    assert alerts
    assert alerts[0].rule_name == "PORT_SCAN"
    assert alerts[0].source_ip == "192.168.1.10"


def test_repeated_connection_detector_detects_threshold():
    detector = RepeatedConnectionDetector(window_seconds=15, connection_threshold=3)
    now = datetime.now(timezone.utc)

    for _ in range(4):
        detector.process_event({
            "timestamp": now,
            "src_ip": "10.0.0.7",
            "dst_ip": "10.0.0.9",
            "dst_port": 22,
            "protocol": "TCP",
            "packet_length": 60,
            "src_port": 4000,
            "tcp_flags": "SYN",
        })

    alerts = detector.detect()
    assert alerts
    assert alerts[0].rule_name == "REPEATED_CONNECTION"


def test_anomaly_detector_flags_rate_spike():
    detector = TrafficAnomalyDetector(window_seconds=30, anomaly_multiplier=2.0)
    now = datetime.now(timezone.utc)
    base = [
        {"timestamp": now - timedelta(seconds=5), "src_ip": f"10.0.0.{i}", "dst_ip": "10.0.0.5", "dst_port": 80, "protocol": "TCP", "packet_length": 60, "src_port": 1024, "tcp_flags": "ACK"}
        for i in range(1, 6)
    ]
    for event in base:
        detector.process_event(event)

    detector.process_event({
        "timestamp": now,
        "src_ip": "10.0.0.12",
        "dst_ip": "10.0.0.5",
        "dst_port": 80,
        "protocol": "TCP",
        "packet_length": 60,
        "src_port": 1024,
        "tcp_flags": "SYN",
    })

    alerts = detector.detect()
    assert alerts
    assert alerts[0].rule_name == "TRAFFIC_ANOMALY"
