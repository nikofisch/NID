from datetime import datetime

from src.models import FlowEvent
from src.parser import parse_packet


def test_parse_tcp_packet():
    packet = {
        "timestamp": "2024-01-01T12:00:00Z",
        "packet_length": 60,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 5000,
        "dst_port": 80,
        "protocol": "TCP",
        "tcp_flags": "SYN",
    }

    event = parse_packet(packet)

    assert isinstance(event, FlowEvent)
    assert event.src_ip == "10.0.0.1"
    assert event.dst_ip == "10.0.0.2"
    assert event.src_port == 5000
    assert event.dst_port == 80
    assert event.protocol == "TCP"
    assert event.tcp_flags == "SYN"
    assert isinstance(event.timestamp, datetime)


def test_parse_packet_handles_malformed_data():
    event = parse_packet({})
    assert event is not None
    assert event.src_ip == "unknown"
    assert event.dst_ip == "unknown"
    assert event.protocol == "UNKNOWN"
