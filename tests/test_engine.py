from datetime import datetime, timedelta, timezone

from src.engine import NetworkIDS


def test_network_ids_processes_events_and_persists_alerts(tmp_path):
    ids = NetworkIDS(database_path=str(tmp_path / "alerts.db"))
    now = datetime.now(timezone.utc)
    events = [
        {
            "timestamp": (now - timedelta(seconds=1)).isoformat(),
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 43000,
            "dst_port": 22,
            "protocol": "TCP",
            "tcp_flags": "SYN",
            "packet_length": 60,
        },
        {
            "timestamp": (now - timedelta(seconds=1)).isoformat(),
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 43001,
            "dst_port": 23,
            "protocol": "TCP",
            "tcp_flags": "SYN",
            "packet_length": 60,
        },
        {
            "timestamp": (now - timedelta(seconds=1)).isoformat(),
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 43002,
            "dst_port": 80,
            "protocol": "TCP",
            "tcp_flags": "SYN",
            "packet_length": 60,
        },
        {
            "timestamp": (now - timedelta(seconds=1)).isoformat(),
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 43003,
            "dst_port": 443,
            "protocol": "TCP",
            "tcp_flags": "SYN",
            "packet_length": 60,
        },
        {
            "timestamp": (now - timedelta(seconds=1)).isoformat(),
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 43004,
            "dst_port": 8080,
            "protocol": "TCP",
            "tcp_flags": "SYN",
            "packet_length": 60,
        },
        {
            "timestamp": (now - timedelta(seconds=1)).isoformat(),
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 43005,
            "dst_port": 8443,
            "protocol": "TCP",
            "tcp_flags": "SYN",
            "packet_length": 60,
        },
        {
            "timestamp": (now - timedelta(seconds=1)).isoformat(),
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 43006,
            "dst_port": 3306,
            "protocol": "TCP",
            "tcp_flags": "SYN",
            "packet_length": 60,
        },
        {
            "timestamp": (now - timedelta(seconds=1)).isoformat(),
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 43007,
            "dst_port": 9000,
            "protocol": "TCP",
            "tcp_flags": "SYN",
            "packet_length": 60,
        },
    ]
    alerts = ids.process_events(events)
    assert alerts
    assert ids.statistics()["total"] >= 1
    ids.close()
