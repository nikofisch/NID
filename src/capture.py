from __future__ import annotations

from typing import Any, Callable

from scapy.all import ICMP, IP, TCP, UDP, sniff

from .config import get_settings
from .models import FlowEvent
from .parser import parse_packet


class PacketCapture:
    def __init__(self, interface: str | None = None) -> None:
        settings = get_settings()
        self.interface = interface or settings.capture_interface

    def _packet_to_event(self, packet: Any) -> FlowEvent | None:
        if packet is None:
            return None

        ip_layer = packet.getlayer(IP)
        if ip_layer is None:
            return None

        payload: dict[str, Any] = {
            "timestamp": None,
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "packet_length": len(packet),
            "protocol": "UNKNOWN",
        }

        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            payload["protocol"] = "TCP"
            payload["src_port"] = tcp_layer.sport
            payload["dst_port"] = tcp_layer.dport
            payload["tcp_flags"] = tcp_layer.flags
        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            payload["protocol"] = "UDP"
            payload["src_port"] = udp_layer.sport
            payload["dst_port"] = udp_layer.dport
        elif packet.haslayer(ICMP):
            payload["protocol"] = "ICMP"

        try:
            return parse_packet(payload)
        except Exception:
            return FlowEvent(timestamp=None)  # type: ignore[arg-type]

    def capture(self, count: int = 0, timeout: int | None = None) -> list[FlowEvent]:
        events: list[FlowEvent] = []

        def callback(pkt: Any) -> None:
            event = self._packet_to_event(pkt)
            if event is not None:
                events.append(event)

        sniff(iface=self.interface, count=count or 0, timeout=timeout or 5, store=False, prn=callback)
        return events

    def capture_async(self, callback: Callable[[FlowEvent], None], count: int = 0, timeout: int | None = None) -> None:
        def handler(pkt: Any) -> None:
            event = self._packet_to_event(pkt)
            if event is not None:
                callback(event)

        sniff(iface=self.interface, count=count or 0, timeout=timeout or 5, store=False, prn=handler)
