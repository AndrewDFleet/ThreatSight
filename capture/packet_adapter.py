"""Converts a raw Scapy packet to a models.Packet — implemented in Phase 4."""
from datetime import datetime
from models import Packet, Protocol


def scapy_to_packet(scapy_pkt) -> Packet | None:
    """Return a models.Packet from a Scapy packet, or None if it should be skipped."""
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        if not scapy_pkt.haslayer(IP):
            return None
        ip = scapy_pkt[IP]
        if scapy_pkt.haslayer(TCP):
            layer = scapy_pkt[TCP]
            proto = Protocol.TCP
            flags = str(layer.flags) if hasattr(layer, "flags") else None
            src_port, dst_port = layer.sport, layer.dport
        elif scapy_pkt.haslayer(UDP):
            layer = scapy_pkt[UDP]
            proto = Protocol.UDP
            flags = None
            src_port, dst_port = layer.sport, layer.dport
        elif scapy_pkt.haslayer(ICMP):
            proto = Protocol.ICMP
            flags = None
            src_port, dst_port = 0, 0
        else:
            return None

        size = len(scapy_pkt)
        return Packet(
            timestamp=datetime.now(),
            src_ip=ip.src,
            dst_ip=ip.dst,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            size=size,
            flags=flags,
        )
    except Exception:
        return None
