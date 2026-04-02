"""
Core data models for Network Threat Visualizer
Defines packets, flows, alerts, and network events
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List
from enum import Enum


class Protocol(Enum):
    """Network protocols"""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    SSH = "SSH"


class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertType(Enum):
    """Types of network anomalies"""
    PORT_SCAN = "port_scan"
    TRAFFIC_SPIKE = "traffic_spike"
    SUSPICIOUS_IP = "suspicious_ip"
    DDoS = "ddos"
    DATA_EXFILTRATION = "data_exfiltration"
    UNUSUAL_PROTOCOL = "unusual_protocol"
    BRUTE_FORCE = "brute_force"


@dataclass
class Packet:
    """
    Represents a single network packet
    Lightweight representation focusing on threat detection needs
    """
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: Protocol
    size: int  # bytes
    flags: Optional[str] = None  # TCP flags (SYN, ACK, FIN, etc.)
    payload_preview: Optional[str] = None  # First few bytes for inspection
    
    def __post_init__(self):
        """Validate packet data"""
        if self.size < 0:
            raise ValueError("Packet size cannot be negative")
        if not (0 <= self.src_port <= 65535):
            raise ValueError(f"Invalid source port: {self.src_port}")
        if not (0 <= self.dst_port <= 65535):
            raise ValueError(f"Invalid destination port: {self.dst_port}")
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol.value,
            'size': self.size,
            'flags': self.flags,
            'payload_preview': self.payload_preview
        }
    
    @property
    def flow_key(self) -> str:
        """
        Generate a unique key for this packet's flow
        Used to group packets into bidirectional flows
        """
        # Sort IPs to make bidirectional flow (A->B same as B->A)
        ips = sorted([f"{self.src_ip}:{self.src_port}", 
                      f"{self.dst_ip}:{self.dst_port}"])
        return f"{ips[0]}<->{ips[1]}:{self.protocol.value}"


@dataclass
class Flow:
    """
    Represents a network flow (collection of related packets)
    Used for flow-level analysis and anomaly detection
    """
    flow_key: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: Protocol
    start_time: datetime
    last_seen: datetime
    packet_count: int = 0
    byte_count: int = 0
    packets: List[Packet] = field(default_factory=list)
    
    def add_packet(self, packet: Packet):
        """Add packet to this flow and update statistics"""
        self.packets.append(packet)
        self.packet_count += 1
        self.byte_count += packet.size
        self.last_seen = packet.timestamp
    
    @property
    def duration(self) -> float:
        """Flow duration in seconds"""
        return (self.last_seen - self.start_time).total_seconds()
    
    @property
    def packets_per_second(self) -> float:
        """Calculate packet rate"""
        if self.duration == 0:
            return 0
        return self.packet_count / self.duration
    
    @property
    def bytes_per_second(self) -> float:
        """Calculate byte rate"""
        if self.duration == 0:
            return 0
        return self.byte_count / self.duration
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'flow_key': self.flow_key,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol.value,
            'start_time': self.start_time.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'duration': self.duration,
            'packet_count': self.packet_count,
            'byte_count': self.byte_count,
            'packets_per_second': self.packets_per_second,
            'bytes_per_second': self.bytes_per_second
        }


@dataclass
class Alert:
    """
    Represents a security alert/anomaly detection event
    """
    alert_id: str
    alert_type: AlertType
    severity: AlertSeverity
    timestamp: datetime
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    port: Optional[int] = None
    description: str = ""
    details: dict = field(default_factory=dict)
    acknowledged: bool = False
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'alert_id': self.alert_id,
            'alert_type': self.alert_type.value,
            'severity': self.severity.value,
            'timestamp': self.timestamp.isoformat(),
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'port': self.port,
            'description': self.description,
            'details': self.details,
            'acknowledged': self.acknowledged
        }


@dataclass
class NetworkStats:
    """
    Real-time network statistics for dashboard display
    """
    timestamp: datetime
    total_packets: int = 0
    total_bytes: int = 0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    active_flows: int = 0
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    protocol_distribution: dict = field(default_factory=dict)  # {protocol: count}
    top_talkers: List[tuple] = field(default_factory=list)  # [(ip, packet_count), ...]
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'packets_per_second': self.packets_per_second,
            'bytes_per_second': self.bytes_per_second,
            'active_flows': self.active_flows,
            'unique_src_ips': self.unique_src_ips,
            'unique_dst_ips': self.unique_dst_ips,
            'protocol_distribution': self.protocol_distribution,
            'top_talkers': self.top_talkers
        }
