"""
Network Traffic Simulator
Generates realistic network traffic patterns with injectable anomalies
"""

import random
import time
from datetime import datetime, timedelta
from typing import List, Callable, Optional
from models import Packet, Protocol, AlertType


class TrafficSimulator:
    """
    Simulates realistic network traffic patterns
    Supports both baseline traffic and injectable attack scenarios
    """
    
    # Common internal IP ranges
    INTERNAL_SUBNETS = [
        "192.168.1",
        "192.168.0",
        "10.0.0",
        "172.16.0"
    ]
    
    # External IPs representing common services
    EXTERNAL_IPS = [
        "8.8.8.8",      # Google DNS
        "1.1.1.1",      # Cloudflare DNS
        "93.184.216.34", # example.com
        "151.101.1.140", # Reddit
        "172.217.14.206" # Google services
    ]
    
    # Suspicious IPs (simulate threat actors)
    SUSPICIOUS_IPS = [
        "45.142.212.61",  # Simulated botnet
        "185.220.101.32", # Simulated scanner
        "91.134.203.19"   # Simulated C2 server
    ]
    
    # Common ports by protocol
    COMMON_PORTS = {
        Protocol.HTTP: [80, 8080, 8000],
        Protocol.HTTPS: [443, 8443],
        Protocol.DNS: [53],
        Protocol.SSH: [22],
        Protocol.TCP: [21, 25, 110, 143, 3306, 5432, 6379, 27017]
    }
    
    def __init__(self, internal_subnet: str = "192.168.1"):
        """
        Initialize traffic simulator
        
        Args:
            internal_subnet: Internal network subnet (e.g., "192.168.1")
        """
        self.internal_subnet = internal_subnet
        self.packet_id_counter = 0
        
    def _random_internal_ip(self) -> str:
        """Generate random internal IP address"""
        return f"{self.internal_subnet}.{random.randint(2, 254)}"
    
    def _random_external_ip(self) -> str:
        """Generate random external IP address"""
        return random.choice(self.EXTERNAL_IPS)
    
    def _random_port(self, protocol: Protocol = None) -> int:
        """
        Generate random port number
        Prefers common ports for specific protocols
        """
        if protocol and protocol in self.COMMON_PORTS:
            # 80% chance of using common port
            if random.random() < 0.8:
                return random.choice(self.COMMON_PORTS[protocol])
        
        # Random high port
        return random.randint(1024, 65535)
    
    def _random_size(self, protocol: Protocol) -> int:
        """Generate realistic packet size based on protocol"""
        if protocol == Protocol.DNS:
            return random.randint(60, 512)
        elif protocol in [Protocol.HTTP, Protocol.HTTPS]:
            # Bimodal: small requests, large responses
            if random.random() < 0.5:
                return random.randint(200, 800)  # Requests
            else:
                return random.randint(1000, 16000)  # Responses
        elif protocol == Protocol.SSH:
            return random.randint(100, 500)
        else:
            return random.randint(64, 1500)
    
    def generate_normal_traffic(self, count: int = 100) -> List[Packet]:
        """
        Generate baseline normal network traffic
        Mix of DNS, HTTP, HTTPS, SSH traffic
        
        Args:
            count: Number of packets to generate
            
        Returns:
            List of Packet objects
        """
        packets = []
        now = datetime.now()
        
        elapsed_ms = 0
        for i in range(count):
            # Protocol distribution (realistic for corporate network)
            rand = random.random()
            if rand < 0.40:  # 40% HTTPS
                protocol = Protocol.HTTPS
            elif rand < 0.65:  # 25% HTTP
                protocol = Protocol.HTTP
            elif rand < 0.85:  # 20% DNS
                protocol = Protocol.DNS
            elif rand < 0.95:  # 10% SSH
                protocol = Protocol.SSH
            else:  # 5% other TCP
                protocol = Protocol.TCP
            
            # Most traffic is outbound (internal -> external)
            if random.random() < 0.7:
                src_ip = self._random_internal_ip()
                dst_ip = self._random_external_ip()
                src_port = self._random_port()
                dst_port = self._random_port(protocol)
            else:
                # Some inbound responses
                src_ip = self._random_external_ip()
                dst_ip = self._random_internal_ip()
                src_port = self._random_port(protocol)
                dst_port = self._random_port()
            
            # Realistic timing: accumulate delays to guarantee monotonic order
            elapsed_ms += random.randint(10, 100)
            timestamp = now + timedelta(milliseconds=elapsed_ms)
            
            packet = Packet(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                size=self._random_size(protocol),
                flags="ACK" if protocol == Protocol.TCP else None
            )
            
            packets.append(packet)
        
        return packets
    
    def generate_port_scan(self, 
                          target_ip: Optional[str] = None,
                          scanner_ip: Optional[str] = None,
                          port_count: int = 1000) -> List[Packet]:
        """
        Simulate a port scan attack
        Scanner probes sequential ports on target
        
        Args:
            target_ip: IP being scanned (defaults to random internal)
            scanner_ip: Attacker IP (defaults to suspicious IP)
            port_count: Number of ports to scan
            
        Returns:
            List of scan packets
        """
        if not target_ip:
            target_ip = self._random_internal_ip()
        if not scanner_ip:
            scanner_ip = random.choice(self.SUSPICIOUS_IPS)
        
        packets = []
        now = datetime.now()
        start_port = random.randint(1, 10000)
        
        elapsed_ms = 0
        for i in range(port_count):
            # SYN scan: send SYN packets to sequential ports
            elapsed_ms += random.randint(1, 5)
            timestamp = now + timedelta(milliseconds=elapsed_ms)
            
            packet = Packet(
                timestamp=timestamp,
                src_ip=scanner_ip,
                dst_ip=target_ip,
                src_port=random.randint(30000, 60000),
                dst_port=start_port + i,
                protocol=Protocol.TCP,
                size=random.randint(60, 80),
                flags="SYN"  # Classic SYN scan signature
            )
            
            packets.append(packet)
        
        return packets
    
    def generate_ddos(self,
                     target_ip: Optional[str] = None,
                     duration_seconds: int = 10,
                     packets_per_second: int = 10000) -> List[Packet]:
        """
        Simulate DDoS attack (traffic flood)
        Multiple sources flooding target with traffic
        
        Args:
            target_ip: Target being flooded
            duration_seconds: Attack duration
            packets_per_second: Packet rate
            
        Returns:
            List of flood packets
        """
        if not target_ip:
            target_ip = self._random_internal_ip()
        
        packets = []
        now = datetime.now()
        total_packets = duration_seconds * packets_per_second
        
        # Botnet: multiple source IPs
        botnet_ips = [
            f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            for _ in range(100)
        ]
        
        for i in range(total_packets):
            timestamp = now + timedelta(microseconds=i * (1000000 // packets_per_second))
            
            packet = Packet(
                timestamp=timestamp,
                src_ip=random.choice(botnet_ips),
                dst_ip=target_ip,
                src_port=random.randint(1024, 65535),
                dst_port=80,  # Usually targets web server
                protocol=Protocol.TCP,
                size=random.randint(60, 100),
                flags="SYN"  # SYN flood is common DDoS
            )
            
            packets.append(packet)
        
        return packets
    
    def generate_data_exfiltration(self,
                                   internal_ip: Optional[str] = None,
                                   external_ip: Optional[str] = None,
                                   size_mb: int = 100) -> List[Packet]:
        """
        Simulate data exfiltration
        Large outbound transfer to suspicious destination
        
        Args:
            internal_ip: Compromised internal host
            external_ip: Attacker's server
            size_mb: Amount of data to exfiltrate
            
        Returns:
            List of exfiltration packets
        """
        if not internal_ip:
            internal_ip = self._random_internal_ip()
        if not external_ip:
            external_ip = random.choice(self.SUSPICIOUS_IPS)
        
        packets = []
        now = datetime.now()
        total_bytes = size_mb * 1024 * 1024
        packet_size = 1500  # MTU size
        num_packets = total_bytes // packet_size
        
        # Exfiltration over HTTPS to hide
        dst_port = 443
        src_port = random.randint(40000, 60000)
        
        elapsed_ms = 0
        for i in range(num_packets):
            elapsed_ms += random.randint(1, 10)
            timestamp = now + timedelta(milliseconds=elapsed_ms)
            
            packet = Packet(
                timestamp=timestamp,
                src_ip=internal_ip,
                dst_ip=external_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=Protocol.HTTPS,
                size=packet_size,
                flags="PSH,ACK"
            )
            
            packets.append(packet)
        
        return packets
    
    def generate_brute_force(self,
                            target_ip: Optional[str] = None,
                            attacker_ip: Optional[str] = None,
                            attempts: int = 500) -> List[Packet]:
        """
        Simulate SSH brute force attack
        Repeated authentication attempts
        
        Args:
            target_ip: SSH server being attacked
            attacker_ip: Attacker IP
            attempts: Number of login attempts
            
        Returns:
            List of brute force packets
        """
        if not target_ip:
            target_ip = self._random_internal_ip()
        if not attacker_ip:
            attacker_ip = random.choice(self.SUSPICIOUS_IPS)
        
        packets = []
        now = datetime.now()
        
        elapsed_s = 0
        for i in range(attempts):
            # Each attempt is multiple packets (SSH handshake)
            elapsed_s += random.randint(1, 3)
            timestamp = now + timedelta(seconds=elapsed_s)
            
            packet = Packet(
                timestamp=timestamp,
                src_ip=attacker_ip,
                dst_ip=target_ip,
                src_port=random.randint(40000, 60000),
                dst_port=22,  # SSH
                protocol=Protocol.SSH,
                size=random.randint(100, 300),
                flags="PSH,ACK"
            )
            
            packets.append(packet)
        
        return packets
    
    def generate_mixed_scenario(self) -> List[Packet]:
        """
        Generate realistic mixed traffic: 90% normal, 10% anomalous
        This is good for demo scenarios
        
        Returns:
            List of mixed packets
        """
        packets = []
        
        # Baseline normal traffic
        packets.extend(self.generate_normal_traffic(count=1000))
        
        # Inject anomalies
        packets.extend(self.generate_port_scan(port_count=100))
        packets.extend(self.generate_brute_force(attempts=50))
        
        # Sort by timestamp to maintain chronological order
        packets.sort(key=lambda p: p.timestamp)
        
        return packets
