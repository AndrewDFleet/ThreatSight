"""
Test script for traffic simulator
Demonstrates different traffic patterns and data model usage
"""

import sys
sys.path.insert(0, '/home/claude/network_threat_viz')

from traffic_simulator import TrafficSimulator
from models import Protocol, AlertType
from collections import Counter
import json


def print_separator(title=""):
    """Print visual separator"""
    print("\n" + "="*70)
    if title:
        print(f"  {title}")
        print("="*70)


def test_normal_traffic():
    """Test normal traffic generation"""
    print_separator("TEST 1: Normal Baseline Traffic")
    
    sim = TrafficSimulator(internal_subnet="192.168.1")
    packets = sim.generate_normal_traffic(count=50)
    
    print(f"Generated {len(packets)} normal packets")
    print(f"Time span: {packets[0].timestamp} to {packets[-1].timestamp}")
    
    # Analyze protocol distribution
    protocols = Counter(p.protocol.value for p in packets)
    print(f"\nProtocol distribution:")
    for proto, count in protocols.most_common():
        percentage = (count / len(packets)) * 100
        print(f"  {proto:8s}: {count:3d} packets ({percentage:5.1f}%)")
    
    # Show sample packets
    print(f"\nSample packets:")
    for i, packet in enumerate(packets[:5]):
        print(f"  [{i+1}] {packet.src_ip}:{packet.src_port} -> "
              f"{packet.dst_ip}:{packet.dst_port} "
              f"[{packet.protocol.value}] {packet.size} bytes")
    
    # Test packet serialization
    print(f"\nSample JSON serialization:")
    print(json.dumps(packets[0].to_dict(), indent=2))


def test_port_scan():
    """Test port scan generation"""
    print_separator("TEST 2: Port Scan Attack")
    
    sim = TrafficSimulator()
    packets = sim.generate_port_scan(
        target_ip="192.168.1.100",
        scanner_ip="45.142.212.61",
        port_count=100
    )
    
    print(f"Generated {len(packets)} port scan packets")
    print(f"Scanner: {packets[0].src_ip}")
    print(f"Target: {packets[0].dst_ip}")
    
    # Analyze port range
    ports = [p.dst_port for p in packets]
    print(f"\nPort range scanned: {min(ports)} - {max(ports)}")
    print(f"Sequential scan: {ports == sorted(ports)}")
    
    # Check TCP flags (should all be SYN for scan)
    flags = Counter(p.flags for p in packets)
    print(f"\nTCP flags distribution:")
    for flag, count in flags.items():
        print(f"  {flag}: {count} packets")
    
    # Show timing pattern
    if len(packets) >= 10:
        print(f"\nTiming between first 10 packets (ms):")
        for i in range(1, 10):
            delta = (packets[i].timestamp - packets[i-1].timestamp).total_seconds() * 1000
            print(f"  Packet {i} -> {i+1}: {delta:.2f} ms")


def test_ddos():
    """Test DDoS generation"""
    print_separator("TEST 3: DDoS Traffic Flood")
    
    sim = TrafficSimulator()
    packets = sim.generate_ddos(
        target_ip="192.168.1.50",
        duration_seconds=2,  # Short for testing
        packets_per_second=1000
    )
    
    print(f"Generated {len(packets)} DDoS packets")
    print(f"Target: {packets[0].dst_ip}")
    print(f"Duration: {(packets[-1].timestamp - packets[0].timestamp).total_seconds():.2f}s")
    
    # Analyze source diversity (botnet fingerprint)
    unique_sources = set(p.src_ip for p in packets)
    print(f"\nUnique source IPs: {len(unique_sources)} (botnet indicator)")
    
    # Calculate packet rate
    duration = (packets[-1].timestamp - packets[0].timestamp).total_seconds()
    if duration > 0:
        pps = len(packets) / duration
        print(f"Average packet rate: {pps:.0f} packets/second")
    
    # Target port analysis
    target_ports = Counter(p.dst_port for p in packets)
    print(f"\nTarget ports:")
    for port, count in target_ports.most_common(5):
        print(f"  Port {port}: {count} packets")


def test_data_exfiltration():
    """Test data exfiltration generation"""
    print_separator("TEST 4: Data Exfiltration")
    
    sim = TrafficSimulator()
    packets = sim.generate_data_exfiltration(
        internal_ip="192.168.1.75",
        external_ip="91.134.203.19",
        size_mb=10  # Small for testing
    )
    
    print(f"Generated {len(packets)} exfiltration packets")
    print(f"Source (compromised host): {packets[0].src_ip}")
    print(f"Destination (C2 server): {packets[0].dst_ip}")
    
    # Calculate total data transferred
    total_bytes = sum(p.size for p in packets)
    total_mb = total_bytes / (1024 * 1024)
    print(f"\nTotal data transferred: {total_mb:.2f} MB")
    
    # Duration and throughput
    duration = (packets[-1].timestamp - packets[0].timestamp).total_seconds()
    if duration > 0:
        mbps = (total_bytes * 8) / (duration * 1_000_000)
        print(f"Duration: {duration:.2f} seconds")
        print(f"Throughput: {mbps:.2f} Mbps")
    
    # Protocol used (should be HTTPS for stealth)
    protocols = Counter(p.protocol.value for p in packets)
    print(f"\nProtocol used: {list(protocols.keys())[0]}")


def test_mixed_scenario():
    """Test mixed traffic scenario"""
    print_separator("TEST 5: Mixed Traffic Scenario")
    
    sim = TrafficSimulator()
    packets = sim.generate_mixed_scenario()
    
    print(f"Generated {len(packets)} total packets")
    
    # Analyze composition
    protocols = Counter(p.protocol.value for p in packets)
    print(f"\nProtocol distribution:")
    for proto, count in protocols.most_common():
        percentage = (count / len(packets)) * 100
        print(f"  {proto:8s}: {count:4d} packets ({percentage:5.1f}%)")
    
    # Identify potential anomalies by pattern
    # Port scans: multiple packets from same source to sequential ports
    port_scan_candidates = {}
    for p in packets:
        if p.flags == "SYN":
            key = (p.src_ip, p.dst_ip)
            if key not in port_scan_candidates:
                port_scan_candidates[key] = []
            port_scan_candidates[key].append(p.dst_port)
    
    print(f"\nPotential anomalies detected:")
    for (src, dst), ports in port_scan_candidates.items():
        if len(ports) > 50:  # Likely port scan
            print(f"  Port scan: {src} -> {dst} ({len(ports)} ports)")
    
    # Brute force: repeated connections to SSH
    ssh_attempts = {}
    for p in packets:
        if p.dst_port == 22:
            key = (p.src_ip, p.dst_ip)
            ssh_attempts[key] = ssh_attempts.get(key, 0) + 1
    
    for (src, dst), count in ssh_attempts.items():
        if count > 30:  # Likely brute force
            print(f"  Brute force: {src} -> {dst}:22 ({count} attempts)")


def test_flow_creation():
    """Test flow aggregation from packets"""
    print_separator("TEST 6: Flow Aggregation")
    
    from models import Flow
    
    sim = TrafficSimulator()
    packets = sim.generate_normal_traffic(count=100)
    
    # Group packets into flows
    flows = {}
    for packet in packets:
        flow_key = packet.flow_key
        if flow_key not in flows:
            flows[flow_key] = Flow(
                flow_key=flow_key,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=packet.protocol,
                start_time=packet.timestamp,
                last_seen=packet.timestamp
            )
        flows[flow_key].add_packet(packet)
    
    print(f"Aggregated {len(packets)} packets into {len(flows)} flows")
    
    # Show top flows by packet count
    sorted_flows = sorted(flows.values(), key=lambda f: f.packet_count, reverse=True)
    print(f"\nTop 5 flows by packet count:")
    for i, flow in enumerate(sorted_flows[:5]):
        print(f"  [{i+1}] {flow.src_ip}:{flow.src_port} <-> {flow.dst_ip}:{flow.dst_port}")
        print(f"      Protocol: {flow.protocol.value}, Packets: {flow.packet_count}, "
              f"Bytes: {flow.byte_count}, Duration: {flow.duration:.2f}s")


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("  NETWORK THREAT VISUALIZER - Traffic Simulator Tests")
    print("="*70)
    
    try:
        test_normal_traffic()
        test_port_scan()
        test_ddos()
        test_data_exfiltration()
        test_mixed_scenario()
        test_flow_creation()
        
        print_separator("ALL TESTS COMPLETED SUCCESSFULLY")
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
