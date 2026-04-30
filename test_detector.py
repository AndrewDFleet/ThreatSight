import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from traffic_simulator import TrafficSimulator
from detectors import DetectionEngine, PortScanDetector, DDoSDetector, BruteForceDetector, ExfiltrationDetector
from models import AlertType


def sep(title=""):
    print("\n" + "="*70)
    if title:
        print(f"  {title}"); print("="*70)

def run(detector, packets):
    return [a for p in packets for a in [detector.process(p)] if a]

def ok(alerts, t, label):
    m = [a for a in alerts if a.alert_type == t]
    print(f"  [{'PASS' if m else 'FAIL'}] {label}")
    if m: print(f"         {m[0].alert_type.value} | {m[0].severity.value} | {m[0].description}")
    return bool(m)

def no(alerts, t, label):
    m = [a for a in alerts if a.alert_type == t]
    print(f"  [{'FAIL' if m else 'PASS'}] {label}")
    if m: print(f"         False positive: {m[0].description}")
    return not bool(m)


def test_port_scan():
    sep("TEST 1: Port Scan Detector")
    sim = TrafficSimulator()
    d = PortScanDetector(window_seconds=10, port_threshold=50)
    ok(run(d, sim.generate_port_scan(target_ip="192.168.1.100", scanner_ip="45.142.212.61", port_count=100)),
       AlertType.PORT_SCAN, "Detects SYN port scan (100 ports)")
    d.reset()
    no(run(d, sim.generate_normal_traffic(200)), AlertType.PORT_SCAN, "No false positive on normal traffic")

def test_ddos():
    sep("TEST 2: DDoS Detector")
    sim = TrafficSimulator()
    d = DDoSDetector(window_seconds=5, pps_threshold=500)
    ok(run(d, sim.generate_ddos(target_ip="192.168.1.50", duration_seconds=2, packets_per_second=1000)),
       AlertType.DDoS, "Detects 1000 pps flood")
    d.reset()
    no(run(d, sim.generate_normal_traffic(200)), AlertType.DDoS, "No false positive on normal traffic")

def test_brute_force():
    sep("TEST 3: Brute Force Detector")
    sim = TrafficSimulator()
    d = BruteForceDetector(window_seconds=300, attempt_threshold=20)
    ok(run(d, sim.generate_brute_force(target_ip="192.168.1.10", attacker_ip="45.142.212.61", attempts=50)),
       AlertType.BRUTE_FORCE, "Detects 50 SSH login attempts")
    d.reset()
    no(run(d, sim.generate_normal_traffic(200)), AlertType.BRUTE_FORCE, "No false positive on normal traffic")

def test_exfiltration():
    sep("TEST 4: Data Exfiltration Detector")
    sim = TrafficSimulator()
    d = ExfiltrationDetector(window_seconds=120, byte_threshold_mb=5.0)
    ok(run(d, sim.generate_data_exfiltration(internal_ip="192.168.1.75", external_ip="91.134.203.19", size_mb=10)),
       AlertType.DATA_EXFILTRATION, "Detects 10 MB outbound transfer")
    d.reset()
    no(run(d, sim.generate_normal_traffic(200)), AlertType.DATA_EXFILTRATION, "No false positive on normal traffic")

def test_mixed_engine():
    sep("TEST 5: Full Engine -- Mixed Scenario")
    sim = TrafficSimulator()
    engine = DetectionEngine()
    packets = sim.generate_mixed_scenario()
    alerts = engine.process_packets(packets)
    print(f"  Processed {len(packets)} packets -> {len(alerts)} alert(s)")
    for a in alerts:
        print(f"    [{a.severity.value.upper():8s}] {a.alert_type.value:20s} {a.description}")
    detected = {a.alert_type for a in alerts}
    for t in [AlertType.PORT_SCAN, AlertType.BRUTE_FORCE]:
        print(f"  [{'PASS' if t in detected else 'FAIL'}] {t.value} detected in mixed scenario")

def test_serialization():
    sep("TEST 6: Alert JSON Serialization")
    import json
    d = PortScanDetector(window_seconds=10, port_threshold=50)
    alerts = run(d, TrafficSimulator().generate_port_scan(port_count=60))
    if alerts:
        print("  [PASS] Alert serializes to JSON:")
        print("  " + json.dumps(alerts[0].to_dict(), indent=2).replace("\n", "\n  "))
    else:
        print("  [FAIL] No alert generated")

def main():
    sep("NETWORK THREAT DETECTOR -- Detection Algorithm Tests")
    try:
        test_port_scan()
        test_ddos()
        test_brute_force()
        test_exfiltration()
        test_mixed_engine()
        test_serialization()
        sep("ALL TESTS COMPLETE")
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback; traceback.print_exc()

if __name__ == "__main__":
    main()
