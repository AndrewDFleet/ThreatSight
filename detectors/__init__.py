from detectors.base_detector import BaseDetector
from detectors.port_scan_detector import PortScanDetector
from detectors.ddos_detector import DDoSDetector
from detectors.exfiltration_detector import ExfiltrationDetector
from detectors.brute_force_detector import BruteForceDetector
from models import Alert, Packet
from typing import List


class DetectionEngine:
    def __init__(self):
        self.detectors: List[BaseDetector] = [
            PortScanDetector(),
            DDoSDetector(),
            BruteForceDetector(),
            ExfiltrationDetector(),
        ]

    def process_packet(self, packet: Packet) -> List[Alert]:
        alerts = []
        for detector in self.detectors:
            alert = detector.process(packet)
            if alert:
                alerts.append(alert)
        return alerts

    def process_packets(self, packets: List[Packet]) -> List[Alert]:
        alerts = []
        for packet in packets:
            alerts.extend(self.process_packet(packet))
        return alerts

    def reset(self):
        for d in self.detectors:
            d.reset()


__all__ = [
    "BaseDetector", "PortScanDetector", "DDoSDetector",
    "ExfiltrationDetector", "BruteForceDetector", "DetectionEngine",
]
