import uuid
from collections import defaultdict
from datetime import timedelta
from typing import List, Optional
from models import Alert, AlertSeverity, AlertType, Packet
from detectors.base_detector import BaseDetector


class BruteForceDetector(BaseDetector):
    DEFAULT_PORTS = {22, 3389, 5900, 21, 23}

    def __init__(self, window_seconds: int = 60, attempt_threshold: int = 20, target_ports: Optional[List[int]] = None):
        self.window = timedelta(seconds=window_seconds)
        self.attempt_threshold = attempt_threshold
        self.target_ports = set(target_ports) if target_ports else self.DEFAULT_PORTS
        self._history: dict = defaultdict(list)
        self._alerted: set = set()

    def process(self, packet: Packet) -> Optional[Alert]:
        if packet.dst_port not in self.target_ports:
            return None
        key = (packet.src_ip, packet.dst_ip, packet.dst_port)
        self._history[key].append(packet.timestamp)
        cutoff = packet.timestamp - self.window
        self._history[key] = [ts for ts in self._history[key] if ts >= cutoff]
        count = len(self._history[key])
        if count < self.attempt_threshold or key in self._alerted:
            return None
        self._alerted.add(key)
        severity = AlertSeverity.HIGH if count >= 100 else AlertSeverity.MEDIUM
        return Alert(
            alert_id=str(uuid.uuid4())[:8],
            alert_type=AlertType.BRUTE_FORCE,
            severity=severity,
            timestamp=packet.timestamp,
            source_ip=packet.src_ip,
            destination_ip=packet.dst_ip,
            port=packet.dst_port,
            description=f"Brute force: {count} attempts from {packet.src_ip} to {packet.dst_ip}:{packet.dst_port}",
            details={"attempts": count, "window_seconds": self.window.seconds},
        )

    def reset(self) -> None:
        self._history.clear()
        self._alerted.clear()
