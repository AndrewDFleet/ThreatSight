import uuid
from collections import defaultdict
from datetime import timedelta
from typing import Optional
from models import Alert, AlertSeverity, AlertType, Packet
from detectors.base_detector import BaseDetector


class DDoSDetector(BaseDetector):
    def __init__(self, window_seconds: int = 5, pps_threshold: int = 500):
        self.window = timedelta(seconds=window_seconds)
        self.pps_threshold = pps_threshold
        self._history: dict = defaultdict(list)
        self._alerted: set = set()

    def process(self, packet: Packet) -> Optional[Alert]:
        self._history[packet.dst_ip].append(packet.timestamp)
        cutoff = packet.timestamp - self.window
        self._history[packet.dst_ip] = [ts for ts in self._history[packet.dst_ip] if ts >= cutoff]
        count = len(self._history[packet.dst_ip])
        pps = count / self.window.seconds
        if pps < self.pps_threshold or packet.dst_ip in self._alerted:
            return None
        self._alerted.add(packet.dst_ip)
        severity = (
            AlertSeverity.CRITICAL if pps >= 5000
            else AlertSeverity.HIGH if pps >= 1000
            else AlertSeverity.MEDIUM
        )
        return Alert(
            alert_id=str(uuid.uuid4())[:8],
            alert_type=AlertType.DDoS,
            severity=severity,
            timestamp=packet.timestamp,
            destination_ip=packet.dst_ip,
            description=f"DDoS flood: {pps:.0f} pps to {packet.dst_ip}",
            details={"pps": round(pps, 1), "window_seconds": self.window.seconds},
        )

    def reset(self) -> None:
        self._history.clear()
        self._alerted.clear()
