import uuid
from collections import defaultdict
from datetime import timedelta
from typing import Optional
from models import Alert, AlertSeverity, AlertType, Packet, Protocol
from detectors.base_detector import BaseDetector


class PortScanDetector(BaseDetector):
    def __init__(self, window_seconds: int = 10, port_threshold: int = 50):
        self.window = timedelta(seconds=window_seconds)
        self.port_threshold = port_threshold
        self._history: dict = defaultdict(list)
        self._alerted: set = set()

    def process(self, packet: Packet) -> Optional[Alert]:
        if packet.flags != "SYN" or packet.protocol != Protocol.TCP:
            return None
        key = (packet.src_ip, packet.dst_ip)
        self._history[key].append((packet.timestamp, packet.dst_port))
        cutoff = packet.timestamp - self.window
        self._history[key] = [(ts, p) for ts, p in self._history[key] if ts >= cutoff]
        unique_ports = {p for _, p in self._history[key]}
        if len(unique_ports) < self.port_threshold or key in self._alerted:
            return None
        self._alerted.add(key)
        count = len(unique_ports)
        severity = (
            AlertSeverity.CRITICAL if count >= 500
            else AlertSeverity.HIGH if count >= 200
            else AlertSeverity.MEDIUM
        )
        return Alert(
            alert_id=str(uuid.uuid4())[:8],
            alert_type=AlertType.PORT_SCAN,
            severity=severity,
            timestamp=packet.timestamp,
            source_ip=packet.src_ip,
            destination_ip=packet.dst_ip,
            description=f"Port scan: {count} ports probed in {self.window.seconds}s",
            details={"unique_ports": count, "window_seconds": self.window.seconds},
        )

    def reset(self) -> None:
        self._history.clear()
        self._alerted.clear()
