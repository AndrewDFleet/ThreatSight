import uuid
from collections import defaultdict
from datetime import timedelta
from typing import Optional
from models import Alert, AlertSeverity, AlertType, Packet
from detectors.base_detector import BaseDetector


class ExfiltrationDetector(BaseDetector):
    def __init__(self, window_seconds: int = 60, byte_threshold_mb: float = 5.0, internal_prefixes: tuple = ("192.168.", "10.", "172.16.")):
        self.window = timedelta(seconds=window_seconds)
        self.byte_threshold = byte_threshold_mb * 1024 * 1024
        self.internal_prefixes = internal_prefixes
        self._history: dict = defaultdict(list)
        self._alerted: set = set()

    def _is_internal(self, ip: str) -> bool:
        return any(ip.startswith(p) for p in self.internal_prefixes)

    def process(self, packet: Packet) -> Optional[Alert]:
        if not self._is_internal(packet.src_ip) or self._is_internal(packet.dst_ip):
            return None
        key = (packet.src_ip, packet.dst_ip)
        self._history[key].append((packet.timestamp, packet.size))
        cutoff = packet.timestamp - self.window
        self._history[key] = [(ts, b) for ts, b in self._history[key] if ts >= cutoff]
        total_bytes = sum(b for _, b in self._history[key])
        if total_bytes < self.byte_threshold or key in self._alerted:
            return None
        self._alerted.add(key)
        total_mb = total_bytes / (1024 * 1024)
        severity = (
            AlertSeverity.CRITICAL if total_mb >= 50
            else AlertSeverity.HIGH if total_mb >= 10
            else AlertSeverity.MEDIUM
        )
        return Alert(
            alert_id=str(uuid.uuid4())[:8],
            alert_type=AlertType.DATA_EXFILTRATION,
            severity=severity,
            timestamp=packet.timestamp,
            source_ip=packet.src_ip,
            destination_ip=packet.dst_ip,
            description=f"Data exfiltration: {total_mb:.1f} MB from {packet.src_ip} to {packet.dst_ip}",
            details={"total_mb": round(total_mb, 2), "window_seconds": self.window.seconds},
        )

    def reset(self) -> None:
        self._history.clear()
        self._alerted.clear()
