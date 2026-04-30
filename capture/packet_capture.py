"""Live packet capture via Scapy — activated in Phase 4 when running as Administrator."""
import asyncio
import logging
import threading
from capture.packet_adapter import scapy_to_packet

logger = logging.getLogger(__name__)


class LiveCapturer:
    def __init__(self, queue: asyncio.Queue, interface: str | None = None):
        self._queue = queue
        self._interface = interface
        self._loop = asyncio.get_event_loop()
        self._thread: threading.Thread | None = None
        self._running = False

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._sniff, daemon=True, name="scapy-capture")
        self._thread.start()
        logger.info("Live capture started on interface: %s", self._interface or "default")

    def stop(self) -> None:
        self._running = False

    def _sniff(self) -> None:
        from scapy.all import sniff
        sniff(
            iface=self._interface,
            prn=self._handle_packet,
            store=False,
            stop_filter=lambda _: not self._running,
        )

    def _handle_packet(self, scapy_pkt) -> None:
        packet = scapy_to_packet(scapy_pkt)
        if packet:
            self._loop.call_soon_threadsafe(self._queue.put_nowait, packet)
