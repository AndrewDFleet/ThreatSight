import asyncio
import logging
from datetime import datetime, timedelta

from models import Packet
from traffic_simulator import TrafficSimulator

logger = logging.getLogger(__name__)

PACKET_INTERVAL = 0.04  # ~25 packets/sec — fast enough to look lively


class DemoModeRunner:
    def __init__(self, queue: asyncio.Queue):
        self._queue = queue
        self._sim = TrafficSimulator()

    async def run(self) -> None:
        logger.info("Demo mode started")
        cycle = 0
        while True:
            cycle += 1
            logger.debug("Demo cycle %d", cycle)
            packets = self._build_cycle()
            for packet in packets:
                packet = self._freshen(packet)
                await self._queue.put(packet)
                await asyncio.sleep(PACKET_INTERVAL)
            await asyncio.sleep(5)

    def _build_cycle(self) -> list[Packet]:
        s = self._sim
        packets: list[Packet] = []
        packets.extend(s.generate_normal_traffic(80))
        packets.extend(s.generate_port_scan(port_count=200))
        packets.extend(s.generate_normal_traffic(40))
        packets.extend(s.generate_brute_force(attempts=60))
        packets.extend(s.generate_normal_traffic(40))
        packets.extend(s.generate_ddos(duration_seconds=4, packets_per_second=1000))
        packets.extend(s.generate_normal_traffic(40))
        packets.extend(s.generate_data_exfiltration(size_mb=10))
        packets.extend(s.generate_normal_traffic(80))
        packets.sort(key=lambda p: p.timestamp)
        return packets

    @staticmethod
    def _freshen(packet: Packet) -> Packet:
        """Shift packet timestamp to now so detector windows stay accurate."""
        packet.timestamp = datetime.now()
        return packet
