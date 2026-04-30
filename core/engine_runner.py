import asyncio
import json
import logging
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import config
from models import Packet, NetworkStats
from detectors import DetectionEngine
from db import queries
from api.websocket import connection_manager

logger = logging.getLogger(__name__)

_STATS_INTERVAL = 2.0
_PPS_WINDOW = 5.0


class EngineRunner:
    def __init__(self):
        self.queue: asyncio.Queue[Packet] = asyncio.Queue(maxsize=20000)
        self._engine = DetectionEngine()
        self._executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="ai-worker")
        self._running = False

        self._total_packets = 0
        self._total_bytes = 0
        self._total_alerts = 0
        self._pending_ips: set = set()
        self._protocol_counts: Counter = Counter()
        self._src_ip_counts: Counter = Counter()
        self._dst_ip_set: set = set()
        self._active_flows: set = set()
        self._recent: deque = deque()  # (datetime, size_bytes)
        self._start_time = datetime.utcnow()

        self._analyzer = None
        if config.AI_ENABLED:
            try:
                from ai.ai_analyzer import AIAnalyzer
                self._analyzer = AIAnalyzer()
                logger.info("AI analysis enabled")
            except Exception as e:
                logger.warning("AI analyzer unavailable: %s", e)

    async def start(self) -> None:
        self._running = True
        self._start_time = datetime.utcnow()

        if not config.DEMO_MODE and self._try_live_capture():
            logger.info("Live capture active")
        else:
            from core.demo_mode import DemoModeRunner
            asyncio.create_task(DemoModeRunner(self.queue).run(), name="demo-mode")
            logger.info("Demo mode active")

        asyncio.create_task(self._process_loop(), name="packet-processor")
        asyncio.create_task(self._stats_loop(), name="stats-broadcaster")
        asyncio.create_task(self._device_flush_loop(), name="device-flusher")

    def stop(self) -> None:
        self._running = False
        self._executor.shutdown(wait=False)

    def _try_live_capture(self) -> bool:
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                logger.warning("Not running as Administrator — falling back to demo mode")
                return False
            from capture.packet_capture import LiveCapturer
            capturer = LiveCapturer(self.queue)
            capturer.start()
            return True
        except Exception as e:
            logger.warning("Live capture unavailable (%s) — falling back to demo mode", e)
            return False

    async def _process_loop(self) -> None:
        while self._running:
            try:
                packet = await asyncio.wait_for(self.queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            self._update_stats(packet)
            self._pending_ips.add(packet.src_ip)
            alerts = self._engine.process_packet(packet)
            for alert in alerts:
                await self._handle_alert(alert)

    async def _handle_alert(self, alert) -> None:
        self._total_alerts += 1
        await queries.insert_alert(alert)
        await connection_manager.broadcast(json.dumps({
            "type": "alert",
            "data": alert.to_dict(),
        }, default=str))
        if self._analyzer:
            asyncio.create_task(self._run_ai(alert), name=f"ai-{alert.alert_id}")

    async def _run_ai(self, alert) -> None:
        loop = asyncio.get_event_loop()
        try:
            analysis = await loop.run_in_executor(
                self._executor, self._analyzer.analyze_alert, alert
            )
            await queries.insert_analysis(analysis)
            await connection_manager.broadcast(json.dumps({
                "type": "analysis",
                "data": {
                    "alert_id": analysis.alert_id,
                    "threat_assessment": analysis.threat_assessment,
                    "recommended_actions": analysis.recommended_actions,
                    "context": analysis.context,
                    "false_positive_likelihood": analysis.false_positive_likelihood,
                    "priority": analysis.priority,
                    "tokens_used": analysis.tokens_used,
                },
            }))
        except Exception as e:
            logger.error("AI analysis failed for %s: %s", alert.alert_id, e)

    async def _stats_loop(self) -> None:
        while self._running:
            await asyncio.sleep(_STATS_INTERVAL)
            stats = self._build_stats()
            d = stats.to_dict()
            d["top_talkers"] = [[ip, cnt] for ip, cnt in d["top_talkers"]]
            d["uptime_seconds"] = int((datetime.utcnow() - self._start_time).total_seconds())
            d["total_alerts"] = self._total_alerts
            d["mode"] = "demo" if config.DEMO_MODE else "live"
            d["ai_enabled"] = config.AI_ENABLED
            await connection_manager.broadcast(json.dumps({"type": "stats", "data": d}, default=str))
            self._active_flows.clear()

    async def _device_flush_loop(self) -> None:
        from db import queries
        from scan.device_scanner import DEVICE_TYPES
        while self._running:
            await asyncio.sleep(15)
            batch, self._pending_ips = self._pending_ips.copy(), set()
            for ip in batch:
                is_new = await queries.upsert_device_seen(ip)
                if is_new:
                    device = await queries.get_device(ip)
                    if device:
                        info = DEVICE_TYPES.get(device["device_type"], DEVICE_TYPES["unknown"])
                        await connection_manager.broadcast(json.dumps({
                            "type": "device_discovered",
                            "data": {**device, "icon": info["icon"], "label": info["label"]},
                        }, default=str))

    def _update_stats(self, packet: Packet) -> None:
        now = datetime.utcnow()
        self._total_packets += 1
        self._total_bytes += packet.size
        self._protocol_counts[packet.protocol.value] += 1
        self._src_ip_counts[packet.src_ip] += 1
        self._dst_ip_set.add(packet.dst_ip)
        self._active_flows.add(packet.flow_key)
        self._recent.append((now, packet.size))
        cutoff = now - timedelta(seconds=_PPS_WINDOW)
        while self._recent and self._recent[0][0] < cutoff:
            self._recent.popleft()

    def _build_stats(self) -> NetworkStats:
        window = len(self._recent)
        window_bytes = sum(s for _, s in self._recent)
        return NetworkStats(
            timestamp=datetime.utcnow(),
            total_packets=self._total_packets,
            total_bytes=self._total_bytes,
            packets_per_second=round(window / _PPS_WINDOW, 1),
            bytes_per_second=round(window_bytes / _PPS_WINDOW, 1),
            active_flows=len(self._active_flows),
            unique_src_ips=len(self._src_ip_counts),
            unique_dst_ips=len(self._dst_ip_set),
            protocol_distribution=dict(self._protocol_counts),
            top_talkers=self._src_ip_counts.most_common(5),
        )


_runner: EngineRunner | None = None


def get_runner() -> EngineRunner:
    return _runner


def create_runner() -> EngineRunner:
    global _runner
    _runner = EngineRunner()
    return _runner
