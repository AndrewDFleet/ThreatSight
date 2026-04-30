import asyncio
import ipaddress
import socket
import logging
from dataclasses import dataclass, field
from typing import Awaitable, Callable, List, Optional

logger = logging.getLogger(__name__)

SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1723: "PPTP", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

RISK_MAP = {
    23: "high",    # Telnet — unencrypted
    135: "medium", # RPC
    139: "medium", # NetBIOS
    445: "high",   # SMB — frequent ransomware vector
    1433: "medium",# MSSQL
    3389: "high",  # RDP — top brute-force target
    5900: "medium",# VNC
    6379: "high",  # Redis — often exposed without auth
    27017: "high", # MongoDB — often exposed without auth
}

QUICK_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 139,
    143, 443, 445, 993, 995, 3306, 3389,
    5432, 5900, 6379, 8080, 27017,
]

STANDARD_PORTS = sorted(set(QUICK_PORTS + [
    81, 88, 111, 389, 465, 587, 631, 636, 873,
    1080, 1194, 1433, 1723, 2049, 2375, 3000,
    4443, 5000, 5001, 5601, 7001, 8000, 8009,
    8081, 8443, 8888, 9000, 9200, 9418,
]))


@dataclass
class PortResult:
    ip: str
    port: int
    service: str
    risk: str  # low | medium | high


@dataclass
class ScanSummary:
    target: str
    scan_type: str
    ports_scanned: int
    open_ports: List[PortResult] = field(default_factory=list)
    error: Optional[str] = None


async def _scan_port(ip: str, port: int, timeout: float = 0.75) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def run_scan(
    target: str,
    scan_type: str,
    on_progress: Callable[[int, int], Awaitable[None]],
    on_open: Callable[[PortResult], Awaitable[None]],
) -> ScanSummary:
    try:
        ipaddress.ip_address(target)
    except ValueError:
        return ScanSummary(target=target, scan_type=scan_type, ports_scanned=0,
                           error="Invalid IP address")

    ports = QUICK_PORTS if scan_type == "quick" else STANDARD_PORTS
    open_ports: List[PortResult] = []
    semaphore = asyncio.Semaphore(40)
    scanned = 0

    async def check(port: int) -> None:
        nonlocal scanned
        async with semaphore:
            is_open = await _scan_port(target, port)
            scanned += 1
            if is_open:
                result = PortResult(
                    ip=target,
                    port=port,
                    service=SERVICE_MAP.get(port, "unknown"),
                    risk=RISK_MAP.get(port, "low"),
                )
                open_ports.append(result)
                await on_open(result)
            if scanned % 5 == 0 or scanned == len(ports):
                await on_progress(scanned, len(ports))

    await asyncio.gather(*[check(p) for p in ports])

    return ScanSummary(
        target=target,
        scan_type=scan_type,
        ports_scanned=len(ports),
        open_ports=sorted(open_ports, key=lambda r: r.port),
    )


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_gateway_ip() -> str:
    local = get_local_ip()
    parts = local.rsplit(".", 1)
    return f"{parts[0]}.1" if len(parts) == 2 else local
