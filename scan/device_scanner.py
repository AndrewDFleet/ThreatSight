"""
Device fingerprinting — no admin rights required.
Uses reverse DNS, HTTP/SSH banners, and port patterns to identify devices.
"""
import asyncio
import ipaddress
import socket
import logging
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)

# ── Device classification ─────────────────────────────────────────────────────

DEVICE_TYPES = {
    "router":     {"label": "Router / Gateway",  "icon": "🌐"},
    "windows":    {"label": "Windows Machine",    "icon": "🖥️"},
    "linux":      {"label": "Linux Server",       "icon": "🐧"},
    "web_server": {"label": "Web Server",         "icon": "🌍"},
    "db_server":  {"label": "Database Server",    "icon": "🗄️"},
    "iot":        {"label": "IoT / Camera",       "icon": "📷"},
    "printer":    {"label": "Printer",            "icon": "🖨️"},
    "network":    {"label": "Network Device",     "icon": "🔌"},
    "unknown":    {"label": "Unknown Device",     "icon": "❓"},
}

DB_PORTS    = {3306, 5432, 27017, 6379, 1433, 5984, 9200}
CAMERA_PORTS = {554, 8554, 8081, 37777}
PRINTER_PORTS = {9100, 515, 631}
NETWORK_PORTS = {161, 162, 179, 520}


def classify_device(open_ports: list[int]) -> str:
    """Return a device_type key from DEVICE_TYPES."""
    s = set(open_ports)
    if s & NETWORK_PORTS or (23 in s and len(s) <= 4):
        return "network"
    if s & CAMERA_PORTS:
        return "iot"
    if s & PRINTER_PORTS:
        return "printer"
    if {135, 445} & s or 3389 in s:
        return "windows"
    if s & DB_PORTS:
        return "db_server"
    if 22 in s and {80, 443, 8080, 8443} & s:
        return "linux"
    if {80, 443, 8080, 8443} & s:
        return "web_server"
    if 22 in s:
        return "linux"
    return "unknown"


def is_internal(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# ── Active fingerprinting ─────────────────────────────────────────────────────

@dataclass
class DeviceProfile:
    ip: str
    hostname: Optional[str] = None
    device_type: str = "unknown"
    os_hint: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    banner: Optional[str] = None
    risk_level: str = "clean"  # clean | suspicious | flagged


async def fingerprint(ip: str, open_ports: list[int]) -> DeviceProfile:
    profile = DeviceProfile(ip=ip, open_ports=sorted(open_ports))
    profile.device_type = classify_device(open_ports)

    hostname, http_banner, ssh_banner = await asyncio.gather(
        _reverse_dns(ip),
        _http_banner(ip) if {80, 8080, 8443, 443} & set(open_ports) else _noop(),
        _ssh_banner(ip)  if 22 in open_ports                          else _noop(),
    )

    profile.hostname = hostname
    raw_banner = http_banner or ssh_banner or ""
    profile.banner = raw_banner[:200] if raw_banner else None
    profile.os_hint = _detect_os(raw_banner, open_ports)
    profile.risk_level = _assess_risk(open_ports)

    return profile


async def _reverse_dns(ip: str) -> Optional[str]:
    try:
        loop = asyncio.get_event_loop()
        result = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip),
            timeout=2.0,
        )
        return result[0]
    except Exception:
        return None


async def _http_banner(ip: str) -> Optional[str]:
    for port in [80, 8080, 8443, 443]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=2.0
            )
            writer.write(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=2.0)
            writer.close()
            text = data.decode(errors="ignore")
            for line in text.splitlines():
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()
        except Exception:
            continue
    return None


async def _ssh_banner(ip: str) -> Optional[str]:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, 22), timeout=2.0
        )
        data = await asyncio.wait_for(reader.read(256), timeout=2.0)
        writer.close()
        return data.decode(errors="ignore").strip()
    except Exception:
        return None


async def _noop() -> None:
    return None


def _detect_os(banner: str, open_ports: list[int]) -> Optional[str]:
    b = (banner or "").lower()
    if "ubuntu" in b or "debian" in b:   return "Linux (Ubuntu/Debian)"
    if "centos" in b or "rhel" in b:     return "Linux (RHEL/CentOS)"
    if "openssh" in b:                   return "Linux/Unix"
    if "microsoft" in b or "iis" in b:  return "Windows"
    if "nginx" in b:                     return "Linux (nginx)"
    if "apache" in b:                    return "Linux (Apache)"
    if "cisco" in b:                     return "Cisco IOS"
    port_set = set(open_ports)
    if {135, 445, 3389} & port_set:      return "Windows"
    if 22 in port_set:                   return "Linux/Unix"
    return None


HIGH_RISK_PORTS = {23, 445, 3389, 6379, 27017, 9200, 2375}

def _assess_risk(open_ports: list[int]) -> str:
    s = set(open_ports)
    if s & HIGH_RISK_PORTS:
        return "flagged"
    if len(s) > 6:
        return "suspicious"
    return "clean"
