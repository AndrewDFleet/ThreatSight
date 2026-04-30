import asyncio
import json
import logging
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from db import queries
import config

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api")


@router.get("/alerts")
async def get_alerts(limit: int = 50, severity: str | None = None):
    return await queries.get_recent_alerts(limit=limit, severity=severity)


@router.get("/alerts/{alert_id}")
async def get_alert(alert_id: str):
    result = await queries.get_alert_with_analysis(alert_id)
    if not result:
        raise HTTPException(status_code=404, detail="Alert not found")
    return result


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge(alert_id: str):
    ok = await queries.acknowledge_alert(alert_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"status": "acknowledged"}


@router.get("/status")
async def status(request: Request):
    from core.engine_runner import get_runner
    from api.websocket import connection_manager
    runner = get_runner()
    counts = await queries.get_alert_counts()
    return {
        "mode": "demo" if config.DEMO_MODE else "live",
        "ai_enabled": config.AI_ENABLED,
        "ws_clients": connection_manager.client_count,
        "alert_counts": counts,
        "packets_processed": runner._total_packets if runner else 0,
    }


@router.get("/report", response_class=PlainTextResponse)
async def generate_report(request: Request):
    import asyncio
    from ai.report_generator import ReportGenerator
    from ai.ai_analyzer import AlertAnalysis

    rows = await queries.get_recent_alerts(limit=20)
    if not rows:
        return "No alerts to report."

    from models import Alert, AlertType, AlertSeverity
    from datetime import datetime

    alerts = []
    for r in rows:
        try:
            alert = Alert(
                alert_id=r["alert_id"],
                alert_type=AlertType(r["alert_type"]),
                severity=AlertSeverity(r["severity"]),
                timestamp=datetime.fromisoformat(r["timestamp"]),
                source_ip=r.get("source_ip"),
                destination_ip=r.get("dest_ip"),
                description=r.get("description", ""),
            )
            alerts.append(alert)
        except Exception:
            continue

    dummy_analyses = [
        AlertAnalysis(
            alert_id=a.alert_id,
            threat_assessment="See database for full AI analysis.",
            recommended_actions=["Review alert details."],
            context="",
            false_positive_likelihood="medium",
            priority="medium",
        )
        for a in alerts
    ]

    loop = asyncio.get_event_loop()
    reporter = ReportGenerator()
    report = await loop.run_in_executor(
        None, reporter.generate_report, alerts, dummy_analyses
    )
    return report


# ── Scan endpoints ────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    scan_type: str = "quick"  # quick | standard


@router.get("/scan/local-ip")
async def local_ip():
    from scan.scanner import get_local_ip, get_gateway_ip
    return {"local_ip": get_local_ip(), "gateway": get_gateway_ip()}


@router.post("/scan/start")
async def start_scan(body: ScanRequest):
    target = body.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="target is required")
    asyncio.create_task(_scan_task(target, body.scan_type))
    return {"status": "started", "target": target, "scan_type": body.scan_type}


async def _scan_task(target: str, scan_type: str) -> None:
    from scan.scanner import run_scan
    from api.websocket import connection_manager

    async def broadcast(msg: dict) -> None:
        await connection_manager.broadcast(json.dumps(msg))

    await broadcast({"type": "scan_start", "data": {"target": target, "scan_type": scan_type}})

    async def on_progress(done: int, total: int) -> None:
        await broadcast({"type": "scan_progress",
                         "data": {"done": done, "total": total,
                                  "pct": round(done / total * 100)}})

    async def on_open(result) -> None:
        await broadcast({"type": "scan_result",
                         "data": {"ip": result.ip, "port": result.port,
                                  "service": result.service, "risk": result.risk}})

    summary = await run_scan(target, scan_type, on_progress, on_open)

    # Fingerprint the device and update the registry
    if not summary.error and summary.open_ports:
        try:
            from scan.device_scanner import fingerprint, DEVICE_TYPES
            from db import queries as _q
            profile = await fingerprint(target, [r.port for r in summary.open_ports])
            await _q.update_device_profile(profile)
            info = DEVICE_TYPES.get(profile.device_type, DEVICE_TYPES["unknown"])
            device_data = await _q.get_device(target)
            if device_data:
                await broadcast({
                    "type": "device_updated",
                    "data": {**device_data, "icon": info["icon"], "label": info["label"]},
                })
        except Exception as e:
            logger.warning("Device fingerprinting failed: %s", e)

    await broadcast({
        "type": "scan_complete",
        "data": {
            "target": target,
            "scan_type": scan_type,
            "ports_scanned": summary.ports_scanned,
            "open_count": len(summary.open_ports),
            "open_ports": [{"port": r.port, "service": r.service, "risk": r.risk}
                           for r in summary.open_ports],
            "error": summary.error,
        },
    })


@router.get("/devices")
async def get_devices():
    from scan.device_scanner import DEVICE_TYPES
    devices = await queries.get_all_devices()
    for d in devices:
        info = DEVICE_TYPES.get(d.get("device_type", "unknown"), DEVICE_TYPES["unknown"])
        d["icon"]  = info["icon"]
        d["label"] = info["label"]
    return devices


@router.get("/devices/{ip}")
async def get_device(ip: str):
    from scan.device_scanner import DEVICE_TYPES
    d = await queries.get_device(ip)
    if not d:
        raise HTTPException(status_code=404, detail="Device not found")
    info = DEVICE_TYPES.get(d.get("device_type", "unknown"), DEVICE_TYPES["unknown"])
    d["icon"]  = info["icon"]
    d["label"] = info["label"]
    return d


@router.post("/scan/analyze")
async def analyze_scan(body: dict):
    if not config.AI_ENABLED:
        raise HTTPException(status_code=503, detail="AI analysis is disabled — add ANTHROPIC_API_KEY to .env")

    target = body.get("target", "unknown")
    open_ports = body.get("open_ports", [])

    if not open_ports:
        return {"analysis": "No open ports found — target appears well-hardened or offline."}

    port_lines = "\n".join(
        f"  Port {p['port']} ({p['service']}) — risk: {p['risk']}"
        for p in open_ports
    )
    prompt = (
        f"I ran a port scan on {target} and found these open ports:\n\n"
        f"{port_lines}\n\n"
        "Provide a security assessment of this attack surface in JSON with these fields:\n"
        '{"threat_assessment": "...", "highest_risk_port": <int>, '
        '"recommended_actions": ["...", "..."], "overall_risk": "low|medium|high|critical"}'
    )

    import anthropic
    from ai import ai_config

    loop = asyncio.get_event_loop()

    def call_claude():
        client = anthropic.Anthropic(api_key=ai_config.ANTHROPIC_API_KEY)
        response = client.messages.create(
            model=ai_config.MODEL,
            max_tokens=1024,
            thinking={"type": "adaptive"},
            output_config={"effort": "medium"},
            messages=[{"role": "user", "content": prompt}],
        )
        for block in response.content:
            if block.type == "text":
                return block.text
        return ""

    raw = await loop.run_in_executor(None, call_claude)

    text = raw.strip()
    if "```" in text:
        lines = text.splitlines()
        text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
    if "{" in text and "}" in text:
        text = text[text.index("{"):text.rindex("}") + 1]

    try:
        import json as _json
        return _json.loads(text)
    except Exception:
        return {"analysis": raw}
