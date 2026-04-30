from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse
from db import queries
import config

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
