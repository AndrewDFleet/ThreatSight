import json
import aiosqlite
from datetime import datetime
from typing import List, Optional

import config
from models import Alert


async def insert_alert(alert: Alert) -> None:
    async with aiosqlite.connect(config.DB_PATH) as db:
        await db.execute(
            """INSERT OR IGNORE INTO alerts
               (alert_id, alert_type, severity, timestamp, source_ip, dest_ip, port, description, details)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                alert.alert_id,
                alert.alert_type.value,
                alert.severity.value,
                alert.timestamp.isoformat(),
                alert.source_ip,
                alert.destination_ip,
                alert.port,
                alert.description,
                json.dumps(alert.details),
            ),
        )
        await db.commit()


async def insert_analysis(analysis) -> None:
    async with aiosqlite.connect(config.DB_PATH) as db:
        await db.execute(
            """INSERT INTO analyses
               (alert_id, threat_assessment, recommended_actions, context,
                false_positive_likelihood, priority, tokens_used, cache_read_tokens, error, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                analysis.alert_id,
                analysis.threat_assessment,
                json.dumps(analysis.recommended_actions),
                analysis.context,
                analysis.false_positive_likelihood,
                analysis.priority,
                analysis.tokens_used,
                analysis.cache_read_tokens,
                analysis.error,
                datetime.utcnow().isoformat(),
            ),
        )
        await db.commit()


async def get_recent_alerts(limit: int = 50, severity: Optional[str] = None) -> List[dict]:
    async with aiosqlite.connect(config.DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if severity:
            cursor = await db.execute(
                "SELECT * FROM alerts WHERE severity = ? ORDER BY timestamp DESC LIMIT ?",
                (severity, limit),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_alert_with_analysis(alert_id: str) -> Optional[dict]:
    async with aiosqlite.connect(config.DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """SELECT a.*, an.threat_assessment, an.recommended_actions,
                      an.context, an.false_positive_likelihood, an.priority,
                      an.tokens_used, an.error
               FROM alerts a
               LEFT JOIN analyses an ON a.alert_id = an.alert_id
               WHERE a.alert_id = ?""",
            (alert_id,),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        result = dict(row)
        if result.get("recommended_actions"):
            result["recommended_actions"] = json.loads(result["recommended_actions"])
        return result


async def acknowledge_alert(alert_id: str) -> bool:
    async with aiosqlite.connect(config.DB_PATH) as db:
        cursor = await db.execute(
            "UPDATE alerts SET acknowledged = 1 WHERE alert_id = ?", (alert_id,)
        )
        await db.commit()
        return cursor.rowcount > 0


async def get_alert_counts() -> dict:
    async with aiosqlite.connect(config.DB_PATH) as db:
        cursor = await db.execute(
            "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
        )
        rows = await cursor.fetchall()
        return {row[0]: row[1] for row in rows}
