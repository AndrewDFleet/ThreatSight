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


# ── Device queries ─────────────────────────────────────────────────────────────

async def upsert_device_seen(ip: str) -> bool:
    """Record that we've seen this IP. Returns True if it's a new device."""
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(config.DB_PATH) as db:
        cursor = await db.execute("SELECT id FROM devices WHERE ip = ?", (ip,))
        exists = await cursor.fetchone()
        if exists:
            await db.execute("UPDATE devices SET last_seen = ? WHERE ip = ?", (now, ip))
        else:
            await db.execute(
                "INSERT INTO devices (ip, first_seen, last_seen) VALUES (?, ?, ?)",
                (ip, now, now),
            )
        await db.commit()
        return not exists


async def update_device_profile(profile) -> None:
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(config.DB_PATH) as db:
        await db.execute(
            """INSERT INTO devices (ip, hostname, device_type, os_hint, open_ports, banner, risk_level, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(ip) DO UPDATE SET
                 hostname    = excluded.hostname,
                 device_type = excluded.device_type,
                 os_hint     = excluded.os_hint,
                 open_ports  = excluded.open_ports,
                 banner      = excluded.banner,
                 risk_level  = excluded.risk_level,
                 last_seen   = excluded.last_seen""",
            (
                profile.ip,
                profile.hostname,
                profile.device_type,
                profile.os_hint,
                json.dumps(profile.open_ports),
                profile.banner,
                profile.risk_level,
                now, now,
            ),
        )
        await db.commit()


async def get_all_devices() -> List[dict]:
    async with aiosqlite.connect(config.DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM devices ORDER BY last_seen DESC")
        rows = await cursor.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["open_ports"] = json.loads(d.get("open_ports") or "[]")
            result.append(d)
        return result


async def get_device(ip: str) -> Optional[dict]:
    async with aiosqlite.connect(config.DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM devices WHERE ip = ?", (ip,))
        row = await cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        d["open_ports"] = json.loads(d.get("open_ports") or "[]")
        return d
