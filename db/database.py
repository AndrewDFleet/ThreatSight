import aiosqlite
import config

_CREATE_ALERTS = """
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id    TEXT NOT NULL UNIQUE,
    alert_type  TEXT NOT NULL,
    severity    TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    source_ip   TEXT,
    dest_ip     TEXT,
    port        INTEGER,
    description TEXT,
    details     TEXT,
    acknowledged INTEGER DEFAULT 0
);
"""

_CREATE_ANALYSES = """
CREATE TABLE IF NOT EXISTS analyses (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id                  TEXT NOT NULL REFERENCES alerts(alert_id),
    threat_assessment         TEXT,
    recommended_actions       TEXT,
    context                   TEXT,
    false_positive_likelihood TEXT,
    priority                  TEXT,
    tokens_used               INTEGER DEFAULT 0,
    cache_read_tokens         INTEGER DEFAULT 0,
    error                     TEXT,
    created_at                TEXT NOT NULL
);
"""

_CREATE_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_analyses_alert   ON analyses(alert_id);
"""


async def init_db() -> None:
    async with aiosqlite.connect(config.DB_PATH) as db:
        await db.execute(_CREATE_ALERTS)
        await db.execute(_CREATE_ANALYSES)
        for stmt in _CREATE_INDEXES.strip().split(";"):
            stmt = stmt.strip()
            if stmt:
                await db.execute(stmt)
        await db.commit()
