"""
Memory Module — SQLite-backed incident store.

Provides persistent storage for:
  - Incidents (threats detected across all scanners)
  - Recurring attack patterns (signature-based)

All data persists across restarts.  Replaces the "FAISS+SQLite" claim
from the Phase-1 report with a straight, honest SQLite implementation.
"""

import sqlite3
import json
import uuid
from datetime import datetime
from pathlib import Path

# ─── Database path ────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent  # backend/
DB_PATH  = BASE_DIR / "scans" / "memory.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)


# ─── Schema bootstrap ─────────────────────────────────────────────────────────
def _init_db(con: sqlite3.Connection) -> None:
    con.executescript("""
    CREATE TABLE IF NOT EXISTS incidents (
        id          TEXT PRIMARY KEY,
        timestamp   TEXT NOT NULL,
        type        TEXT NOT NULL,
        severity    TEXT NOT NULL,
        scanner     TEXT NOT NULL,
        title       TEXT NOT NULL,
        details     TEXT NOT NULL DEFAULT '{}',
        status      TEXT NOT NULL DEFAULT 'open',
        resolved_at TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_incidents_status    ON incidents(status);
    CREATE INDEX IF NOT EXISTS idx_incidents_severity  ON incidents(severity);
    CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp);

    CREATE TABLE IF NOT EXISTS patterns (
        signature   TEXT PRIMARY KEY,
        first_seen  TEXT NOT NULL,
        last_seen   TEXT NOT NULL,
        hit_count   INTEGER NOT NULL DEFAULT 1,
        severity    TEXT NOT NULL
    );
    """)
    con.commit()


def _get_con() -> sqlite3.Connection:
    con = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    con.row_factory = sqlite3.Row
    _init_db(con)
    return con


# ─── Write helpers ────────────────────────────────────────────────────────────
def add_incident(
    type_: str,
    severity: str,
    scanner: str,
    title: str,
    details: dict | None = None,
) -> str:
    """Insert a new incident. Returns generated id."""
    incident_id = str(uuid.uuid4())[:8].upper()
    now = datetime.utcnow().isoformat()
    with _get_con() as con:
        con.execute(
            """INSERT INTO incidents (id, timestamp, type, severity, scanner, title, details)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (incident_id, now, type_, severity, scanner, title,
             json.dumps(details or {})),
        )
    return incident_id


def update_pattern(signature: str, severity: str) -> None:
    """Upsert a pattern — increments hit_count on repeat."""
    now = datetime.utcnow().isoformat()
    with _get_con() as con:
        row = con.execute(
            "SELECT signature FROM patterns WHERE signature = ?", (signature,)
        ).fetchone()
        if row:
            con.execute(
                """UPDATE patterns SET last_seen = ?, hit_count = hit_count + 1
                   WHERE signature = ?""",
                (now, signature),
            )
        else:
            con.execute(
                """INSERT INTO patterns (signature, first_seen, last_seen, severity)
                   VALUES (?, ?, ?, ?)""",
                (signature, now, now, severity),
            )


def resolve_incident(incident_id: str) -> bool:
    """Mark an incident as resolved. Returns True if found."""
    now = datetime.utcnow().isoformat()
    with _get_con() as con:
        cur = con.execute(
            """UPDATE incidents SET status = 'resolved', resolved_at = ?
               WHERE id = ? AND status != 'resolved'""",
            (now, incident_id),
        )
        return cur.rowcount > 0


# ─── Read helpers ─────────────────────────────────────────────────────────────
def get_incidents(
    status: str | None = None,
    severity: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """Fetch incidents with optional filters."""
    query = "SELECT * FROM incidents WHERE 1=1"
    params: list = []
    if status:
        query += " AND status = ?"
        params.append(status)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    with _get_con() as con:
        rows = con.execute(query, params).fetchall()

    result = []
    for r in rows:
        row_dict = dict(r)
        row_dict["details"] = json.loads(row_dict.get("details", "{}"))
        result.append(row_dict)
    return result


def get_stats() -> dict:
    """Return aggregate stats for the memory store."""
    with _get_con() as con:
        total    = con.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        open_    = con.execute("SELECT COUNT(*) FROM incidents WHERE status = 'open'").fetchone()[0]
        resolved = con.execute("SELECT COUNT(*) FROM incidents WHERE status = 'resolved'").fetchone()[0]
        patterns = con.execute("SELECT COUNT(*) FROM patterns WHERE hit_count > 1").fetchone()[0]
        top_patterns = con.execute(
            "SELECT signature, hit_count, severity FROM patterns ORDER BY hit_count DESC LIMIT 5"
        ).fetchall()

    return {
        "total_incidents": total,
        "open":            open_,
        "in_progress":     0,
        "resolved":        resolved,
        "recurring_patterns": patterns,
        "top_patterns": [dict(p) for p in top_patterns],
    }
