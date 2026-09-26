from __future__ import annotations
import sqlite3
import json
from datetime import datetime
from typing import Any, Optional
from pathlib import Path


class SecurityDatabase:
    """Embedded SQLite persistence engine for Aegis-X events, scans, and audit trails."""

    def __init__(self, db_path: str = "aegis_telemetry.db"):
        import os
        if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME") or not os.access(".", os.W_OK):
            self.db_path = "/tmp/aegis_telemetry.db"
        else:
            self.db_path = db_path
        self._init_tables()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self) -> None:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    incident_count INTEGER NOT NULL,
                    entity_count INTEGER NOT NULL,
                    metrics_json TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    entity_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT NOT NULL
                )
            """)
            conn.commit()

    def record_scan(self, scan_id: str, score: int, incident_count: int, entity_count: int, metrics: dict[str, Any]) -> None:
        with self._get_conn() as conn:
            conn.cursor().execute("""
                INSERT OR REPLACE INTO scans (id, timestamp, score, incident_count, entity_count, metrics_json)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (scan_id, datetime.utcnow().isoformat(), score, incident_count, entity_count, json.dumps(metrics)))
            conn.commit()

    def record_incident(self, scan_id: str, inc_dict: dict[str, Any]) -> None:
        with self._get_conn() as conn:
            conn.cursor().execute("""
                INSERT OR REPLACE INTO incidents (incident_id, scan_id, rule_id, title, severity, entity_name, status, data_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                inc_dict["incident_id"],
                scan_id,
                inc_dict["rule_id"],
                inc_dict["title"],
                inc_dict["severity"],
                inc_dict["entity"]["name"],
                inc_dict["status"],
                json.dumps(inc_dict),
                inc_dict["created_at"],
            ))
            conn.commit()

    def update_incident_status(self, incident_id: str, new_status: str) -> None:
        with self._get_conn() as conn:
            conn.cursor().execute("UPDATE incidents SET status = ? WHERE incident_id = ?", (new_status, incident_id))
            conn.commit()

    def record_audit(self, incident_id: str, action: str, details: str) -> None:
        with self._get_conn() as conn:
            conn.cursor().execute("""
                INSERT INTO audit_logs (timestamp, incident_id, action, details)
                VALUES (?, ?, ?, ?)
            """, (datetime.utcnow().isoformat(), incident_id, action, details))
            conn.commit()

    def get_recent_scans(self, limit: int = 15) -> list[dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.cursor().execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def get_recent_audits(self, limit: int = 25) -> list[dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.cursor().execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]
