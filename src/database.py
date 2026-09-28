from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import get_settings
from .models import Alert


class AlertDatabase:
    def __init__(self, database_path: str | None = None):
        settings = get_settings()
        self.database_path = database_path or settings.database_path
        self._ensure_parent_directory()
        self._initialize()

    def _ensure_parent_directory(self) -> None:
        path = Path(self.database_path)
        path.parent.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.database_path)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _json_dump(value: dict[str, Any]) -> str:
        return json.dumps(value, sort_keys=True)

    @staticmethod
    def _json_load(value: str | None) -> dict[str, Any]:
        if not value:
            return {}
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return {}

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    description TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    metadata TEXT NOT NULL
                )
                """
            )

    def add_alert(self, alert: Alert) -> Alert:
        alert.timestamp = alert.timestamp or datetime.now(timezone.utc)
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO alerts (timestamp, severity, rule_name, source_ip, destination_ip, description, evidence, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.timestamp.isoformat(),
                    alert.severity,
                    alert.rule_name,
                    alert.source_ip,
                    alert.destination_ip,
                    alert.description,
                    self._json_dump(alert.evidence),
                    self._json_dump(alert.metadata),
                ),
            )
            alert.id = cursor.lastrowid
        return alert

    def get_recent_alerts(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def _row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "severity": row["severity"],
            "rule_name": row["rule_name"],
            "source_ip": row["source_ip"],
            "destination_ip": row["destination_ip"],
            "description": row["description"],
            "evidence": self._json_load(row["evidence"]),
            "metadata": self._json_load(row["metadata"]),
        }

    def get_alerts_by_rule(self, rule_name: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE rule_name = ? ORDER BY id DESC",
                (rule_name,),
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def get_alerts_by_severity(self, severity: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE severity = ? ORDER BY id DESC",
                (severity,),
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def get_statistics(self) -> dict[str, int]:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            high = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'HIGH'").fetchone()[0]
            medium = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'MEDIUM'").fetchone()[0]
            low = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'LOW'").fetchone()[0]
            return {"total": total, "high": high, "medium": medium, "low": low}

    def close(self) -> None:
        pass
