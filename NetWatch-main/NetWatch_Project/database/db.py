from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import List, Optional, Tuple


class DatabaseManager:
    """Central SQLite helper for all NetWatch data."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        project_root = Path(__file__).resolve().parent.parent
        self.db_path = Path(db_path or project_root / "netwatch.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _initialize_schema(self) -> None:
        conn = self._connect()
        cursor = conn.cursor()
        cursor.executescript(
            """
            CREATE TABLE IF NOT EXISTS dns_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                ip TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ping_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                latency REAL,
                status TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS port_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                port INTEGER NOT NULL,
                status TEXT NOT NULL,
                service_name TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS usage_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bytes_sent INTEGER NOT NULL,
                bytes_received INTEGER NOT NULL,
                upload_speed REAL NOT NULL,
                download_speed REAL NOT NULL,
                timestamp TEXT NOT NULL
            );



            CREATE TABLE IF NOT EXISTS url_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                classification TEXT NOT NULL,
                reasons TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS report_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );
            """
        )
        conn.commit()
        conn.close()

    def insert_dns_history(self, domain: str, ip: str, timestamp: str) -> None:
        conn = self._connect()
        conn.execute(
            "INSERT INTO dns_history (domain, ip, timestamp) VALUES (?, ?, ?)",
            (domain, ip, timestamp),
        )
        conn.commit()
        conn.close()

    def get_dns_history(self, limit: int = 20) -> List[Tuple[str, str, str]]:
        conn = self._connect()
        rows = conn.execute(
            "SELECT domain, ip, timestamp FROM dns_history ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [(row["domain"], row["ip"], row["timestamp"]) for row in rows]

    def insert_ping_history(self, target: str, latency: Optional[float], status: str, timestamp: str) -> None:
        conn = self._connect()
        conn.execute(
            "INSERT INTO ping_history (target, latency, status, timestamp) VALUES (?, ?, ?, ?)",
            (target, latency, status, timestamp),
        )
        conn.commit()
        conn.close()

    def get_ping_history(self, limit: int = 20) -> List[Tuple[str, Optional[float], str, str]]:
        conn = self._connect()
        rows = conn.execute(
            "SELECT target, latency, status, timestamp FROM ping_history ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [(row["target"], row["latency"], row["status"], row["timestamp"]) for row in rows]

    def insert_port_scan(self, target: str, port: int, status: str, service_name: str, timestamp: str) -> None:
        conn = self._connect()
        conn.execute(
            "INSERT INTO port_scans (target, port, status, service_name, timestamp) VALUES (?, ?, ?, ?, ?)",
            (target, port, status, service_name, timestamp),
        )
        conn.commit()
        conn.close()

    def get_port_scan_history(self, limit: int = 50) -> List[Tuple[str, int, str, str, str]]:
        conn = self._connect()
        rows = conn.execute(
            "SELECT target, port, status, service_name, timestamp FROM port_scans ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [(row["target"], row["port"], row["status"], row["service_name"], row["timestamp"]) for row in rows]

    def insert_usage_log(self, bytes_sent: int, bytes_received: int, upload_speed: float, download_speed: float, timestamp: str) -> None:
        conn = self._connect()
        conn.execute(
            "INSERT INTO usage_logs (bytes_sent, bytes_received, upload_speed, download_speed, timestamp) VALUES (?, ?, ?, ?, ?)",
            (bytes_sent, bytes_received, upload_speed, download_speed, timestamp),
        )
        conn.commit()
        conn.close()

    def get_usage_logs(self, limit: int = 100) -> List[Tuple[int, int, float, float, str]]:
        conn = self._connect()
        rows = conn.execute(
            "SELECT bytes_sent, bytes_received, upload_speed, download_speed, timestamp FROM usage_logs ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [(row["bytes_sent"], row["bytes_received"], row["upload_speed"], row["download_speed"], row["timestamp"]) for row in rows]

    def insert_url_scan(self, url: str, risk_score: int, classification: str, reasons: str, timestamp: str) -> None:
        conn = self._connect()
        conn.execute(
            "INSERT INTO url_scans (url, risk_score, classification, reasons, timestamp) VALUES (?, ?, ?, ?, ?)",
            (url, risk_score, classification, reasons, timestamp),
        )
        conn.commit()
        conn.close()

    def get_url_scan_history(self, limit: int = 50) -> List[Tuple[str, int, str, str, str]]:
        conn = self._connect()
        rows = conn.execute(
            "SELECT url, risk_score, classification, reasons, timestamp FROM url_scans ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [(row["url"], row["risk_score"], row["classification"], row["reasons"], row["timestamp"]) for row in rows]

    def insert_report_history(self, report_name: str, file_path: str, timestamp: str) -> None:
        conn = self._connect()
        conn.execute(
            "INSERT INTO report_history (report_name, file_path, timestamp) VALUES (?, ?, ?)",
            (report_name, file_path, timestamp),
        )
        conn.commit()
        conn.close()

    def get_report_history(self, limit: int = 20) -> List[Tuple[str, str, str]]:
        conn = self._connect()
        rows = conn.execute(
            "SELECT report_name, file_path, timestamp FROM report_history ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [(row["report_name"], row["file_path"], row["timestamp"]) for row in rows]
