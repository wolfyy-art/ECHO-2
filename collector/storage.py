"""
collector/storage.py
====================
ECHO — Telemetry Storage Engine.

Safely handles persistence of raw process and network telemetry snapshots
into SQLite using safe, non-destructive extensions to the database schema.
Preserves existing database records and tables.
"""

import sqlite3
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from dashboard.database import DB_PATH, _get_connection, init_database
from collector.models import ProcessTelemetry, NetworkTelemetry

logger = logging.getLogger(__name__)

# Schema for raw telemetry snapshots (extending SQLite without modifying existing tables)
_CREATE_RAW_PROCESS_TELEMETRY = """
CREATE TABLE IF NOT EXISTS raw_process_telemetry (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp           TEXT    NOT NULL,
    pid                 INTEGER NOT NULL,
    ppid                INTEGER NOT NULL,
    process_name        TEXT    NOT NULL,
    username            TEXT,
    exe                 TEXT,
    cmdline             TEXT,
    cpu_percent         REAL    NOT NULL DEFAULT 0.0,
    memory_percent      REAL    NOT NULL DEFAULT 0.0,
    memory_rss          INTEGER NOT NULL DEFAULT 0,
    num_threads         INTEGER NOT NULL DEFAULT 1,
    process_start_time  TEXT    NOT NULL,
    status              TEXT    NOT NULL
);
"""

_CREATE_RAW_NETWORK_TELEMETRY = """
CREATE TABLE IF NOT EXISTS raw_network_telemetry (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp           TEXT    NOT NULL,
    pid                 INTEGER NOT NULL,
    local_address       TEXT    NOT NULL,
    local_port          INTEGER,
    remote_address      TEXT,
    remote_port         INTEGER,
    status              TEXT    NOT NULL,
    protocol            TEXT    NOT NULL
);
"""

_CREATE_TELEMETRY_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_rpt_timestamp ON raw_process_telemetry(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_rpt_pid       ON raw_process_telemetry(pid);",
    "CREATE INDEX IF NOT EXISTS idx_rnt_timestamp ON raw_network_telemetry(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_rnt_pid       ON raw_network_telemetry(pid);",
]


def init_telemetry_tables(db_path: Path = DB_PATH) -> None:
    """
    Ensure base database tables and raw telemetry extension tables exist.
    Completely non-destructive to existing tables.
    """
    # 1. Ensure existing core schema exists
    init_database(db_path)

    # 2. Add raw telemetry tables
    conn = _get_connection(db_path)
    try:
        with conn:
            conn.execute(_CREATE_RAW_PROCESS_TELEMETRY)
            conn.execute(_CREATE_RAW_NETWORK_TELEMETRY)
            for idx_sql in _CREATE_TELEMETRY_INDEXES:
                conn.execute(idx_sql)
        logger.debug("Telemetry extension tables verified at: %s", db_path)
    finally:
        conn.close()


class TelemetryStorage:
    """
    Handles batched storage of process and network telemetry records.
    """

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        init_telemetry_tables(self.db_path)

    def save_process_telemetry_batch(self, records: List[ProcessTelemetry]) -> int:
        """
        Insert a batch of ProcessTelemetry items into raw_process_telemetry.

        Returns
        -------
        int
            Number of records successfully inserted.
        """
        if not records:
            return 0

        sql = """
            INSERT INTO raw_process_telemetry (
                timestamp, pid, ppid, process_name, username,
                exe, cmdline, cpu_percent, memory_percent,
                memory_rss, num_threads, process_start_time, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        data = [
            (
                r.timestamp,
                r.pid,
                r.ppid,
                r.process_name,
                r.username,
                r.exe,
                r.cmdline,
                r.cpu_percent,
                r.memory_percent,
                r.memory_rss,
                r.num_threads,
                r.process_start_time,
                r.status,
            )
            for r in records
        ]

        conn = _get_connection(self.db_path)
        try:
            with conn:
                conn.executemany(sql, data)
            return len(records)
        except sqlite3.Error as exc:
            logger.error("Failed to insert process telemetry batch: %s", exc)
            raise
        finally:
            conn.close()

    def save_network_telemetry_batch(self, records: List[NetworkTelemetry]) -> int:
        """
        Insert a batch of NetworkTelemetry items into raw_network_telemetry.

        Returns
        -------
        int
            Number of records successfully inserted.
        """
        if not records:
            return 0

        sql = """
            INSERT INTO raw_network_telemetry (
                timestamp, pid, local_address, local_port,
                remote_address, remote_port, status, protocol
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        data = [
            (
                r.timestamp,
                r.pid,
                r.local_address,
                r.local_port,
                r.remote_address,
                r.remote_port,
                r.status,
                r.protocol,
            )
            for r in records
        ]

        conn = _get_connection(self.db_path)
        try:
            with conn:
                conn.executemany(sql, data)
            return len(records)
        except sqlite3.Error as exc:
            logger.error("Failed to insert network telemetry batch: %s", exc)
            raise
        finally:
            conn.close()

    def get_recent_process_telemetry(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve recent raw process telemetry records."""
        sql = "SELECT * FROM raw_process_telemetry ORDER BY id DESC LIMIT ?"
        conn = _get_connection(self.db_path)
        try:
            return [dict(row) for row in conn.execute(sql, (limit,)).fetchall()]
        finally:
            conn.close()

    def get_recent_network_telemetry(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve recent raw network telemetry records."""
        sql = "SELECT * FROM raw_network_telemetry ORDER BY id DESC LIMIT ?"
        conn = _get_connection(self.db_path)
        try:
            return [dict(row) for row in conn.execute(sql, (limit,)).fetchall()]
        finally:
            conn.close()
