"""
baseline/storage.py
===================
ECHO — Process Baselines Storage Subsystem.

Manages the persistence, querying, and versioning of learned behavioural
baselines in SQLite (process_baselines table).
"""

import sqlite3
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import pandas as pd

from dashboard.database import DB_PATH, _get_connection

logger = logging.getLogger(__name__)

_CREATE_PROCESS_BASELINES_TABLE = """
CREATE TABLE IF NOT EXISTS process_baselines (
    baseline_id             TEXT    PRIMARY KEY,
    process_identity        TEXT    NOT NULL,
    pid_reference           INTEGER,
    process_name            TEXT    NOT NULL,
    executable_identity     TEXT,
    learning_period_days    REAL    NOT NULL,
    observation_count       INTEGER NOT NULL,
    cpu_median              REAL    NOT NULL DEFAULT 0.0,
    cpu_mean                REAL    NOT NULL DEFAULT 0.0,
    cpu_min                 REAL    NOT NULL DEFAULT 0.0,
    cpu_max                 REAL    NOT NULL DEFAULT 0.0,
    cpu_std                 REAL    NOT NULL DEFAULT 0.0,
    cpu_mad                 REAL    NOT NULL DEFAULT 0.0,
    memory_median           REAL    NOT NULL DEFAULT 0.0,
    memory_mean             REAL    NOT NULL DEFAULT 0.0,
    memory_max              REAL    NOT NULL DEFAULT 0.0,
    memory_mad              REAL    NOT NULL DEFAULT 0.0,
    socket_median           REAL    NOT NULL DEFAULT 0.0,
    socket_max              INTEGER NOT NULL DEFAULT 0,
    socket_mad              REAL    NOT NULL DEFAULT 0.0,
    remote_ip_median        REAL    NOT NULL DEFAULT 0.0,
    remote_ip_mad           REAL    NOT NULL DEFAULT 0.0,
    thread_median           REAL    NOT NULL DEFAULT 1.0,
    thread_max              INTEGER NOT NULL DEFAULT 1,
    thread_mad              REAL    NOT NULL DEFAULT 0.0,
    baseline_start          TEXT    NOT NULL,
    baseline_end            TEXT    NOT NULL,
    model_version           TEXT    NOT NULL DEFAULT '1.0.0',
    baseline_status         TEXT    NOT NULL CHECK (baseline_status IN ('preliminary', 'established', 'stale')),
    created_at              TEXT    NOT NULL,
    updated_at              TEXT    NOT NULL
);
"""

_CREATE_BASELINES_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_pb_proc_name ON process_baselines(process_name);",
    "CREATE INDEX IF NOT EXISTS idx_pb_proc_id   ON process_baselines(process_identity);",
    "CREATE INDEX IF NOT EXISTS idx_pb_status    ON process_baselines(baseline_status);",
]


def init_baselines_table(db_path: Path = DB_PATH) -> None:
    """Create process_baselines table and indexes if not existing."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = _get_connection(db_path)
    try:
        with conn:
            conn.execute(_CREATE_PROCESS_BASELINES_TABLE)
            for idx in _CREATE_BASELINES_INDEXES:
                conn.execute(idx)
        logger.debug("process_baselines table initialized at: %s", db_path)
    finally:
        conn.close()


class BaselineStorage:
    """
    Handles persistence and retrieval of learned process baselines.
    """

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = Path(db_path)
        init_baselines_table(self.db_path)

    def save_baselines(self, baselines: List[Dict[str, Any]]) -> int:
        """
        Insert or replace a collection of learned baseline records.

        Parameters
        ----------
        baselines : List[Dict[str, Any]]
            Baseline records.

        Returns
        -------
        int
            Count of saved records.
        """
        if not baselines:
            return 0

        cols = [
            "baseline_id", "process_identity", "pid_reference", "process_name",
            "executable_identity", "learning_period_days", "observation_count",
            "cpu_median", "cpu_mean", "cpu_min", "cpu_max", "cpu_std", "cpu_mad",
            "memory_median", "memory_mean", "memory_max", "memory_mad",
            "socket_median", "socket_max", "socket_mad",
            "remote_ip_median", "remote_ip_mad",
            "thread_median", "thread_max", "thread_mad",
            "baseline_start", "baseline_end", "model_version",
            "baseline_status", "created_at", "updated_at",
        ]

        placeholders = ", ".join(["?"] * len(cols))
        col_str = ", ".join(cols)
        sql = f"INSERT OR REPLACE INTO process_baselines ({col_str}) VALUES ({placeholders})"

        records = []
        for b in baselines:
            records.append(tuple(b.get(col) for col in cols))

        conn = _get_connection(self.db_path)
        try:
            with conn:
                conn.executemany(sql, records)
            return len(records)
        except sqlite3.Error as exc:
            logger.error("Failed to insert process baselines: %s", exc)
            raise
        finally:
            conn.close()

    def get_active_baseline(
        self,
        process_name: str,
        username: Optional[str] = None,
        process_identity: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Identity-aware lookup for the active baseline of a process.

        Prioritizes:
        1. Exact match on canonical process_identity (type::<user>::<name> or inst::<...>)
        2. Match on (process_name, username)
        3. Match on process_name alone
        Always resolves the most recent model_version (ORDER BY updated_at DESC LIMIT 1).

        Parameters
        ----------
        process_name : str
            Executable process name.
        username : Optional[str]
            Process owner username.
        process_identity : Optional[str]
            Optional canonical process identity string.

        Returns
        -------
        Optional[Dict[str, Any]]
            Latest baseline profile or None.
        """
        conn = _get_connection(self.db_path)
        try:
            # 1. Try exact identity match if provided
            if process_identity:
                sql = "SELECT * FROM process_baselines WHERE process_identity = ? ORDER BY updated_at DESC LIMIT 1"
                row = conn.execute(sql, (process_identity,)).fetchone()
                if row:
                    return dict(row)

            # 2. Try process_name and username match
            if username and username.strip() and username.strip() != "unknown":
                target_type = f"type::{username.strip().lower()}::{process_name.strip()}"
                sql = """
                    SELECT * FROM process_baselines
                    WHERE process_identity = ? OR (process_name = ? AND executable_identity = ?)
                    ORDER BY updated_at DESC LIMIT 1
                """
                row = conn.execute(sql, (target_type, process_name, username)).fetchone()
                if row:
                    return dict(row)

            # 3. Fallback to process_name match
            sql = "SELECT * FROM process_baselines WHERE process_name = ? ORDER BY updated_at DESC LIMIT 1"
            row = conn.execute(sql, (process_name,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def get_baseline_by_process_name(self, process_name: str) -> Optional[Dict[str, Any]]:
        """Retrieve most up-to-date baseline for a given process executable name."""
        return self.get_active_baseline(process_name=process_name)

    def get_baseline_by_identity(self, process_identity: str) -> Optional[Dict[str, Any]]:
        """Retrieve baseline by specific process-instance identity."""
        sql = "SELECT * FROM process_baselines WHERE process_identity = ? ORDER BY updated_at DESC LIMIT 1"
        conn = _get_connection(self.db_path)
        try:
            row = conn.execute(sql, (process_identity,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def get_all_baselines(self) -> List[Dict[str, Any]]:
        """Retrieve all active process baselines."""
        sql = "SELECT * FROM process_baselines ORDER BY process_name ASC"
        conn = _get_connection(self.db_path)
        try:
            return [dict(row) for row in conn.execute(sql).fetchall()]
        finally:
            conn.close()
