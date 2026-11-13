"""
correlation/storage.py
======================
ECHO — M3: Correlation Records & Persistence Subsystem.

Provides non-destructive storage of M3 risk evaluations and policy decisions.
Features:
- Dedicated correlation_records table preserving relational integrity to process_events.
- Stores multi-signal breakdowns (ML score, behavioural score, resource score).
- Does not alter or break existing M4 database tables.
- Idempotent schema initialization.
"""

import sqlite3
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from dashboard.database import (
    DB_PATH,
    _get_connection,
    _utc_now,
    insert_process_event,
)
from correlation.models import (
    CorrelatedSignal,
    RiskScoreResult,
    PolicyDecision,
)

logger = logging.getLogger(__name__)

_CREATE_CORRELATION_RECORDS = """
CREATE TABLE IF NOT EXISTS correlation_records (
    record_id           TEXT PRIMARY KEY,
    event_id            TEXT NOT NULL REFERENCES process_events(event_id),
    timestamp           TEXT NOT NULL,
    pid                 INTEGER NOT NULL,
    process_name        TEXT NOT NULL,
    process_identity    TEXT NOT NULL,
    overall_risk_score  REAL NOT NULL,
    risk_level          TEXT NOT NULL CHECK (risk_level IN ('low', 'medium', 'high', 'unknown')),
    ml_score            REAL,
    behavioural_score   REAL,
    resource_score      REAL,
    recommended_action  TEXT NOT NULL,
    requires_approval   INTEGER NOT NULL CHECK (requires_approval IN (0, 1)),
    is_protected        INTEGER NOT NULL CHECK (is_protected IN (0, 1)),
    is_provisional      INTEGER NOT NULL CHECK (is_provisional IN (0, 1)),
    explanation         TEXT NOT NULL,
    decision_reason     TEXT NOT NULL
);
"""

_CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_cr_event_id   ON correlation_records(event_id);",
    "CREATE INDEX IF NOT EXISTS idx_cr_timestamp  ON correlation_records(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_cr_risk_level ON correlation_records(risk_level);",
]


class CorrelationStorage:
    """
    Manages persistence of M3 correlated events and risk scores.
    """

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = Path(db_path)
        self.init_storage()

    def init_storage(self) -> None:
        """Create correlation_records table and indexes if not exists."""
        conn = _get_connection(self.db_path)
        try:
            with conn:
                conn.execute(_CREATE_CORRELATION_RECORDS)
                for idx_sql in _CREATE_INDEXES:
                    conn.execute(idx_sql)
        except sqlite3.Error as exc:
            logger.error("Failed to initialize correlation_records table: %s", exc)
            raise
        finally:
            conn.close()

    def save_record(
        self,
        correlated: CorrelatedSignal,
        risk: RiskScoreResult,
        decision: PolicyDecision,
        ensure_parent_event: bool = True,
    ) -> str:
        """
        Persist a correlated risk evaluation and policy decision.

        Parameters
        ----------
        correlated : CorrelatedSignal
        risk : RiskScoreResult
        decision : PolicyDecision
        ensure_parent_event : bool
            If True, automatically inserts a record into process_events if not already present.

        Returns
        -------
        str
            The record_id of the inserted record.
        """
        record_id = f"cr-{correlated.correlation_id[-12:]}"
        event_id = correlated.telemetry.event_id
        ts = correlated.timestamp or _utc_now()

        # Ensure parent event exists in process_events to satisfy FK constraint
        if ensure_parent_event:
            conn = _get_connection(self.db_path)
            try:
                row = conn.execute("SELECT 1 FROM process_events WHERE event_id = ?", (event_id,)).fetchone()
                if not row:
                    # Ingest into process_events using M4 API
                    telem = correlated.telemetry
                    insert_process_event(
                        event_id=event_id,
                        pid=telem.pid,
                        process_name=telem.process_name,
                        process_start_time=telem.process_start_time or ts,
                        cpu_percent=telem.cpu_percent,
                        memory_percent=telem.memory_percent,
                        risk_level=risk.risk_level,
                        anomaly_score=risk.risk_score / 100.0, # M4 expects normalized score
                        timestamp=ts,
                        db_path=self.db_path,
                    )
            finally:
                conn.close()

        sql = """
            INSERT INTO correlation_records (
                record_id, event_id, timestamp, pid, process_name, process_identity,
                overall_risk_score, risk_level, ml_score, behavioural_score, resource_score,
                recommended_action, requires_approval, is_protected, is_provisional,
                explanation, decision_reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            record_id,
            event_id,
            ts,
            correlated.telemetry.pid,
            correlated.telemetry.process_name,
            correlated.process_type_identity,
            risk.risk_score,
            risk.risk_level,
            risk.ml_score_normalized,
            risk.behavioural_score_normalized,
            risk.resource_score_normalized,
            decision.recommended_action,
            1 if decision.requires_approval else 0,
            1 if decision.is_protected else 0,
            1 if risk.is_provisional else 0,
            risk.explanation,
            decision.reason,
        )

        conn = _get_connection(self.db_path)
        try:
            with conn:
                conn.execute(sql, params)
            logger.debug("Saved correlation record %s for event %s", record_id, event_id)
            return record_id
        except sqlite3.Error as exc:
            logger.error("DB error saving correlation record: %s", exc)
            raise
        finally:
            conn.close()

    def get_records(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent correlation records."""
        sql = "SELECT * FROM correlation_records ORDER BY timestamp DESC LIMIT ?"
        conn = _get_connection(self.db_path)
        try:
            return [dict(row) for row in conn.execute(sql, (limit,)).fetchall()]
        finally:
            conn.close()

    def get_by_event_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve correlation record by foreign key event_id."""
        sql = "SELECT * FROM correlation_records WHERE event_id = ?"
        conn = _get_connection(self.db_path)
        try:
            row = conn.execute(sql, (event_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

