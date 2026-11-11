"""
dashboard/database.py
=====================
ECHO — M4: Enforcement, Verification & Monitoring Dashboard
Author : Mayank (M4)

This module is the single source of truth for all SQLite database access in M4.
It uses Python's built-in sqlite3 library — no third-party ORM required.

Design decisions
----------------
* SQLite is chosen because it is file-based, zero-configuration, and ideal for
  a single-host monitoring project that does not need a network database server.
* Foreign keys are ENABLED on every connection so referential integrity is
  enforced at the database level (SQLite disables them by default).
* All timestamps are stored as ISO-8601 strings in UTC so records are portable
  and human-readable without timezone conversion bugs.
* Parameterised queries (the ? placeholder) prevent SQL injection and keep SQL
  statements readable.
* Every connection is always closed in a finally block so file handles are
  never leaked, even if an exception is raised mid-operation.
"""

import sqlite3
import logging
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Module-level logger — callers configure verbosity via logging.basicConfig().
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Path resolution — NO hardcoded absolute paths anywhere in this file.
# ---------------------------------------------------------------------------
# Layout on disk:
#   echo-project/
#       dashboard/
#           database.py     <-- this file
#       data/
#           echo.db         <-- the database
#
# Path(__file__).resolve() gives the absolute path of this script.
# .parent        -> dashboard/
# .parent.parent -> echo-project/  (project root)

_THIS_FILE    = Path(__file__).resolve()
_PROJECT_ROOT = _THIS_FILE.parent.parent
_DATA_DIR     = _PROJECT_ROOT / "data"
DB_PATH       = _DATA_DIR / "echo.db"


# ---------------------------------------------------------------------------
# Internal helpers (private — not imported by other modules)
# ---------------------------------------------------------------------------

def _get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    """
    Open and configure a sqlite3 connection.

    Creates the parent directory if it does not exist so the first
    call to init_database() always succeeds even on a fresh clone.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    # sqlite3.Row lets us access columns by name (e.g. row["pid"]) not just index.
    conn.row_factory = sqlite3.Row
    # Foreign key enforcement must be re-enabled per connection in SQLite.
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def _utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string ending in 'Z'."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _validate_not_empty(value, field_name: str) -> None:
    """Raise ValueError if the value is None or a blank string."""
    if value is None or (isinstance(value, str) and value.strip() == ""):
        raise ValueError(
            f"Required field '{field_name}' must not be empty or None."
        )


# ---------------------------------------------------------------------------
# SQL schema — defined as module-level strings for clarity
# ---------------------------------------------------------------------------

_CREATE_PROCESS_EVENTS = """
CREATE TABLE IF NOT EXISTS process_events (
    event_id            TEXT    PRIMARY KEY,
    timestamp           TEXT    NOT NULL,
    pid                 INTEGER NOT NULL,
    process_name        TEXT    NOT NULL,
    process_start_time  TEXT    NOT NULL,
    cpu_percent         REAL    NOT NULL DEFAULT 0.0,
    memory_percent      REAL    NOT NULL DEFAULT 0.0,
    anomaly_score       REAL,
    risk_level          TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (risk_level IN ('low', 'medium', 'high', 'unknown'))
);
"""

_CREATE_ALERTS = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id    TEXT PRIMARY KEY,
    event_id    TEXT NOT NULL REFERENCES process_events(event_id),
    timestamp   TEXT NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
    reason      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'acknowledged', 'resolved'))
);
"""

_CREATE_RESPONSE_ACTIONS = """
CREATE TABLE IF NOT EXISTS response_actions (
    action_id       TEXT PRIMARY KEY,
    event_id        TEXT NOT NULL REFERENCES process_events(event_id),
    timestamp       TEXT NOT NULL,
    action_type     TEXT NOT NULL
        CHECK (action_type IN (
            'alert', 'investigate', 'simulate_restriction',
            'log_only', 'notify_operator'
        )),
    execution_mode  TEXT NOT NULL CHECK (execution_mode IN ('simulation', 'live')),
    approval_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (approval_status IN ('pending', 'approved', 'rejected')),
    result          TEXT NOT NULL DEFAULT 'pending'
        CHECK (result IN ('pending', 'success', 'failed', 'skipped')),
    error_message   TEXT
);
"""

_CREATE_VERIFICATION_RESULTS = """
CREATE TABLE IF NOT EXISTS verification_results (
    verification_id     TEXT    PRIMARY KEY,
    action_id           TEXT    NOT NULL REFERENCES response_actions(action_id),
    timestamp           TEXT    NOT NULL,
    success             INTEGER NOT NULL CHECK (success IN (0, 1)),
    details             TEXT    NOT NULL,
    collateral_impact   TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (collateral_impact IN ('none', 'detected', 'unknown'))
);
"""

# Index creation is separated from table creation for readability.
_CREATE_INDEXES = [
    # Timestamp indexes — dashboards almost always sort/filter by time.
    "CREATE INDEX IF NOT EXISTS idx_pe_timestamp  ON process_events(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_al_timestamp  ON alerts(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_ra_timestamp  ON response_actions(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_vr_timestamp  ON verification_results(timestamp);",
    # Foreign-key indexes — speed up JOIN operations.
    "CREATE INDEX IF NOT EXISTS idx_al_event_id   ON alerts(event_id);",
    "CREATE INDEX IF NOT EXISTS idx_ra_event_id   ON response_actions(event_id);",
    "CREATE INDEX IF NOT EXISTS idx_vr_action_id  ON verification_results(action_id);",
    # Status/approval indexes — common WHERE clause predicates.
    "CREATE INDEX IF NOT EXISTS idx_al_status     ON alerts(status);",
    "CREATE INDEX IF NOT EXISTS idx_ra_approval   ON response_actions(approval_status);",
]


# ---------------------------------------------------------------------------
# Public API — Initialisation
# ---------------------------------------------------------------------------

def init_database(db_path: Path = DB_PATH) -> None:
    """
    Create all four ECHO tables and their indexes if they do not exist.

    This function is idempotent: running it on an already-initialised
    database is safe and will not drop or alter existing data.

    Parameters
    ----------
    db_path : Path
        Where to create or open the database file.
        Defaults to echo-project/data/echo.db.
    """
    logger.info("Initialising ECHO database at: %s", db_path)
    conn = _get_connection(db_path)
    try:
        with conn:  # context manager: commits on success, rolls back on error
            conn.execute(_CREATE_PROCESS_EVENTS)
            conn.execute(_CREATE_ALERTS)
            conn.execute(_CREATE_RESPONSE_ACTIONS)
            conn.execute(_CREATE_VERIFICATION_RESULTS)
            for idx_sql in _CREATE_INDEXES:
                conn.execute(idx_sql)
        logger.info("Database initialised successfully.")
    except sqlite3.Error as exc:
        logger.error("Failed to initialise database: %s", exc)
        raise  # Always propagate — never silently discard failures
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Public API — Insertion functions
# ---------------------------------------------------------------------------

def insert_process_event(
    event_id: str,
    pid: int,
    process_name: str,
    process_start_time: str,
    cpu_percent: float,
    memory_percent: float,
    risk_level: str = "unknown",
    anomaly_score=None,
    timestamp: str = None,
    db_path: Path = DB_PATH,
) -> None:
    """
    Insert one process observation into process_events.

    Called by M3 (correlation/risk engine) when it forwards a scored event
    to M4 for persistence.

    Parameters
    ----------
    event_id          : Unique string ID (UUID4 recommended, produced by M1/M3).
    pid               : Linux process ID captured at observation time.
    process_name      : Process name, e.g. 'firefox', 'bash', 'python3'.
    process_start_time: ISO-8601 UTC string of when the process was launched.
    cpu_percent       : CPU usage % at observation time (0.0 – 100.0).
    memory_percent    : RSS memory usage % at observation time (0.0 – 100.0).
    risk_level        : M3 risk classification: 'low', 'medium', 'high', or 'unknown'.
    anomaly_score     : Float score from M2 ML model (None if not yet scored).
    timestamp         : UTC observation time; auto-generated if omitted.
    db_path           : Alternate database path — used by unit tests.
    """
    _validate_not_empty(event_id, "event_id")
    _validate_not_empty(process_name, "process_name")

    valid_risk = {"low", "medium", "high", "unknown"}
    if risk_level not in valid_risk:
        raise ValueError(
            f"Invalid risk_level '{risk_level}'. Allowed: {valid_risk}"
        )

    ts = timestamp or _utc_now()

    sql = """
        INSERT INTO process_events
            (event_id, timestamp, pid, process_name, process_start_time,
             cpu_percent, memory_percent, anomaly_score, risk_level)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    params = (
        event_id, ts, int(pid), process_name, process_start_time,
        float(cpu_percent), float(memory_percent), anomaly_score, risk_level,
    )

    conn = _get_connection(db_path)
    try:
        with conn:
            conn.execute(sql, params)
        logger.debug("Inserted process_event %s (%s)", event_id, process_name)
    except sqlite3.IntegrityError as exc:
        logger.error("Integrity error — process_event %s: %s", event_id, exc)
        raise
    except sqlite3.Error as exc:
        logger.error("DB error — process_event %s: %s", event_id, exc)
        raise
    finally:
        conn.close()


def insert_alert(
    alert_id: str,
    event_id: str,
    severity: str,
    reason: str,
    status: str = "open",
    timestamp: str = None,
    db_path: Path = DB_PATH,
) -> None:
    """
    Insert a security alert that is linked to a process event.

    Parameters
    ----------
    alert_id  : Unique alert ID (UUID4 recommended).
    event_id  : FK — must reference an existing process_events.event_id.
    severity  : 'low', 'medium', or 'high'.
    reason    : Plain-English description of why the alert was raised.
    status    : Initial lifecycle state: 'open' (default), 'acknowledged', 'resolved'.
    timestamp : UTC string; auto-generated if omitted.
    db_path   : Alternate path for tests.
    """
    _validate_not_empty(alert_id, "alert_id")
    _validate_not_empty(event_id, "event_id")
    _validate_not_empty(reason, "reason")

    if severity not in {"low", "medium", "high"}:
        raise ValueError(f"Invalid severity '{severity}'.")
    if status not in {"open", "acknowledged", "resolved"}:
        raise ValueError(f"Invalid status '{status}'.")

    ts = timestamp or _utc_now()

    sql = """
        INSERT INTO alerts (alert_id, event_id, timestamp, severity, reason, status)
        VALUES (?, ?, ?, ?, ?, ?)
    """
    conn = _get_connection(db_path)
    try:
        with conn:
            conn.execute(sql, (alert_id, event_id, ts, severity, reason, status))
        logger.debug("Inserted alert %s (severity=%s)", alert_id, severity)
    except sqlite3.IntegrityError as exc:
        logger.error("Integrity error — alert %s: %s", alert_id, exc)
        raise
    except sqlite3.Error as exc:
        logger.error("DB error — alert %s: %s", alert_id, exc)
        raise
    finally:
        conn.close()


def insert_response_action(
    action_id: str,
    event_id: str,
    action_type: str,
    execution_mode: str,
    approval_status: str = "pending",
    result: str = "pending",
    error_message: str = None,
    timestamp: str = None,
    db_path: Path = DB_PATH,
) -> None:
    """
    Record a response action associated with a process event.

    IMPORTANT: This function only writes a record to the database.
    It does NOT execute any OS-level action. All enforcement logic will be
    added in a later phase after project approval.

    Parameters
    ----------
    action_id       : Unique ID for this action record.
    event_id        : FK — must reference process_events.event_id.
    action_type     : 'alert', 'investigate', 'simulate_restriction',
                      'log_only', or 'notify_operator'.
    execution_mode  : 'simulation' (Phase 1 only) or 'live' (Phase 2+).
    approval_status : 'pending', 'approved', or 'rejected'.
    result          : 'pending', 'success', 'failed', or 'skipped'.
    error_message   : Error text if result == 'failed'; else None.
    timestamp       : UTC string; auto-generated if omitted.
    db_path         : Alternate path for tests.
    """
    _validate_not_empty(action_id, "action_id")
    _validate_not_empty(event_id, "event_id")

    valid_types = {
        "alert", "investigate", "simulate_restriction", "log_only", "notify_operator"
    }
    if action_type not in valid_types:
        raise ValueError(f"Invalid action_type '{action_type}'.")
    if execution_mode not in {"simulation", "live"}:
        raise ValueError(f"Invalid execution_mode '{execution_mode}'.")
    if approval_status not in {"pending", "approved", "rejected"}:
        raise ValueError(f"Invalid approval_status '{approval_status}'.")
    if result not in {"pending", "success", "failed", "skipped"}:
        raise ValueError(f"Invalid result '{result}'.")

    ts = timestamp or _utc_now()

    sql = """
        INSERT INTO response_actions
            (action_id, event_id, timestamp, action_type, execution_mode,
             approval_status, result, error_message)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """
    params = (
        action_id, event_id, ts, action_type, execution_mode,
        approval_status, result, error_message,
    )

    conn = _get_connection(db_path)
    try:
        with conn:
            conn.execute(sql, params)
        logger.debug("Inserted response_action %s (type=%s)", action_id, action_type)
    except sqlite3.IntegrityError as exc:
        logger.error("Integrity error — response_action %s: %s", action_id, exc)
        raise
    except sqlite3.Error as exc:
        logger.error("DB error — response_action %s: %s", action_id, exc)
        raise
    finally:
        conn.close()


def insert_verification_result(
    verification_id: str,
    action_id: str,
    success: bool,
    details: str,
    collateral_impact: str = "unknown",
    timestamp: str = None,
    db_path: Path = DB_PATH,
) -> None:
    """
    Record the outcome of verifying a response action.

    Parameters
    ----------
    verification_id   : Unique ID.
    action_id         : FK — must reference response_actions.action_id.
    success           : True if post-action verification passed.
    details           : Human-readable verification summary.
    collateral_impact : 'none', 'detected', or 'unknown'.
    timestamp         : UTC string; auto-generated if omitted.
    db_path           : Alternate path for tests.
    """
    _validate_not_empty(verification_id, "verification_id")
    _validate_not_empty(action_id, "action_id")
    _validate_not_empty(details, "details")

    if collateral_impact not in {"none", "detected", "unknown"}:
        raise ValueError(f"Invalid collateral_impact '{collateral_impact}'.")

    ts = timestamp or _utc_now()
    success_int = 1 if success else 0

    sql = """
        INSERT INTO verification_results
            (verification_id, action_id, timestamp, success, details, collateral_impact)
        VALUES (?, ?, ?, ?, ?, ?)
    """
    params = (verification_id, action_id, ts, success_int, details, collateral_impact)

    conn = _get_connection(db_path)
    try:
        with conn:
            conn.execute(sql, params)
        logger.debug(
            "Inserted verification_result %s (success=%s)", verification_id, success
        )
    except sqlite3.IntegrityError as exc:
        logger.error("Integrity error — verification_result %s: %s", verification_id, exc)
        raise
    except sqlite3.Error as exc:
        logger.error("DB error — verification_result %s: %s", verification_id, exc)
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Public API — Retrieval functions
# ---------------------------------------------------------------------------

def get_recent_process_events(limit: int = 50, db_path: Path = DB_PATH) -> list:
    """
    Return the most recent process events, newest first.

    Parameters
    ----------
    limit   : Maximum rows to return (default 50).
    db_path : Alternate path for tests.

    Returns
    -------
    list of dict — each dict contains all process_events columns.
    """
    if limit < 1:
        raise ValueError("limit must be >= 1.")
    sql = "SELECT * FROM process_events ORDER BY timestamp DESC LIMIT ?"
    conn = _get_connection(db_path)
    try:
        return [dict(row) for row in conn.execute(sql, (limit,)).fetchall()]
    except sqlite3.Error as exc:
        logger.error("Error retrieving process events: %s", exc)
        raise
    finally:
        conn.close()


def get_active_alerts(db_path: Path = DB_PATH) -> list:
    """
    Return all alerts with status == 'open', enriched with process metadata.

    Returns
    -------
    list of dict — alert columns plus process_name, pid, risk_level.
    """
    sql = """
        SELECT
            a.alert_id, a.event_id, a.timestamp, a.severity, a.reason, a.status,
            pe.process_name, pe.pid, pe.risk_level
        FROM alerts a
        JOIN process_events pe ON a.event_id = pe.event_id
        WHERE a.status = 'open'
        ORDER BY a.timestamp DESC
    """
    conn = _get_connection(db_path)
    try:
        return [dict(row) for row in conn.execute(sql).fetchall()]
    except sqlite3.Error as exc:
        logger.error("Error retrieving active alerts: %s", exc)
        raise
    finally:
        conn.close()


def get_response_history(limit: int = 50, db_path: Path = DB_PATH) -> list:
    """
    Return the most recent response actions enriched with process metadata.

    Parameters
    ----------
    limit   : Maximum rows to return.
    db_path : Alternate path for tests.

    Returns
    -------
    list of dict
    """
    if limit < 1:
        raise ValueError("limit must be >= 1.")
    sql = """
        SELECT
            ra.action_id, ra.event_id, ra.timestamp, ra.action_type,
            ra.execution_mode, ra.approval_status, ra.result, ra.error_message,
            pe.process_name, pe.pid, pe.risk_level
        FROM response_actions ra
        JOIN process_events pe ON ra.event_id = pe.event_id
        ORDER BY ra.timestamp DESC
        LIMIT ?
    """
    conn = _get_connection(db_path)
    try:
        return [dict(row) for row in conn.execute(sql, (limit,)).fetchall()]
    except sqlite3.Error as exc:
        logger.error("Error retrieving response history: %s", exc)
        raise
    finally:
        conn.close()


def get_verification_history(limit: int = 50, db_path: Path = DB_PATH) -> list:
    """
    Return the most recent verification results enriched with action metadata.

    Parameters
    ----------
    limit   : Maximum rows to return.
    db_path : Alternate path for tests.

    Returns
    -------
    list of dict
    """
    if limit < 1:
        raise ValueError("limit must be >= 1.")
    sql = """
        SELECT
            vr.verification_id, vr.action_id, vr.timestamp, vr.success,
            vr.details, vr.collateral_impact,
            ra.action_type, ra.execution_mode, ra.result AS action_result
        FROM verification_results vr
        JOIN response_actions ra ON vr.action_id = ra.action_id
        ORDER BY vr.timestamp DESC
        LIMIT ?
    """
    conn = _get_connection(db_path)
    try:
        return [dict(row) for row in conn.execute(sql, (limit,)).fetchall()]
    except sqlite3.Error as exc:
        logger.error("Error retrieving verification history: %s", exc)
        raise
    finally:
        conn.close()
