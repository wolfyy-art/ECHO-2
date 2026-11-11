"""
tests/test_database.py
======================
ECHO — M4: Automated Database Tests
Author : Mayank (M4)

All tests use a temporary SQLite file (via tempfile) so the real
data/echo.db is never read from or written to during testing.

Run:
    cd echo-project
    python -m pytest tests/test_database.py -v
    # or
    python -m unittest tests/test_database -v
"""

import sys
import unittest
import sqlite3
import tempfile
import os
from pathlib import Path
from datetime import datetime, timezone

# Ensure the project root is on sys.path so we can import dashboard.database.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dashboard.database import (
    init_database,
    insert_process_event,
    insert_alert,
    insert_response_action,
    insert_verification_result,
    get_recent_process_events,
    get_active_alerts,
    get_response_history,
    get_verification_history,
)


# ---------------------------------------------------------------------------
# Helper — create a fresh, isolated temporary database for each test
# ---------------------------------------------------------------------------

def _make_temp_db() -> Path:
    """Create a temporary directory and return a Path to a db inside it."""
    tmp_dir = tempfile.mkdtemp()
    return Path(tmp_dir) / "test_echo.db"


# ---------------------------------------------------------------------------
# Shared fixture data
# ---------------------------------------------------------------------------

SAMPLE_EVENT = dict(
    event_id           = "test-evt-001",
    pid                = 1234,
    process_name       = "python3",
    process_start_time = "2026-01-01T00:00:00.000000Z",
    cpu_percent        = 10.5,
    memory_percent     = 5.2,
    risk_level         = "medium",
    anomaly_score      = 0.65,
    timestamp          = "2026-01-01T00:01:00.000000Z",
)

SAMPLE_ALERT = dict(
    alert_id  = "test-alert-001",
    event_id  = "test-evt-001",
    severity  = "medium",
    reason    = "Anomaly score exceeded threshold.",
    status    = "open",
    timestamp = "2026-01-01T00:01:05.000000Z",
)

SAMPLE_ACTION = dict(
    action_id       = "test-action-001",
    event_id        = "test-evt-001",
    action_type     = "simulate_restriction",
    execution_mode  = "simulation",
    approval_status = "pending",
    result          = "pending",
    error_message   = None,
    timestamp       = "2026-01-01T00:01:10.000000Z",
)

SAMPLE_VERIFICATION = dict(
    verification_id   = "test-verify-001",
    action_id         = "test-action-001",
    success           = True,
    details           = "Post-action check passed — simulation mode only.",
    collateral_impact = "none",
    timestamp         = "2026-01-01T00:01:15.000000Z",
)


# ===========================================================================
# Test Class 1 — Schema initialisation
# ===========================================================================

class TestInitDatabase(unittest.TestCase):
    """Tests that init_database() creates the correct schema."""

    def setUp(self):
        self.db_path = _make_temp_db()

    def test_init_creates_database_file(self):
        """init_database() should create the .db file on disk."""
        init_database(self.db_path)
        self.assertTrue(self.db_path.exists(), "Database file was not created.")

    def test_all_four_tables_exist(self):
        """All four tables must be present after initialisation."""
        init_database(self.db_path)
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
        )
        tables = {row[0] for row in cursor.fetchall()}
        conn.close()
        expected = {"process_events", "alerts", "response_actions", "verification_results"}
        self.assertEqual(expected, tables)

    def test_init_is_idempotent(self):
        """Calling init_database() twice must not raise any error."""
        init_database(self.db_path)
        try:
            init_database(self.db_path)
        except Exception as exc:
            self.fail(f"Second call to init_database() raised: {exc}")

    def test_foreign_keys_enabled(self):
        """PRAGMA foreign_keys should return 1 after _get_connection()."""
        init_database(self.db_path)
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("PRAGMA foreign_keys = ON;")
        result = conn.execute("PRAGMA foreign_keys;").fetchone()[0]
        conn.close()
        self.assertEqual(result, 1)


# ===========================================================================
# Test Class 2 — Insertion functions
# ===========================================================================

class TestInsertions(unittest.TestCase):
    """Tests that all insert_*() functions write correct data."""

    def setUp(self):
        self.db_path = _make_temp_db()
        init_database(self.db_path)

    def _raw_conn(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def test_insert_process_event(self):
        """insert_process_event() must persist all fields correctly."""
        insert_process_event(**{**SAMPLE_EVENT, "db_path": self.db_path})
        conn = self._raw_conn()
        row = dict(
            conn.execute(
                "SELECT * FROM process_events WHERE event_id = ?",
                ("test-evt-001",),
            ).fetchone()
        )
        conn.close()
        self.assertEqual(row["pid"], 1234)
        self.assertEqual(row["process_name"], "python3")
        self.assertAlmostEqual(row["cpu_percent"], 10.5, places=3)
        self.assertEqual(row["risk_level"], "medium")
        self.assertAlmostEqual(row["anomaly_score"], 0.65, places=3)

    def test_insert_alert(self):
        """insert_alert() must persist all fields correctly."""
        insert_process_event(**{**SAMPLE_EVENT, "db_path": self.db_path})
        insert_alert(**{**SAMPLE_ALERT, "db_path": self.db_path})
        conn = self._raw_conn()
        row = dict(
            conn.execute(
                "SELECT * FROM alerts WHERE alert_id = ?",
                ("test-alert-001",),
            ).fetchone()
        )
        conn.close()
        self.assertEqual(row["severity"], "medium")
        self.assertEqual(row["status"], "open")
        self.assertEqual(row["event_id"], "test-evt-001")

    def test_insert_response_action(self):
        """insert_response_action() must persist all fields correctly."""
        insert_process_event(**{**SAMPLE_EVENT, "db_path": self.db_path})
        insert_response_action(**{**SAMPLE_ACTION, "db_path": self.db_path})
        conn = self._raw_conn()
        row = dict(
            conn.execute(
                "SELECT * FROM response_actions WHERE action_id = ?",
                ("test-action-001",),
            ).fetchone()
        )
        conn.close()
        self.assertEqual(row["action_type"], "simulate_restriction")
        self.assertEqual(row["execution_mode"], "simulation")
        self.assertEqual(row["result"], "pending")

    def test_insert_verification_result(self):
        """insert_verification_result() must persist all fields correctly."""
        insert_process_event(**{**SAMPLE_EVENT, "db_path": self.db_path})
        insert_response_action(**{**SAMPLE_ACTION, "db_path": self.db_path})
        insert_verification_result(**{**SAMPLE_VERIFICATION, "db_path": self.db_path})
        conn = self._raw_conn()
        row = dict(
            conn.execute(
                "SELECT * FROM verification_results WHERE verification_id = ?",
                ("test-verify-001",),
            ).fetchone()
        )
        conn.close()
        self.assertEqual(row["success"], 1)           # stored as integer
        self.assertEqual(row["collateral_impact"], "none")

    def test_anomaly_score_nullable(self):
        """anomaly_score may be None when M2 has not yet scored the event."""
        event_no_score = {**SAMPLE_EVENT, "event_id": "test-evt-noscore",
                          "anomaly_score": None, "db_path": self.db_path}
        insert_process_event(**event_no_score)
        conn = self._raw_conn()
        row = dict(
            conn.execute(
                "SELECT anomaly_score FROM process_events WHERE event_id = ?",
                ("test-evt-noscore",),
            ).fetchone()
        )
        conn.close()
        self.assertIsNone(row["anomaly_score"])


# ===========================================================================
# Test Class 3 — Foreign key enforcement
# ===========================================================================

class TestForeignKeyEnforcement(unittest.TestCase):
    """Tests that the database rejects orphan records."""

    def setUp(self):
        self.db_path = _make_temp_db()
        init_database(self.db_path)

    def test_alert_requires_valid_event_id(self):
        """Inserting an alert without a parent event must raise IntegrityError."""
        with self.assertRaises(sqlite3.IntegrityError):
            insert_alert(
                alert_id  = "orphan-alert",
                event_id  = "nonexistent-event",
                severity  = "low",
                reason    = "This should fail due to missing parent.",
                db_path   = self.db_path,
            )

    def test_response_action_requires_valid_event_id(self):
        """Inserting a response_action without a parent event must raise IntegrityError."""
        with self.assertRaises(sqlite3.IntegrityError):
            insert_response_action(
                action_id      = "orphan-action",
                event_id       = "nonexistent-event",
                action_type    = "log_only",
                execution_mode = "simulation",
                db_path        = self.db_path,
            )

    def test_verification_requires_valid_action_id(self):
        """Inserting a verification_result without a parent action must raise IntegrityError."""
        insert_process_event(**{**SAMPLE_EVENT, "db_path": self.db_path})
        with self.assertRaises(sqlite3.IntegrityError):
            insert_verification_result(
                verification_id   = "orphan-verify",
                action_id         = "nonexistent-action",
                success           = True,
                details           = "Should fail.",
                db_path           = self.db_path,
            )


# ===========================================================================
# Test Class 4 — Input validation
# ===========================================================================

class TestInputValidation(unittest.TestCase):
    """Tests that invalid inputs raise ValueError before touching the DB."""

    def setUp(self):
        self.db_path = _make_temp_db()
        init_database(self.db_path)

    def test_empty_event_id_raises(self):
        with self.assertRaises(ValueError):
            insert_process_event(
                event_id="", pid=1, process_name="test",
                process_start_time="2026-01-01T00:00:00Z",
                cpu_percent=0.0, memory_percent=0.0, db_path=self.db_path,
            )

    def test_none_event_id_raises(self):
        with self.assertRaises(ValueError):
            insert_process_event(
                event_id=None, pid=1, process_name="test",
                process_start_time="2026-01-01T00:00:00Z",
                cpu_percent=0.0, memory_percent=0.0, db_path=self.db_path,
            )

    def test_invalid_risk_level_raises(self):
        with self.assertRaises(ValueError):
            insert_process_event(
                event_id="x", pid=1, process_name="test",
                process_start_time="2026-01-01T00:00:00Z",
                cpu_percent=0.0, memory_percent=0.0,
                risk_level="critical",     # not an allowed value
                db_path=self.db_path,
            )

    def test_invalid_severity_raises(self):
        with self.assertRaises(ValueError):
            insert_alert(
                alert_id="x", event_id="y",
                severity="extreme",        # not an allowed value
                reason="test",
                db_path=self.db_path,
            )

    def test_invalid_action_type_raises(self):
        with self.assertRaises(ValueError):
            insert_response_action(
                action_id="x", event_id="y",
                action_type="nuke_server",  # not an allowed value
                execution_mode="simulation",
                db_path=self.db_path,
            )

    def test_invalid_collateral_impact_raises(self):
        with self.assertRaises(ValueError):
            insert_verification_result(
                verification_id="x", action_id="y",
                success=True, details="test",
                collateral_impact="maybe",  # not an allowed value
                db_path=self.db_path,
            )

    def test_negative_limit_raises(self):
        """get_recent_process_events() must reject limit < 1."""
        with self.assertRaises(ValueError):
            get_recent_process_events(limit=0, db_path=self.db_path)


# ===========================================================================
# Test Class 5 — Retrieval functions
# ===========================================================================

class TestRetrievalFunctions(unittest.TestCase):
    """Tests that all get_*() functions return correct data."""

    def setUp(self):
        self.db_path = _make_temp_db()
        init_database(self.db_path)
        # Insert a full chain of related records.
        insert_process_event(**{**SAMPLE_EVENT, "db_path": self.db_path})
        insert_alert(**{**SAMPLE_ALERT, "db_path": self.db_path})
        insert_response_action(**{**SAMPLE_ACTION, "db_path": self.db_path})
        insert_verification_result(**{**SAMPLE_VERIFICATION, "db_path": self.db_path})

    def test_get_recent_process_events_returns_list(self):
        rows = get_recent_process_events(db_path=self.db_path)
        self.assertIsInstance(rows, list)
        self.assertGreater(len(rows), 0)

    def test_get_recent_process_events_correct_data(self):
        rows = get_recent_process_events(db_path=self.db_path)
        self.assertEqual(rows[0]["event_id"], "test-evt-001")
        self.assertEqual(rows[0]["process_name"], "python3")

    def test_get_recent_process_events_limit(self):
        """Only the requested number of rows should be returned."""
        # Insert a second event so limit can be tested meaningfully.
        insert_process_event(
            event_id="test-evt-002", pid=9999, process_name="extra",
            process_start_time="2026-01-01T00:02:00Z",
            cpu_percent=1.0, memory_percent=1.0,
            timestamp="2026-01-01T00:02:30Z",
            db_path=self.db_path,
        )
        rows = get_recent_process_events(limit=1, db_path=self.db_path)
        self.assertEqual(len(rows), 1)

    def test_get_active_alerts_returns_open_only(self):
        """Only open alerts should be returned."""
        rows = get_active_alerts(db_path=self.db_path)
        for row in rows:
            self.assertEqual(row["status"], "open")

    def test_get_active_alerts_includes_process_name(self):
        """Active alert rows must include the joined process_name."""
        rows = get_active_alerts(db_path=self.db_path)
        self.assertIn("process_name", rows[0])
        self.assertEqual(rows[0]["process_name"], "python3")

    def test_get_active_alerts_excludes_resolved(self):
        """Resolved alerts must NOT appear in get_active_alerts()."""
        insert_process_event(
            event_id="test-evt-resolved", pid=5555, process_name="systemd",
            process_start_time="2026-01-01T01:00:00Z",
            cpu_percent=0.0, memory_percent=0.0,
            timestamp="2026-01-01T01:00:01Z",
            db_path=self.db_path,
        )
        insert_alert(
            alert_id="resolved-alert", event_id="test-evt-resolved",
            severity="low", reason="Resolved alert test.",
            status="resolved", timestamp="2026-01-01T01:00:02Z",
            db_path=self.db_path,
        )
        rows = get_active_alerts(db_path=self.db_path)
        alert_ids = [r["alert_id"] for r in rows]
        self.assertNotIn("resolved-alert", alert_ids)

    def test_get_response_history_returns_list(self):
        rows = get_response_history(db_path=self.db_path)
        self.assertIsInstance(rows, list)
        self.assertGreater(len(rows), 0)

    def test_get_response_history_correct_data(self):
        rows = get_response_history(db_path=self.db_path)
        self.assertEqual(rows[0]["action_type"], "simulate_restriction")
        self.assertEqual(rows[0]["execution_mode"], "simulation")

    def test_get_verification_history_returns_list(self):
        rows = get_verification_history(db_path=self.db_path)
        self.assertIsInstance(rows, list)
        self.assertGreater(len(rows), 0)

    def test_get_verification_history_correct_data(self):
        rows = get_verification_history(db_path=self.db_path)
        self.assertEqual(rows[0]["verification_id"], "test-verify-001")
        self.assertEqual(rows[0]["success"], 1)


# ===========================================================================
# Test Class 6 — UTC timestamp storage
# ===========================================================================

class TestUTCTimestamps(unittest.TestCase):
    """Tests that timestamps are stored in UTC and in ISO-8601 format."""

    def setUp(self):
        self.db_path = _make_temp_db()
        init_database(self.db_path)

    def test_auto_timestamp_is_utc_iso8601(self):
        """
        When no timestamp is provided, the auto-generated one must end in 'Z'
        (indicating UTC) and be parseable as ISO-8601.
        """
        insert_process_event(
            event_id="ts-test-001", pid=111, process_name="sleep",
            process_start_time="2026-01-01T00:00:00Z",
            cpu_percent=0.0, memory_percent=0.0,
            db_path=self.db_path,
            # No timestamp supplied — the function must generate one.
        )
        rows = get_recent_process_events(db_path=self.db_path)
        ts = rows[0]["timestamp"]

        self.assertTrue(ts.endswith("Z"), f"Timestamp '{ts}' does not end with 'Z'.")

        # Make sure datetime can parse it.
        try:
            dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            self.fail(f"Timestamp '{ts}' is not valid ISO-8601.")

    def test_explicit_timestamp_stored_correctly(self):
        """An explicitly provided timestamp must be stored as-is."""
        explicit_ts = "2026-06-15T12:30:00.000000Z"
        insert_process_event(
            event_id="ts-test-002", pid=222, process_name="nginx",
            process_start_time="2026-06-15T10:00:00Z",
            cpu_percent=0.5, memory_percent=0.2,
            timestamp=explicit_ts,
            db_path=self.db_path,
        )
        conn = sqlite3.connect(str(self.db_path))
        row = conn.execute(
            "SELECT timestamp FROM process_events WHERE event_id = ?",
            ("ts-test-002",),
        ).fetchone()
        conn.close()
        self.assertEqual(row[0], explicit_ts)


# ===========================================================================
# Test Class 7 — Duplicate primary key rejection
# ===========================================================================

class TestDuplicateRejection(unittest.TestCase):
    """Tests that inserting a duplicate primary key raises IntegrityError."""

    def setUp(self):
        self.db_path = _make_temp_db()
        init_database(self.db_path)

    def test_duplicate_event_id_raises(self):
        insert_process_event(**{**SAMPLE_EVENT, "db_path": self.db_path})
        with self.assertRaises(sqlite3.IntegrityError):
            insert_process_event(**{**SAMPLE_EVENT, "db_path": self.db_path})

    def test_duplicate_alert_id_raises(self):
        insert_process_event(**{**SAMPLE_EVENT, "db_path": self.db_path})
        insert_alert(**{**SAMPLE_ALERT, "db_path": self.db_path})
        with self.assertRaises(sqlite3.IntegrityError):
            insert_alert(**{**SAMPLE_ALERT, "db_path": self.db_path})


if __name__ == "__main__":
    unittest.main(verbosity=2)
