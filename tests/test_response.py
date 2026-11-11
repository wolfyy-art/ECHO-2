"""
tests/test_response.py
======================
Unit tests for ECHO M4 Response Subsystem.
Tests safety guards, allowlists, simulation mode, approval gates, and DB persistence.
"""

import sys
import unittest
import tempfile
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dashboard.database import init_database, insert_process_event, get_response_history
from response.safety import SafetyChecker, is_protected_process
from response.engine import ResponseEngine


class TestResponseSafety(unittest.TestCase):
    """Test safety rules and allowlists."""

    def test_protected_pids(self):
        self.assertTrue(is_protected_process(0, "systemd")[0])
        self.assertTrue(is_protected_process(1, "systemd")[0])

    def test_protected_process_names(self):
        self.assertTrue(is_protected_process(999, "systemd")[0])
        self.assertTrue(is_protected_process(999, "sshd")[0])
        self.assertTrue(is_protected_process(999, "python3")[0])
        self.assertFalse(is_protected_process(999, "crypto_miner")[0])

    def test_safety_checker_blocks_pid_1(self):
        allowed, reason = SafetyChecker.validate_action(
            pid=1,
            process_name="init",
            action_type="simulate_restriction",
            execution_mode="simulation",
            approval_status="approved",
        )
        self.assertFalse(allowed)
        self.assertIn("Safety Violation", reason)

    def test_safety_checker_allows_benign_anomalous_process(self):
        allowed, reason = SafetyChecker.validate_action(
            pid=12345,
            process_name="unauthorized_script.sh",
            action_type="simulate_restriction",
            execution_mode="simulation",
            approval_status="approved",
        )
        self.assertTrue(allowed)
        self.assertIsNone(reason)


class TestResponseEngine(unittest.TestCase):
    """Test response engine execution and database recording."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.tmp_dir) / "test_echo.db"
        init_database(self.db_path)
        self.engine = ResponseEngine(db_path=self.db_path)

        # Seed a test event
        insert_process_event(
            event_id="evt-target-1",
            pid=19840,
            process_name="suspicious_miner",
            process_start_time="2026-01-01T00:00:00Z",
            cpu_percent=90.0,
            memory_percent=15.0,
            risk_level="high",
            db_path=self.db_path,
        )

    def test_execute_simulation_restriction(self):
        rec = self.engine.execute_response(
            event_id="evt-target-1",
            action_type="simulate_restriction",
            execution_mode="simulation",
            approval_status="approved",
        )
        self.assertEqual(rec["result"], "success")
        self.assertEqual(rec["execution_mode"], "simulation")

        # Verify persisted in database
        history = get_response_history(db_path=self.db_path)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["action_type"], "simulate_restriction")
        self.assertEqual(history[0]["result"], "success")

    def test_execute_blocked_on_protected_process(self):
        # Insert a protected systemd event
        insert_process_event(
            event_id="evt-systemd-1",
            pid=1,
            process_name="systemd",
            process_start_time="2026-01-01T00:00:00Z",
            cpu_percent=0.5,
            memory_percent=1.0,
            db_path=self.db_path,
        )
        rec = self.engine.execute_response(
            event_id="evt-systemd-1",
            action_type="simulate_restriction",
            execution_mode="simulation",
            approval_status="approved",
        )
        self.assertEqual(rec["result"], "failed")
        self.assertIn("Safety Violation", rec["error_message"])

    def test_execute_rejected_approval(self):
        rec = self.engine.execute_response(
            event_id="evt-target-1",
            action_type="simulate_restriction",
            execution_mode="simulation",
            approval_status="rejected",
        )
        self.assertEqual(rec["result"], "skipped")


if __name__ == "__main__":
    unittest.main()
