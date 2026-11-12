"""
tests/test_response.py
======================
Unit tests for ECHO M4 Response Subsystem.

Tests safety guards, allowlists, simulation mode, approval gates, and DB
persistence.

Approval contract being verified
---------------------------------
1. Default approval_status is "pending", NOT "approved".
2. Restrictive actions (simulate_restriction, investigate, notify_operator)
   require explicit approval_status == "approved" to execute.
3. "pending" restrictive actions must be recorded as "skipped", not executed.
4. "rejected" actions must be recorded as "skipped", not executed.
5. Protected processes must be blocked regardless of approval status.
6. Harmless actions (alert, log_only) may proceed without prior approval.
7. All outcomes are persisted to the database with the correct result code.
"""

import sys
import unittest
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dashboard.database import init_database, insert_process_event, get_response_history
from response.safety import SafetyChecker, is_protected_process, APPROVAL_REQUIRED_ACTIONS
from response.engine import ResponseEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_event(db_path: Path, event_id: str = "evt-target-1",
                pid: int = 19840, process_name: str = "suspicious_miner") -> None:
    insert_process_event(
        event_id=event_id,
        pid=pid,
        process_name=process_name,
        process_start_time="2026-01-01T00:00:00Z",
        cpu_percent=90.0,
        memory_percent=15.0,
        risk_level="high",
        db_path=db_path,
    )


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

    # --- New: approval gate tests on SafetyChecker ---

    def test_pending_approval_blocks_simulate_restriction(self):
        """simulate_restriction with pending approval must be blocked."""
        allowed, reason = SafetyChecker.validate_action(
            pid=12345, process_name="miner",
            action_type="simulate_restriction",
            execution_mode="simulation", approval_status="pending",
        )
        self.assertFalse(allowed)
        self.assertIn("pending", reason)
        self.assertIn("requires explicit operator approval", reason)

    def test_pending_approval_blocks_investigate(self):
        """investigate with pending approval must be blocked."""
        allowed, reason = SafetyChecker.validate_action(
            pid=12345, process_name="miner",
            action_type="investigate",
            execution_mode="simulation", approval_status="pending",
        )
        self.assertFalse(allowed)
        self.assertIn("pending", reason)

    def test_pending_approval_blocks_notify_operator(self):
        """notify_operator with pending approval must be blocked."""
        allowed, reason = SafetyChecker.validate_action(
            pid=12345, process_name="miner",
            action_type="notify_operator",
            execution_mode="simulation", approval_status="pending",
        )
        self.assertFalse(allowed)
        self.assertIn("pending", reason)

    def test_rejected_approval_blocks_simulate_restriction(self):
        """simulate_restriction with rejected approval must be blocked."""
        allowed, reason = SafetyChecker.validate_action(
            pid=12345, process_name="miner",
            action_type="simulate_restriction",
            execution_mode="simulation", approval_status="rejected",
        )
        self.assertFalse(allowed)
        self.assertIn("rejected", reason)

    def test_approved_simulate_restriction_passes_safety(self):
        """simulate_restriction with explicit approval must pass safety check."""
        allowed, reason = SafetyChecker.validate_action(
            pid=12345, process_name="miner",
            action_type="simulate_restriction",
            execution_mode="simulation", approval_status="approved",
        )
        self.assertTrue(allowed)
        self.assertIsNone(reason)

    def test_alert_proceeds_without_approval(self):
        """alert action must proceed regardless of approval_status."""
        for status in ("pending", "approved"):
            allowed, reason = SafetyChecker.validate_action(
                pid=12345, process_name="miner",
                action_type="alert",
                execution_mode="simulation", approval_status=status,
            )
            self.assertTrue(allowed, f"alert blocked unexpectedly with status={status}: {reason}")

    def test_log_only_proceeds_without_approval(self):
        """log_only action must proceed regardless of approval_status."""
        for status in ("pending", "approved"):
            allowed, reason = SafetyChecker.validate_action(
                pid=12345, process_name="miner",
                action_type="log_only",
                execution_mode="simulation", approval_status=status,
            )
            self.assertTrue(allowed, f"log_only blocked unexpectedly with status={status}: {reason}")

    def test_approval_required_actions_set_is_correct(self):
        """The approval-required action set must be exactly as specified."""
        self.assertEqual(
            set(APPROVAL_REQUIRED_ACTIONS),
            {"simulate_restriction", "investigate", "notify_operator"},
        )

    def test_protected_process_always_blocked_regardless_of_approval(self):
        """Protected processes must be blocked even when approval_status is 'approved'."""
        for status in ("pending", "approved", "rejected"):
            allowed, reason = SafetyChecker.validate_action(
                pid=1, process_name="systemd",
                action_type="simulate_restriction",
                execution_mode="simulation", approval_status=status,
            )
            self.assertFalse(allowed, f"Protected process passed with status={status}")
            self.assertIn("Safety Violation", reason)


class TestResponseEngine(unittest.TestCase):
    """Test response engine execution and database recording."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.tmp_dir) / "test_echo.db"
        init_database(self.db_path)
        self.engine = ResponseEngine(db_path=self.db_path)
        _seed_event(self.db_path)

    # --- Pre-existing tests (must remain passing) ---

    def test_execute_simulation_restriction(self):
        """Explicitly approved restriction in simulation mode must succeed."""
        rec = self.engine.execute_response(
            event_id="evt-target-1",
            action_type="simulate_restriction",
            execution_mode="simulation",
            approval_status="approved",
        )
        self.assertEqual(rec["result"], "success")
        self.assertEqual(rec["execution_mode"], "simulation")

        history = get_response_history(db_path=self.db_path)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["action_type"], "simulate_restriction")
        self.assertEqual(history[0]["result"], "success")

    def test_execute_blocked_on_protected_process(self):
        """Protected process must be blocked even with approved status."""
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
        """Explicitly rejected action must be recorded as skipped."""
        rec = self.engine.execute_response(
            event_id="evt-target-1",
            action_type="simulate_restriction",
            execution_mode="simulation",
            approval_status="rejected",
        )
        self.assertEqual(rec["result"], "skipped")

    # --- New: approval default and pending gate tests ---

    def test_default_approval_is_pending(self):
        """Calling execute_response with no approval_status must default to pending."""
        rec = self.engine.execute_response(
            event_id="evt-target-1",
            action_type="simulate_restriction",
            execution_mode="simulation",
            # approval_status intentionally omitted to test the default
        )
        self.assertEqual(rec["approval_status"], "pending")
        self.assertEqual(rec["result"], "skipped",
                         "Default pending must NOT execute the restrictive action")

    def test_pending_restrictive_action_is_skipped_not_failed(self):
        """A pending restrictive action must be 'skipped', not 'failed'."""
        rec = self.engine.execute_response(
            event_id="evt-target-1",
            action_type="simulate_restriction",
            execution_mode="simulation",
            approval_status="pending",
        )
        self.assertEqual(rec["result"], "skipped")
        self.assertEqual(rec["approval_status"], "pending")
        history = get_response_history(db_path=self.db_path)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["result"], "skipped")
        self.assertEqual(history[0]["approval_status"], "pending")

    def test_pending_investigate_is_skipped(self):
        """investigate with pending approval must be skipped."""
        rec = self.engine.execute_response(
            event_id="evt-target-1",
            action_type="investigate",
            execution_mode="simulation",
            approval_status="pending",
        )
        self.assertEqual(rec["result"], "skipped")

    def test_pending_notify_operator_is_skipped(self):
        """notify_operator with pending approval must be skipped."""
        rec = self.engine.execute_response(
            event_id="evt-target-1",
            action_type="notify_operator",
            execution_mode="simulation",
            approval_status="pending",
        )
        self.assertEqual(rec["result"], "skipped")

    def test_alert_executes_without_approval(self):
        """alert must succeed even with pending approval_status."""
        rec = self.engine.execute_response(
            event_id="evt-target-1",
            action_type="alert",
            execution_mode="simulation",
            approval_status="pending",
        )
        self.assertEqual(rec["result"], "success")

    def test_log_only_executes_without_approval(self):
        """log_only must succeed even with pending approval_status."""
        rec = self.engine.execute_response(
            event_id="evt-target-1",
            action_type="log_only",
            execution_mode="simulation",
            approval_status="pending",
        )
        self.assertEqual(rec["result"], "success")

    def test_approved_investigate_executes(self):
        """investigate with explicit approval must execute successfully."""
        rec = self.engine.execute_response(
            event_id="evt-target-1",
            action_type="investigate",
            execution_mode="simulation",
            approval_status="approved",
        )
        self.assertEqual(rec["result"], "success")

    def test_rejected_investigate_is_skipped(self):
        """investigate with rejected approval must be skipped."""
        rec = self.engine.execute_response(
            event_id="evt-target-1",
            action_type="investigate",
            execution_mode="simulation",
            approval_status="rejected",
        )
        self.assertEqual(rec["result"], "skipped")

    def test_all_approval_outcomes_persisted_to_database(self):
        """Every response action, regardless of outcome, must be persisted."""
        self.engine.execute_response(
            event_id="evt-target-1", action_type="simulate_restriction",
            execution_mode="simulation", approval_status="pending",
        )
        self.engine.execute_response(
            event_id="evt-target-1", action_type="simulate_restriction",
            execution_mode="simulation", approval_status="rejected",
        )
        self.engine.execute_response(
            event_id="evt-target-1", action_type="simulate_restriction",
            execution_mode="simulation", approval_status="approved",
        )
        history = get_response_history(limit=10, db_path=self.db_path)
        self.assertEqual(len(history), 3)
        results = {r["approval_status"]: r["result"] for r in history}
        self.assertEqual(results["pending"], "skipped")
        self.assertEqual(results["rejected"], "skipped")
        self.assertEqual(results["approved"], "success")

    def test_simulation_mode_is_default(self):
        """execution_mode must default to 'simulation'."""
        rec = self.engine.execute_response(
            event_id="evt-target-1",
            action_type="log_only",
            # execution_mode intentionally omitted
        )
        self.assertEqual(rec["execution_mode"], "simulation")

    def test_pending_protected_process_records_failed(self):
        """A protected process must still record 'failed' even with pending approval;
        safety violations are a harder block than the approval gate."""
        insert_process_event(
            event_id="evt-systemd-2", pid=1, process_name="systemd",
            process_start_time="2026-01-01T00:00:00Z",
            cpu_percent=0.5, memory_percent=1.0, db_path=self.db_path,
        )
        rec = self.engine.execute_response(
            event_id="evt-systemd-2",
            action_type="simulate_restriction",
            execution_mode="simulation",
            approval_status="pending",
        )
        # Safety check runs before approval gate → "Safety Violation" in reason
        # → result is "failed", not "skipped"
        self.assertIn("Safety Violation", rec["error_message"])
        self.assertEqual(rec["result"], "failed")


if __name__ == "__main__":
    unittest.main()
