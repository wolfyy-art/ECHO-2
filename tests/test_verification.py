"""
tests/test_verification.py
==========================
Unit tests for ECHO M4 Closed-Loop Verification Subsystem.
Tests post-action validation, collateral damage detection, and DB persistence.
"""

import sys
import unittest
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dashboard.database import (
    init_database,
    insert_process_event,
    insert_response_action,
    get_verification_history,
)
from verification.verifier import ClosedLoopVerifier


class TestClosedLoopVerification(unittest.TestCase):
    """Test verification engine checks."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.tmp_dir) / "test_echo.db"
        init_database(self.db_path)
        self.verifier = ClosedLoopVerifier(db_path=self.db_path)

        # Insert process event & action
        insert_process_event(
            event_id="evt-verif-1",
            pid=2048,
            process_name="rogue_agent",
            process_start_time="2026-01-01T00:00:00Z",
            cpu_percent=75.0,
            memory_percent=20.0,
            risk_level="high",
            db_path=self.db_path,
        )
        insert_response_action(
            action_id="act-verif-success",
            event_id="evt-verif-1",
            action_type="simulate_restriction",
            execution_mode="simulation",
            approval_status="approved",
            result="success",
            db_path=self.db_path,
        )
        insert_response_action(
            action_id="act-verif-failed",
            event_id="evt-verif-1",
            action_type="simulate_restriction",
            execution_mode="simulation",
            approval_status="approved",
            result="failed",
            error_message="Simulation engine error",
            db_path=self.db_path,
        )

    def test_verify_successful_response_no_collateral(self):
        res = self.verifier.verify_response(
            action_id="act-verif-success",
            simulated_metrics={"collateral_impact_detected": False},
        )
        self.assertTrue(res["success"])
        self.assertEqual(res["collateral_impact"], "none")

        history = get_verification_history(db_path=self.db_path)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["success"], 1)

    def test_verify_collateral_damage_detected(self):
        res = self.verifier.verify_response(
            action_id="act-verif-success",
            simulated_metrics={
                "collateral_impact_detected": True,
                "unrelated_processes_impacted": 2,
            },
        )
        self.assertFalse(res["success"])
        self.assertEqual(res["collateral_impact"], "detected")
        self.assertIn("collateral impact", res["details"])

    def test_verify_failed_action_fails_verification(self):
        res = self.verifier.verify_response(action_id="act-verif-failed")
        self.assertFalse(res["success"])
        self.assertIn("Simulation engine error", res["details"])


if __name__ == "__main__":
    unittest.main()
