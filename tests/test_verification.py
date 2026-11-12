"""
tests/test_verification.py
==========================
Unit tests for ECHO M4 Closed-Loop Verification Subsystem.

Tests post-action validation, collateral damage detection, and DB persistence.

Verification contract being verified
--------------------------------------
1. Missing post-action telemetry → INCONCLUSIVE (success=False,
   collateral_impact="unknown").  Missing evidence is never success.
2. Failed/skipped action → collateral_impact="unknown", not "none".
3. Simulated evidence is labelled "[SIMULATED EVIDENCE]" in details.
4. The three outcomes (success / failure / inconclusive) are distinguishable
   via the "verification_outcome" key in the return dict.
5. Successful verification requires explicit telemetry showing no collateral.
6. Collateral detection sets success=False, collateral_impact="detected".
7. All outcomes are persisted to the database.
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
from verification.verifier import (
    ClosedLoopVerifier,
    OUTCOME_SUCCESS,
    OUTCOME_FAILURE,
    OUTCOME_INCONCLUSIVE,
)


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

    # -----------------------------------------------------------------------
    # Pre-existing tests — must remain passing
    # -----------------------------------------------------------------------

    def test_verify_successful_response_no_collateral(self):
        """Explicit telemetry confirming no collateral → success."""
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
        """Explicit telemetry reporting collateral → failure."""
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
        """Failed action must produce success=False with error message in details."""
        res = self.verifier.verify_response(action_id="act-verif-failed")
        self.assertFalse(res["success"])
        self.assertIn("Simulation engine error", res["details"])

    # -----------------------------------------------------------------------
    # New tests: missing telemetry → inconclusive
    # -----------------------------------------------------------------------

    def test_missing_metrics_is_inconclusive_not_success(self):
        """Calling verify_response with no simulated_metrics must be INCONCLUSIVE."""
        res = self.verifier.verify_response(action_id="act-verif-success")
        self.assertFalse(res["success"],
                         "Missing metrics must not produce success=True")
        self.assertEqual(res["collateral_impact"], "unknown",
                         "Missing collateral evidence must be recorded as 'unknown'")
        self.assertEqual(res["verification_outcome"], OUTCOME_INCONCLUSIVE)

    def test_missing_metrics_details_mentions_no_telemetry(self):
        """Inconclusive details must explain that no telemetry was provided."""
        res = self.verifier.verify_response(action_id="act-verif-success")
        self.assertIn("no post-action telemetry", res["details"].lower())

    def test_missing_metrics_is_persisted_as_inconclusive(self):
        """Inconclusive outcome must be persisted with success=0, impact=unknown."""
        self.verifier.verify_response(action_id="act-verif-success")
        history = get_verification_history(db_path=self.db_path)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["success"], 0)
        self.assertEqual(history[0]["collateral_impact"], "unknown")

    # -----------------------------------------------------------------------
    # New tests: failed/skipped action → collateral_impact must be "unknown"
    # -----------------------------------------------------------------------

    def test_failed_action_collateral_is_unknown_not_none(self):
        """A failed action has no collateral evidence — must be 'unknown', not 'none'."""
        res = self.verifier.verify_response(action_id="act-verif-failed")
        self.assertEqual(res["collateral_impact"], "unknown",
                         "Failed action must record collateral_impact='unknown', not 'none'")

    def test_skipped_action_collateral_is_unknown(self):
        """A skipped (pending/rejected) action must also record collateral='unknown'."""
        insert_response_action(
            action_id="act-verif-skipped",
            event_id="evt-verif-1",
            action_type="simulate_restriction",
            execution_mode="simulation",
            approval_status="pending",
            result="skipped",
            db_path=self.db_path,
        )
        res = self.verifier.verify_response(action_id="act-verif-skipped")
        self.assertFalse(res["success"])
        self.assertEqual(res["collateral_impact"], "unknown")
        self.assertEqual(res["verification_outcome"], OUTCOME_FAILURE)

    def test_failed_action_outcome_is_failure(self):
        """Failed action must carry verification_outcome='failure'."""
        res = self.verifier.verify_response(action_id="act-verif-failed")
        self.assertEqual(res["verification_outcome"], OUTCOME_FAILURE)

    # -----------------------------------------------------------------------
    # New tests: simulation label in details
    # -----------------------------------------------------------------------

    def test_simulated_evidence_is_labelled(self):
        """Details must contain the simulation label when execution_mode is 'simulation'."""
        res = self.verifier.verify_response(
            action_id="act-verif-success",
            simulated_metrics={"collateral_impact_detected": False},
        )
        self.assertIn("[SIMULATED EVIDENCE]", res["details"])

    def test_simulated_success_details_mentions_simulated_telemetry(self):
        """Successful simulation verification details must note it is not real host state."""
        res = self.verifier.verify_response(
            action_id="act-verif-success",
            simulated_metrics={"collateral_impact_detected": False},
        )
        self.assertIn("simulated", res["details"].lower())

    # -----------------------------------------------------------------------
    # New tests: outcome constants and distinguishability
    # -----------------------------------------------------------------------

    def test_outcome_constants_are_distinct(self):
        """The three outcome constants must be distinct strings."""
        outcomes = {OUTCOME_SUCCESS, OUTCOME_FAILURE, OUTCOME_INCONCLUSIVE}
        self.assertEqual(len(outcomes), 3,
                         "success, failure, and inconclusive must be distinct values")

    def test_success_outcome_returned_on_verified_success(self):
        """Successful verification must carry verification_outcome='success'."""
        res = self.verifier.verify_response(
            action_id="act-verif-success",
            simulated_metrics={"collateral_impact_detected": False},
        )
        self.assertEqual(res["verification_outcome"], OUTCOME_SUCCESS)

    def test_failure_outcome_on_collateral_detection(self):
        """Collateral detection must produce verification_outcome='failure'."""
        res = self.verifier.verify_response(
            action_id="act-verif-success",
            simulated_metrics={"collateral_impact_detected": True,
                               "unrelated_processes_impacted": 1},
        )
        self.assertEqual(res["verification_outcome"], OUTCOME_FAILURE)

    def test_inconclusive_outcome_on_missing_metrics(self):
        """Missing metrics must produce verification_outcome='inconclusive'."""
        res = self.verifier.verify_response(action_id="act-verif-success")
        self.assertEqual(res["verification_outcome"], OUTCOME_INCONCLUSIVE)

    # -----------------------------------------------------------------------
    # New tests: all outcomes persisted correctly
    # -----------------------------------------------------------------------

    def test_all_three_outcomes_persisted(self):
        """All three outcomes must be distinct and persistable."""
        # 1. Inconclusive (no metrics)
        self.verifier.verify_response(
            action_id="act-verif-success",
            verification_id="vrf-inconclusive",
        )
        # 2. Success (explicit no-collateral metrics)
        self.verifier.verify_response(
            action_id="act-verif-success",
            simulated_metrics={"collateral_impact_detected": False},
            verification_id="vrf-success",
        )
        # 3. Failure (action itself failed — uses act-verif-failed)
        self.verifier.verify_response(
            action_id="act-verif-failed",
            verification_id="vrf-failure",
        )
        history = get_verification_history(limit=10, db_path=self.db_path)
        self.assertEqual(len(history), 3)

        by_id = {r["verification_id"]: r for r in history}
        # Inconclusive: success=0, impact=unknown
        self.assertEqual(by_id["vrf-inconclusive"]["success"], 0)
        self.assertEqual(by_id["vrf-inconclusive"]["collateral_impact"], "unknown")
        # Success: success=1, impact=none
        self.assertEqual(by_id["vrf-success"]["success"], 1)
        self.assertEqual(by_id["vrf-success"]["collateral_impact"], "none")
        # Failure: success=0, impact=unknown (action never ran)
        self.assertEqual(by_id["vrf-failure"]["success"], 0)
        self.assertEqual(by_id["vrf-failure"]["collateral_impact"], "unknown")


if __name__ == "__main__":
    unittest.main()
