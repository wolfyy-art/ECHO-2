"""
tests/test_policy_engine.py
===========================
Unit tests for ECHO M3 PolicyRules, ActionMapper, and PolicyEngine.
"""

import unittest
from pathlib import Path
import tempfile
from correlation.models import (
    ProcessTelemetryInput,
    DetectionSignalInput,
    RiskScoreResult,
    CorrelatedSignal,
    PolicyDecision,
)
from policy.rules import PolicyRules, PolicyRulesConfig
from policy.action_mapper import ActionMapper, VALID_M4_ACTIONS
from policy.engine import PolicyEngine
from dashboard.database import init_database


class TestPolicyEngine(unittest.TestCase):
    """Test suite for security rules, action mapping, and protected process safety."""

    def setUp(self):
        self.rules = PolicyRules()
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.tmp_dir) / "test_echo.db"
        init_database(self.db_path)
        self.policy_engine = PolicyEngine(rules=self.rules, db_path=self.db_path)

    def _make_correlated(
        self,
        pid: int = 4000,
        name: str = "custom_tool",
        is_repeated: bool = False,
        parent_suspicious: bool = False,
    ) -> CorrelatedSignal:
        telem = ProcessTelemetryInput(
            pid=pid,
            process_name=name,
            process_start_time="2026-11-12T10:00:00Z",
            username="vboxuser",
        )
        return CorrelatedSignal(
            correlation_id="corr-test-01",
            telemetry=telem,
            detection=DetectionSignalInput(),
            process_type_identity=f"type::vboxuser::{name}",
            process_instance_identity=f"inst::vboxuser::{name}::{pid}::start",
            is_repeated_anomaly=is_repeated,
            prior_anomaly_count=3 if is_repeated else 0,
            parent_is_suspicious=parent_suspicious,
        )

    def test_low_risk_policy(self):
        """Low risk must recommend log_only with no approval required."""
        corr = self._make_correlated(pid=4001, name="firefox")
        risk = RiskScoreResult(risk_score=15.0, risk_level="low", is_provisional=False)
        decision = self.rules.evaluate(corr, risk)

        self.assertEqual(decision.recommended_action, "log_only")
        self.assertFalse(decision.requires_approval)
        self.assertEqual(decision.risk_level, "low")
        self.assertFalse(decision.is_protected)

    def test_medium_risk_policy(self):
        """Medium risk must recommend investigate without restrictive action."""
        corr = self._make_correlated(pid=4002, name="bash")
        risk = RiskScoreResult(risk_score=45.0, risk_level="medium", is_provisional=False)
        decision = self.rules.evaluate(corr, risk)

        self.assertEqual(decision.recommended_action, "investigate")
        self.assertFalse(decision.requires_approval)
        self.assertEqual(decision.risk_level, "medium")

    def test_high_risk_policy(self):
        """High risk non-protected process recommends containment and REQUIRES approval."""
        corr = self._make_correlated(pid=4003, name="crypto_miner_sim")
        risk = RiskScoreResult(risk_score=85.0, risk_level="high", is_provisional=False)
        decision = self.rules.evaluate(corr, risk)

        self.assertEqual(decision.recommended_action, "simulate_restriction")
        self.assertTrue(decision.requires_approval)
        self.assertEqual(decision.risk_level, "high")

    def test_protected_process_pid_1_never_restricted(self):
        """System PID 1 must NEVER be restricted even if high risk."""
        corr = self._make_correlated(pid=1, name="systemd")
        risk = RiskScoreResult(risk_score=95.0, risk_level="high", is_provisional=False)
        decision = self.rules.evaluate(corr, risk)

        self.assertTrue(decision.is_protected)
        self.assertNotEqual(decision.recommended_action, "simulate_restriction")
        self.assertEqual(decision.recommended_action, "alert")
        self.assertFalse(decision.requires_approval) # Alerts don't restrict host
        self.assertIn("prohibited", decision.reason.lower())

    def test_protected_process_allowlist_python_never_restricted(self):
        """Allowlisted names (e.g. python, sshd) must NEVER receive restrictive actions."""
        corr = self._make_correlated(pid=8888, name="python3")
        risk = RiskScoreResult(risk_score=92.0, risk_level="high", is_provisional=False)
        decision = self.rules.evaluate(corr, risk)

        self.assertTrue(decision.is_protected)
        self.assertEqual(decision.recommended_action, "alert")
        self.assertIn("protected system allowlist", decision.reason.lower())

    def test_action_mapper_respects_approval(self):
        """ActionMapper sets approval_status based on policy requirements and operator consent."""
        dec_restrict = PolicyDecision(
            decision_id="dec-1",
            event_id="evt-1",
            pid=9999,
            process_name="threat",
            process_identity="type::vboxuser::threat",
            risk_score=88.0,
            risk_level="high",
            recommended_action="simulate_restriction",
            requires_approval=True,
            is_protected=False,
            reason="High risk",
        )
        # Without operator approval -> status is 'pending'
        args_unapproved = ActionMapper.map_to_response_args(dec_restrict, operator_approved=False)
        self.assertEqual(args_unapproved["approval_status"], "pending")
        self.assertEqual(args_unapproved["action_type"], "simulate_restriction")
        self.assertEqual(args_unapproved["execution_mode"], "simulation")

        # With operator approval -> status is 'approved'
        args_approved = ActionMapper.map_to_response_args(dec_restrict, operator_approved=True)
        self.assertEqual(args_approved["approval_status"], "approved")


if __name__ == "__main__":
    unittest.main()

