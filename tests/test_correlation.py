"""
tests/test_correlation.py
=========================
Unit tests for ECHO Phase 6 & 7: Multi-Signal Correlation and Policy Engine.
"""

import unittest
import tempfile
import sqlite3
import uuid
from pathlib import Path

from dashboard.database import (
    init_database,
    insert_process_event,
    get_active_alerts,
    get_response_history,
)
from correlation.engine import (
    CorrelationEngine,
    CorrelationWeights,
    ContextRuleEngine,
    CorrelatedRiskResult,
)
from correlation.policy import (
    PolicyEngine,
    PolicyDecision,
)
from response.engine import ResponseEngine


class TestCorrelationEngine(unittest.TestCase):
    """Test suite for Phase 6 Correlation Engine."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.tmp_dir) / "test_echo.db"
        init_database(self.db_path)

    def test_correlation_weights_validation(self):
        """Weights must sum to 1.0; invalid weights raise ValueError."""
        # Valid weights
        weights = CorrelationWeights(w_m=0.35, w_a=0.45, w_r=0.20)
        self.assertAlmostEqual(weights.w_m + weights.w_a + weights.w_r, 1.0)

        # Invalid weights
        with self.assertRaises(ValueError):
            CorrelationWeights(w_m=0.5, w_a=0.5, w_r=0.5)

    def test_context_rule_engine_rules(self):
        """Verify individual context rules trigger appropriately."""
        # Rule 1: Writable path
        q, rules = ContextRuleEngine.evaluate("malware", exe_path="/tmp/malware.bin")
        self.assertGreater(q, 0.0)
        self.assertTrue(any("volatile/writable" in r for r in rules))

        # Rule 2: Web server spawning shell
        q2, rules2 = ContextRuleEngine.evaluate("sh", parent_name="nginx")
        self.assertGreater(q2, 0.0)
        self.assertTrue(any("spawned interactive shell" in r for r in rules2))

        # Rule 3: Abnormally high sockets
        q3, rules3 = ContextRuleEngine.evaluate("crawler", open_sockets=55)
        self.assertGreater(q3, 0.0)
        self.assertTrue(any("open sockets" in r for r in rules3))

        # Clean benign process
        q_clean, rules_clean = ContextRuleEngine.evaluate("python", exe_path="/usr/bin/python3")
        self.assertEqual(q_clean, 0.0)
        self.assertEqual(len(rules_clean), 0)

    def test_composite_risk_calculation(self):
        """Test R = w_m*M + w_a*A + w_r*Q produces expected score and categorization."""
        weights = CorrelationWeights(w_m=0.4, w_a=0.4, w_r=0.2)
        engine = CorrelationEngine(db_path=self.db_path, weights=weights)

        # Observation with no baseline or ML model -> tests rule-only contribution
        obs = {
            "process_name": "crypto_miner",
            "pid": 5555,
            "cpu_percent": 95.0,
            "memory_percent": 2.0,
            "open_sockets_count": 50,
        }
        res = engine.correlate_process_event(obs, exe_path="/tmp/crypto_miner")

        self.assertIsInstance(res, CorrelatedRiskResult)
        self.assertTrue(0.0 <= res.composite_risk_R <= 1.0)
        self.assertIn(res.risk_level, ("low", "medium", "high"))
        self.assertGreater(res.rule_score_Q, 0.0)


class TestPolicyEngine(unittest.TestCase):
    """Test suite for Phase 7 Policy Engine."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.tmp_dir) / "test_echo.db"
        init_database(self.db_path)
        self.response_engine = ResponseEngine(db_path=self.db_path)
        self.policy_engine = PolicyEngine(
            db_path=self.db_path,
            response_engine=self.response_engine,
            default_execution_mode="simulation",
        )

    def test_graduated_response_ladder(self):
        """Verify R maps correctly to graduated actions."""
        # Low risk -> log_only
        low_res = CorrelatedRiskResult(
            process_name="nginx", pid=1001, ml_score_M=0.1, mad_score_A=0.1,
            rule_score_Q=0.0, composite_risk_R=0.08, risk_level="low",
            triggered_rules=[], explanation="Normal"
        )
        dec_low = self.policy_engine.evaluate_policy("evt-low", low_res)
        self.assertEqual(dec_low.recommended_action, "log_only")
        self.assertIsNone(dec_low.alert_severity)

        # Medium risk -> investigate
        med_res = CorrelatedRiskResult(
            process_name="worker", pid=1002, ml_score_M=0.4, mad_score_A=0.5,
            rule_score_Q=0.2, composite_risk_R=0.40, risk_level="medium",
            triggered_rules=["Minor deviation"], explanation="Moderate"
        )
        dec_med = self.policy_engine.evaluate_policy("evt-med", med_res)
        self.assertEqual(dec_med.recommended_action, "investigate")
        self.assertEqual(dec_med.alert_severity, "medium")

        # High risk -> simulate_restriction
        high_res = CorrelatedRiskResult(
            process_name="unauthorized_miner", pid=49152, ml_score_M=0.85, mad_score_A=0.9,
            rule_score_Q=0.7, composite_risk_R=0.84, risk_level="high",
            triggered_rules=["Extreme CPU", "Tmp path"], explanation="Critical"
        )
        dec_high = self.policy_engine.evaluate_policy("evt-high", high_res)
        self.assertEqual(dec_high.recommended_action, "simulate_restriction")
        self.assertEqual(dec_high.alert_severity, "high")

    def test_policy_enforces_safety_on_protected_pid(self):
        """PID 1 or system processes must be blocked from restriction."""
        res_systemd = CorrelatedRiskResult(
            process_name="systemd", pid=1, ml_score_M=0.9, mad_score_A=0.9,
            rule_score_Q=0.5, composite_risk_R=0.82, risk_level="high",
            triggered_rules=[], explanation="Spike in systemd"
        )
        dec = self.policy_engine.evaluate_policy("evt-sys", res_systemd)
        self.assertFalse(dec.is_action_permitted)
        self.assertIn("Safety Block", str(dec.rejection_reason))
        self.assertEqual(dec.recommended_action, "log_only")

    def test_dispatch_decision_creates_alerts_and_actions(self):
        """Verify dispatching high-risk decision persists alert and response action."""
        event_id = "evt-test-999"
        insert_process_event(
            event_id=event_id,
            timestamp="2026-11-12T10:00:00.000000Z",
            pid=49152,
            process_name="unauthorized_miner.bin",
            process_start_time="2026-11-12T09:00:00.000000Z",
            cpu_percent=98.5,
            memory_percent=1.2,
            anomaly_score=0.85,
            risk_level="high",
            db_path=self.db_path,
        )

        risk_res = CorrelatedRiskResult(
            process_name="unauthorized_miner.bin", pid=49152, ml_score_M=0.85,
            mad_score_A=0.9, rule_score_Q=0.7, composite_risk_R=0.84,
            risk_level="high", triggered_rules=["Spike"], explanation="Test"
        )

        decision = self.policy_engine.evaluate_policy(event_id, risk_res)
        result = self.policy_engine.dispatch_decision(decision)

        self.assertIsNotNone(result["alert_id"])
        self.assertIsNotNone(result["response_action"])
        self.assertEqual(result["response_action"]["result"], "success")

        # Confirm persisted in DB
        alerts = get_active_alerts(db_path=self.db_path)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_id"], result["alert_id"])

        history = get_response_history(db_path=self.db_path)
        self.assertEqual(len(history), 1)


if __name__ == "__main__":
    unittest.main()

