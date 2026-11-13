"""
tests/test_m3_integration.py
============================
End-to-end integration tests for ECHO M3 subsystem and M4 integration.
Validates:
1. Demo data adapter ingestion from seed_demo.py and run_demo_pipeline.py.
2. Signal correlation -> Risk calculation -> Policy decision.
3. Response execution via ResponseEngine (simulation mode).
4. Closed-loop verification via ClosedLoopVerifier.
5. Multi-table database persistence (process_events, alerts, response_actions, verification_results, correlation_records).
"""

import unittest
from pathlib import Path
import tempfile

from correlation.models import (
    ProcessTelemetryInput,
    DetectionSignalInput,
    RiskScoreResult,
)
from correlation.signal_correlator import SignalCorrelator
from correlation.risk_engine import RiskEngine
from correlation.process_context import ProcessContextManager
from correlation.adapters import DemoDataAdapter
from correlation.storage import CorrelationStorage
from policy.engine import PolicyEngine
from dashboard.database import (
    init_database,
    get_recent_process_events,
    get_active_alerts,
    get_response_history,
    get_verification_history,
)


class TestM3Integration(unittest.TestCase):
    """End-to-end integration suite for M3 and M4 pipeline."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.tmp_dir) / "test_echo.db"
        # Initialize M4 database
        init_database(self.db_path)
        # Initialize M3 storage
        self.m3_storage = CorrelationStorage(self.db_path)
        # Setup M3 pipeline components
        self.ctx = ProcessContextManager()
        self.correlator = SignalCorrelator(context_manager=self.ctx)
        self.risk_engine = RiskEngine()
        self.policy_engine = PolicyEngine(db_path=self.db_path)

    def test_scenario_normal_process_firefox(self):
        """Scenario 1: Normal process (Firefox) yields low risk and log_only action."""
        raw_demo_event = {
            "event_id": "demo-evt-001",
            "pid": 4521,
            "process_name": "firefox",
            "process_start_time": "2026-11-12T11:00:00Z",
            "cpu_percent": 3.2,
            "memory_percent": 5.8,
            "risk_level": "low",
            "anomaly_score": 0.04,
            "timestamp": "2026-11-12T11:01:00Z",
        }
        telem, det = DemoDataAdapter.from_seed_demo_event(raw_demo_event)
        correlated = self.correlator.correlate(telem, det)
        risk = self.risk_engine.calculate_risk(det, telem)
        decision = self.policy_engine.evaluate_decision(correlated, risk)

        self.assertEqual(risk.risk_level, "low")
        self.assertEqual(decision.recommended_action, "log_only")
        self.assertFalse(decision.requires_approval)

        # Persist and execute
        rec_id = self.m3_storage.save_record(correlated, risk, decision)
        self.assertIsNotNone(rec_id)

        # Dispatch via M4
        result = self.policy_engine.execute_and_verify(
            decision=decision,
            operator_approved=False,
            execution_mode="simulation",
        )
        self.assertEqual(result["response"]["result"], "success")
        self.assertEqual(result["response"]["action_type"], "log_only")

    def test_scenario_suspicious_process(self):
        """Scenario 2: Process with moderate deviations yields medium risk and investigate action."""
        telem = ProcessTelemetryInput(
            pid=7711,
            process_name="suspicious_task",
            cpu_percent=45.0,
            memory_percent=25.0,
            open_sockets_count=2,
            distinct_remote_ips=1,
            num_threads=12,
        )
        det = DetectionSignalInput(
            ml_anomaly_score=50.0,
            behavioural_score=45.0,
            is_simulated=True,
        )
        correlated = self.correlator.correlate(telem, det)
        risk = self.risk_engine.calculate_risk(det, telem)
        decision = self.policy_engine.evaluate_decision(correlated, risk)

        self.assertEqual(risk.risk_level, "medium")
        self.assertEqual(decision.recommended_action, "investigate")
        self.assertFalse(decision.requires_approval)

        # Persist and execute
        self.m3_storage.save_record(correlated, risk, decision)
        result = self.policy_engine.execute_and_verify(
            decision=decision,
            operator_approved=False,
            execution_mode="simulation",
        )
        self.assertEqual(result["response"]["action_type"], "investigate")
        self.assertEqual(result["response"]["result"], "success")

    def test_scenario_high_threat_miner_with_verification(self):
        """Scenario 3: Unauthorized crypto miner triggers alert, simulated restriction, and verification."""
        telem, det = DemoDataAdapter.from_pipeline_event(
            event_id="evt-miner-001",
            pid=49152,
            process_name="[DEMO] unauthorized_miner.bin",
            cpu_percent=94.2,
            memory_percent=18.4,
            anomaly_score=0.92,
            timestamp="2026-11-12T11:30:00Z",
        )
        correlated = self.correlator.correlate(telem, det)
        risk = self.risk_engine.calculate_risk(det, telem)
        decision = self.policy_engine.evaluate_decision(correlated, risk)

        self.assertEqual(risk.risk_level, "high")
        self.assertEqual(decision.recommended_action, "simulate_restriction")
        self.assertTrue(decision.requires_approval)

        # Save record
        self.m3_storage.save_record(correlated, risk, decision)

        # Execute with operator approval and simulated metrics for verification
        pipeline_outcome = self.policy_engine.execute_and_verify(
            decision=decision,
            operator_approved=True,
            execution_mode="simulation",
            simulated_metrics={
                "collateral_impact_detected": False,
                "unrelated_processes_impacted": 0,
            },
            record_alert=True,
        )

        # Assert response executed
        self.assertEqual(pipeline_outcome["response"]["result"], "success")
        self.assertEqual(pipeline_outcome["response"]["action_type"], "simulate_restriction")

        # Assert verification succeeded
        self.assertIsNotNone(pipeline_outcome["verification"])
        self.assertTrue(pipeline_outcome["verification"]["success"])

        # Check database records using explicit keyword arguments
        alerts = get_active_alerts(db_path=self.db_path)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "high")

        responses = get_response_history(limit=50, db_path=self.db_path)
        self.assertEqual(len(responses), 1)
        self.assertEqual(responses[0]["action_type"], "simulate_restriction")

        verifications = get_verification_history(limit=50, db_path=self.db_path)
        self.assertEqual(len(verifications), 1)
        self.assertEqual(verifications[0]["success"], 1)

    def test_scenario_missing_detection_data(self):
        """Scenario 4: Missing ML scores must be handled safely as provisional."""
        telem = ProcessTelemetryInput(
            pid=9876,
            process_name="unscored_daemon",
            cpu_percent=2.0,
            memory_percent=1.0,
        )
        # No ML or behavioural scores provided
        det = DetectionSignalInput(
            ml_anomaly_score=None,
            behavioural_score=None,
            resource_anomaly_score=None,
        )
        correlated = self.correlator.correlate(telem, det)
        risk = self.risk_engine.calculate_risk(det, telem)
        decision = self.policy_engine.evaluate_decision(correlated, risk)

        self.assertTrue(risk.is_provisional)
        self.assertIn("ML anomaly score (M)", risk.missing_signals)
        self.assertIn("Behavioural anomaly score (A)", risk.missing_signals)
        # Policy notes missing signals and logs safely
        self.assertIn("missing signals", decision.reason.lower())
        self.assertEqual(decision.recommended_action, "log_only")


if __name__ == "__main__":
    unittest.main()
