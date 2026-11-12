"""
tests/test_m2_m3_integration.py
================================
ECHO M2 -> M3 Integration and ML Validation Test Suite
Author: Rishit (M3)

Verifies:
1. Strict schema validation of the 13 approved ML features via M2ModelAdapter:
   - Missing features rejection
   - Null, NaN, and Infinite feature rejection
   - Strict column ordering matching models/metadata.json
2. Real Isolation Forest inference standardisation [0.0, 100.0] and metadata fidelity.
3. End-to-end evaluation of the three canonical host workloads from run_echo.py:
   - Process A (nginx): Low traffic web client -> Low Risk, Log Only
   - Process B (rsync_backup): Heavy backup -> Zero False Alarm, Low Risk, Log Only
   - Process C (worker_daemon): Compromised miner -> High Risk, Contained in Simulation Mode
4. Closed-loop policy dispatch and response execution with M4 contracts.
"""

import math
import tempfile
import unittest
from pathlib import Path
import numpy as np
import pandas as pd

from dashboard.database import init_database
from detection.isolation_forest import ProcessIsolationForest, APPROVED_FEATURE_COLUMNS
from correlation.adapters import M2ModelAdapter
from correlation.models import ProcessTelemetryInput, DetectionSignalInput
from correlation.risk_engine import RiskEngine, RiskEngineConfig
from correlation.signal_correlator import SignalCorrelator
from policy.engine import PolicyEngine
from policy.rules import PolicyRules
from response.engine import ResponseEngine
from verification.verifier import ClosedLoopVerifier

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_MODEL_PATH = _PROJECT_ROOT / "models" / "isolation_forest.joblib"


class TestM2ModelAdapterValidation(unittest.TestCase):
    """Test feature validation and error handling in M2ModelAdapter."""

    def setUp(self):
        self.valid_record = {
            "pid": 1010,
            "ppid": 1,
            "process_name": "nginx",
            "username": "www-data",
            "cpu_mean": 2.1,
            "cpu_max": 2.8,
            "cpu_std": 0.15,
            "memory_mean": 0.75,
            "memory_max": 0.80,
            "memory_rss_mean": 32000000,
            "num_threads_mean": 4.0,
            "num_threads_max": 4,
            "open_sockets_count": 5,
            "distinct_remote_ips": 3,
            "sample_count": 5,
            "cpu_mem_ratio": 2.8,
            "socket_thread_ratio": 1.25,
            "exe_path": "/usr/sbin/nginx",
            "parent_name": "systemd",
        }
        self.model = ProcessIsolationForest.load(_MODEL_PATH)

    def test_missing_features_raises_value_error(self):
        """Omitting any of the 13 approved features must raise ValueError."""
        record = self.valid_record.copy()
        del record["cpu_mean"]
        with self.assertRaises(ValueError) as ctx:
            M2ModelAdapter.validate_and_extract_features(record)
        self.assertIn("cpu_mean", str(ctx.exception))

    def test_null_feature_raises_value_error(self):
        """None/null value in any of the 13 features must raise ValueError."""
        record = self.valid_record.copy()
        record["memory_rss_mean"] = None
        with self.assertRaises(ValueError) as ctx:
            M2ModelAdapter.validate_and_extract_features(record)
        self.assertIn("memory_rss_mean", str(ctx.exception))
        self.assertIn("null", str(ctx.exception))

    def test_nan_and_inf_features_raise_value_error(self):
        """NaN or Infinite feature values must raise ValueError."""
        record_nan = self.valid_record.copy()
        record_nan["cpu_mem_ratio"] = float("nan")
        with self.assertRaises(ValueError) as ctx_nan:
            M2ModelAdapter.validate_and_extract_features(record_nan)
        self.assertIn("NaN or Infinite", str(ctx_nan.exception))

        record_inf = self.valid_record.copy()
        record_inf["socket_thread_ratio"] = float("inf")
        with self.assertRaises(ValueError) as ctx_inf:
            M2ModelAdapter.validate_and_extract_features(record_inf)
        self.assertIn("NaN or Infinite", str(ctx_inf.exception))

    def test_feature_ordering_matches_approved_columns(self):
        """Extracted DataFrame must strictly preserve the 13 approved features in exact order."""
        df_row = M2ModelAdapter.validate_and_extract_features(self.valid_record)
        self.assertEqual(list(df_row.columns), APPROVED_FEATURE_COLUMNS)
        self.assertEqual(len(df_row), 1)

    def test_unfitted_model_raises_runtime_error(self):
        """Passing an unfitted model to from_m2_inference must raise RuntimeError."""
        unfitted = ProcessIsolationForest()
        with self.assertRaises(RuntimeError) as ctx:
            M2ModelAdapter.from_m2_inference(self.valid_record, unfitted)
        self.assertIn("not fitted", str(ctx.exception))

    def test_score_standardisation_and_metadata_fidelity(self):
        """Verify real inference standardises scores into [0.0, 100.0] and preserves metadata."""
        telemetry, detection = M2ModelAdapter.from_m2_inference(
            self.valid_record,
            self.model,
            event_id="evt-m2-test-01",
            timestamp="2026-11-12T20:00:00Z",
        )
        self.assertEqual(telemetry.event_id, "evt-m2-test-01")
        self.assertEqual(telemetry.process_name, "nginx")
        self.assertEqual(telemetry.exe_path, "/usr/sbin/nginx")
        self.assertEqual(telemetry.parent_name, "systemd")

        # Check standardisation bounds
        self.assertGreaterEqual(detection.ml_anomaly_score, 0.0)
        self.assertLessEqual(detection.ml_anomaly_score, 100.0)
        self.assertFalse(detection.is_simulated)
        self.assertIn("raw_unit_score", detection.model_metadata)
        self.assertIn("score_offset", detection.model_metadata)
        self.assertFalse(detection.model_metadata["is_simulated"])


class TestThreeWorkloadScenariosEndToEnd(unittest.TestCase):
    """
    End-to-End M2 -> M3 -> M4 integration testing on the 3 canonical processes:
    - Process A (nginx): Web client
    - Process B (rsync_backup): Heavy backup
    - Process C (worker_daemon): Hidden miner
    """

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = Path(self.temp_db.name)
        init_database(self.db_path)

        self.model = ProcessIsolationForest.load(_MODEL_PATH)
        self.correlator = SignalCorrelator()
        self.risk_engine = RiskEngine()
        self.policy_engine = PolicyEngine(db_path=self.db_path)
        self.verifier = ClosedLoopVerifier(db_path=self.db_path)

    def tearDown(self):
        try:
            self.temp_db.close()
            if self.db_path.exists():
                self.db_path.unlink()
        except Exception:
            pass

    def test_process_a_nginx_normal_web_client(self):
        """
        Process A (nginx):
        - Normal web client traffic
        - ML Score < 50.0 (Normal)
        - Context Q Score = 0.0 (Clean binary path & parent)
        - Composite Risk < 30.0 (Low)
        - Policy: log_only, no approval needed
        """
        nginx_record = {
            "pid": 1010,
            "ppid": 1,
            "process_name": "nginx",
            "username": "www-data",
            "cpu_mean": 2.1,
            "cpu_max": 2.8,
            "cpu_std": 0.15,
            "memory_mean": 0.75,
            "memory_max": 0.80,
            "memory_rss_mean": 32000000,
            "num_threads_mean": 4.0,
            "num_threads_max": 4,
            "open_sockets_count": 5,
            "distinct_remote_ips": 3,
            "sample_count": 5,
            "cpu_mem_ratio": 2.8,
            "socket_thread_ratio": 1.25,
            "exe_path": "/usr/sbin/nginx",
            "parent_name": "systemd",
        }

        telemetry, detection = M2ModelAdapter.from_m2_inference(
            nginx_record,
            self.model,
            event_id="evt-nginx-001",
            timestamp="2026-11-12T20:00:00Z",
        )
        # Baseline behavioural deviation for normal nginx is minimal
        detection.behavioural_score = 5.0

        # Context scoring Q must be 0.0
        q = self.risk_engine.estimate_resource_anomaly(telemetry)
        self.assertEqual(q, 0.0)

        # Correlate and assess risk
        correlated = self.correlator.correlate(telemetry, detection)
        risk_res = self.risk_engine.calculate_risk(correlated.detection, correlated.telemetry)

        self.assertLess(detection.ml_anomaly_score, 50.0)
        self.assertLess(risk_res.risk_score, 30.0)
        self.assertEqual(risk_res.risk_level, "low")

        # Evaluate policy
        decision = self.policy_engine.evaluate_decision(correlated, risk_res)
        self.assertEqual(decision.recommended_action, "log_only")
        self.assertFalse(decision.requires_approval)

        # Dispatch
        dispatch = self.policy_engine.execute_and_verify(decision)
        self.assertIsNone(dispatch["alert"])
        self.assertEqual(dispatch["response"]["action_type"], "log_only")
        self.assertEqual(dispatch["response"]["result"], "success")
        self.assertEqual(dispatch["response"]["execution_mode"], "simulation")
        self.assertIsNotNone(dispatch["verification"])
        self.assertEqual(dispatch["verification"]["collateral_impact"], "none")

    def test_process_b_rsync_backup_heavy_transfer_no_false_alarm(self):
        """
        Process B (rsync_backup):
        - Heavy data transfer: 18.2% CPU, 24 sockets
        - Matches high-traffic learned baseline (MAD = 0.0)
        - Context Q Score = 0.0 (Standard /usr/bin/rsync binary, systemd parent)
        - Composite Risk < 30.0 (Low)
        - Policy: log_only (Demonstrates zero false positive on legitimate heavy workloads)
        """
        rsync_record = {
            "pid": 1020,
            "ppid": 1,
            "process_name": "rsync_backup",
            "username": "backup",
            "cpu_mean": 18.2,
            "cpu_max": 22.0,
            "cpu_std": 0.80,
            "memory_mean": 2.50,
            "memory_max": 2.70,
            "memory_rss_mean": 105000000,
            "num_threads_mean": 3.0,
            "num_threads_max": 3,
            "open_sockets_count": 24,
            "distinct_remote_ips": 2,
            "sample_count": 5,
            "cpu_mem_ratio": 7.28,
            "socket_thread_ratio": 8.0,
            "exe_path": "/usr/bin/rsync",
            "parent_name": "systemd",
        }

        telemetry, detection = M2ModelAdapter.from_m2_inference(
            rsync_record,
            self.model,
            event_id="evt-rsync-001",
            timestamp="2026-11-12T20:00:00Z",
        )
        # Matches learned backup profile: MAD score is 0.0
        detection.behavioural_score = 0.0

        # Context scoring Q must be 0.0 (no double-counting of CPU or sockets)
        q = self.risk_engine.estimate_resource_anomaly(telemetry)
        self.assertEqual(q, 0.0)

        # Correlate and assess risk
        correlated = self.correlator.correlate(telemetry, detection)
        risk_res = self.risk_engine.calculate_risk(correlated.detection, correlated.telemetry)

        # rsync ML score is around decision boundary (~50.0), MAD is 0, Q is 0
        # 0.40 * ~50 + 0.40 * 0 + 0.20 * 0 ≈ 20.0 (< 30.0)
        self.assertLess(risk_res.risk_score, 30.0)
        self.assertEqual(risk_res.risk_level, "low")

        decision = self.policy_engine.evaluate_decision(correlated, risk_res)
        self.assertEqual(decision.recommended_action, "log_only")
        self.assertFalse(decision.requires_approval)

        dispatch = self.policy_engine.execute_and_verify(decision)
        self.assertIsNone(dispatch["alert"])
        self.assertEqual(dispatch["response"]["action_type"], "log_only")

    def test_process_c_worker_daemon_compromised_miner(self):
        """
        Process C (worker_daemon):
        - Anomalous spike: 96.5% CPU, 68 open sockets, 35 remote IPs
        - Volatile executable path: /tmp/.hidden_miner
        - Spawned from bash interactive shell
        - ML Score > 50.0 (High anomaly)
        - Context Q Score >= 60.0 (Volatile path + extreme socket burst)
        - Behavioural MAD = 100.0 (Severe departure from 0.5% CPU baseline)
        - Composite Risk > 70.0 (High)
        - Policy: simulate_restriction, requires approval True
        - Closed-loop verification confirms successful simulated restriction
        """
        miner_record = {
            "pid": 1030,
            "ppid": 1000,
            "process_name": "worker_daemon",
            "username": "vboxuser",
            "cpu_mean": 96.5,
            "cpu_max": 99.8,
            "cpu_std": 1.20,
            "memory_mean": 6.80,
            "memory_max": 7.20,
            "memory_rss_mean": 285000000,
            "num_threads_mean": 16.0,
            "num_threads_max": 16,
            "open_sockets_count": 68,
            "distinct_remote_ips": 35,
            "sample_count": 5,
            "cpu_mem_ratio": 14.19,
            "socket_thread_ratio": 4.25,
            "exe_path": "/tmp/.hidden_miner",
            "parent_name": "bash",
        }

        telemetry, detection = M2ModelAdapter.from_m2_inference(
            miner_record,
            self.model,
            event_id="evt-miner-001",
            timestamp="2026-11-12T20:00:00Z",
        )
        detection.behavioural_score = 100.0  # Extreme MAD deviation

        # Verify Q Context Rules trigger:
        # /tmp in path (+35.0) and sockets >= 40 (+25.0) -> Q = 60.0
        q = self.risk_engine.estimate_resource_anomaly(telemetry)
        self.assertGreaterEqual(q, 60.0)

        # Correlate
        correlated = self.correlator.correlate(telemetry, detection)
        risk_res = self.risk_engine.calculate_risk(correlated.detection, correlated.telemetry)

        self.assertGreater(detection.ml_anomaly_score, 50.0)
        self.assertGreaterEqual(risk_res.risk_score, 70.0)
        self.assertEqual(risk_res.risk_level, "high")

        # Policy decision
        decision = self.policy_engine.evaluate_decision(correlated, risk_res)
        self.assertEqual(decision.recommended_action, "simulate_restriction")
        self.assertTrue(decision.requires_approval)

        # Dispatch with operator approval
        dispatch = self.policy_engine.execute_and_verify(
            decision,
            operator_approved=True,
            simulated_metrics={
                "post_cpu": 0.0,
                "target_terminated": True,
                "collateral_processes_checked": 2,
                "healthy_services_count": 2,
            },
        )
        self.assertIsNotNone(dispatch["alert"])
        self.assertEqual(dispatch["alert"]["severity"], "high")
        self.assertEqual(dispatch["response"]["action_type"], "simulate_restriction")
        self.assertEqual(dispatch["response"]["result"], "success")
        self.assertEqual(dispatch["response"]["execution_mode"], "simulation")
        self.assertIsNotNone(dispatch["verification"])
        self.assertTrue(dispatch["verification"]["success"])
        self.assertEqual(dispatch["verification"]["collateral_impact"], "none")


if __name__ == "__main__":
    unittest.main()
