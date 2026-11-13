"""
tests/test_risk_engine.py
=========================
Unit tests for ECHO M3 RiskEngine and RiskEngineConfig.
"""

import math
import unittest
from correlation.models import DetectionSignalInput, ProcessTelemetryInput
from correlation.risk_engine import RiskEngine, RiskEngineConfig


class TestRiskEngineScoring(unittest.TestCase):
    """Test suite for risk calculation, normalization, and weights."""

    def setUp(self):
        self.engine = RiskEngine()

    def test_default_canonical_weights(self):
        """RiskEngineConfig must default to canonical ECHO-2 formula: 40/40/20."""
        self.assertAlmostEqual(self.engine.config.w_ml, 0.40)
        self.assertAlmostEqual(self.engine.config.w_behavioural, 0.40)
        self.assertAlmostEqual(self.engine.config.w_resource, 0.20)

    def test_all_normal_scores(self):
        """All low scores should yield a low risk score and 'low' level."""
        detection = DetectionSignalInput(
            ml_anomaly_score=10.0,
            behavioural_score=15.0,
            resource_anomaly_score=5.0,
        )
        result = self.engine.calculate_risk(detection)
        expected = (0.40 * 10.0) + (0.40 * 15.0) + (0.20 * 5.0) # 4 + 6 + 1 = 11.0
        self.assertAlmostEqual(result.risk_score, expected, places=2)
        self.assertEqual(result.risk_level, "low")
        self.assertFalse(result.is_provisional)

    def test_all_high_scores(self):
        """All high scores should yield a high risk score and 'high' level."""
        detection = DetectionSignalInput(
            ml_anomaly_score=90.0,
            behavioural_score=85.0,
            resource_anomaly_score=80.0,
        )
        result = self.engine.calculate_risk(detection)
        expected = (0.40 * 90.0) + (0.40 * 85.0) + (0.20 * 80.0) # 36 + 34 + 16 = 86.0
        self.assertAlmostEqual(result.risk_score, expected, places=2)
        self.assertEqual(result.risk_level, "high")
        self.assertFalse(result.is_provisional)

    def test_prompt_reference_example(self):
        """
        Verify canonical multi-signal correlation formula:
        ML = 90, Behavioural = 80, Resource/network = 70
        R = (0.40 * 90) + (0.40 * 80) + (0.20 * 70) = 82.0 -> HIGH
        """
        detection = DetectionSignalInput(
            ml_anomaly_score=90.0,
            behavioural_score=80.0,
            resource_anomaly_score=70.0,
        )
        result = self.engine.calculate_risk(detection)
        self.assertEqual(result.risk_score, 82.0)
        self.assertEqual(result.risk_level, "high")
        self.assertIn("R=82.0", result.explanation)

    def test_score_normalization_unit_interval(self):
        """0.0 - 1.0 float scales should be normalized to 0.0 - 100.0."""
        detection = DetectionSignalInput(
            ml_anomaly_score=0.90,
            behavioural_score=0.80,
            resource_anomaly_score=0.70,
        )
        result = self.engine.calculate_risk(detection)
        self.assertEqual(result.risk_score, 82.0)
        self.assertEqual(result.risk_level, "high")
        self.assertEqual(result.ml_score_normalized, 90.0)
        self.assertEqual(result.behavioural_score_normalized, 80.0)
        self.assertEqual(result.resource_score_normalized, 70.0)

    def test_boundary_values(self):
        """Test exact thresholds: 0, 29.9, 30.0, 69.9, 70.0, 100.0."""
        self.assertEqual(self.engine.classify_risk(0.0), "low")
        self.assertEqual(self.engine.classify_risk(29.9), "low")
        self.assertEqual(self.engine.classify_risk(30.0), "medium")
        self.assertEqual(self.engine.classify_risk(69.9), "medium")
        self.assertEqual(self.engine.classify_risk(70.0), "high")
        self.assertEqual(self.engine.classify_risk(100.0), "high")
        self.assertEqual(self.engine.classify_risk(None), "unknown")

    def test_missing_single_signal_provisional_rescale(self):
        """Missing ML score should re-weight available signals without silently zeroing."""
        detection = DetectionSignalInput(
            ml_anomaly_score=None,
            behavioural_score=80.0,
            resource_anomaly_score=60.0,
        )
        result = self.engine.calculate_risk(detection)
        # Weights: behavioural=0.40, resource=0.20 -> total 0.60
        # effective: beh = 0.40/0.60, res = 0.20/0.60
        expected = ((0.40 / 0.60) * 80.0) + ((0.20 / 0.60) * 60.0)
        self.assertAlmostEqual(result.risk_score, round(expected, 2), places=1)
        self.assertTrue(result.is_provisional)
        self.assertIn("ML anomaly score (M)", result.missing_signals)

    def test_all_signals_missing(self):
        """If all signals are None, return 0.0 with 'unknown' risk level."""
        detection = DetectionSignalInput(
            ml_anomaly_score=None,
            behavioural_score=None,
            resource_anomaly_score=None,
        )
        result = self.engine.calculate_risk(detection)
        self.assertEqual(result.risk_score, 0.0)
        self.assertEqual(result.risk_level, "unknown")
        self.assertTrue(result.is_provisional)
        self.assertEqual(len(result.missing_signals), 3)

    def test_strict_insufficient_missing_strategy(self):
        """Configured strict strategy returns unknown risk when any signal is missing."""
        strict_config = RiskEngineConfig(missing_strategy="strict_insufficient")
        strict_engine = RiskEngine(strict_config)
        detection = DetectionSignalInput(
            ml_anomaly_score=85.0,
            behavioural_score=None,
            resource_anomaly_score=60.0,
        )
        result = strict_engine.calculate_risk(detection)
        self.assertEqual(result.risk_level, "unknown")
        self.assertTrue(result.is_provisional)

    def test_contextual_resource_anomaly_estimation(self):
        """High CPU alone with no contextual violations yields Q=0.0 to prevent double-counting."""
        telem_compiler = ProcessTelemetryInput(
            pid=2001,
            process_name="gcc",
            cpu_percent=95.0,
            memory_percent=10.0,
            open_sockets_count=0,
            distinct_remote_ips=0,
            num_threads=2,
            exe_path="/usr/bin/gcc",
            parent_name="bash",
        )
        q_compiler = self.engine.estimate_resource_anomaly(telem_compiler)
        self.assertEqual(q_compiler, 0.0) # Zero double-counting on clean compilers

        # Suspicious volatile path + miner name + socket burst
        telem_miner = ProcessTelemetryInput(
            pid=2002,
            process_name="miner",
            cpu_percent=95.0,
            memory_percent=10.0,
            open_sockets_count=45,
            distinct_remote_ips=25,
            num_threads=40,
            exe_path="/tmp/.miner_payload",
            parent_name="bash",
        )
        q_miner = self.engine.estimate_resource_anomaly(telem_miner)
        self.assertGreater(q_miner, 60.0)
        self.assertGreater(q_miner, q_compiler)

    def test_negative_weights_raise_value_error(self):
        """Individual negative weights must raise ValueError."""
        with self.assertRaises(ValueError):
            RiskEngineConfig(weight_ml=-0.40, weight_behavioural=0.40, weight_resource=0.20)
        with self.assertRaises(ValueError):
            RiskEngineConfig(weight_ml=0.40, weight_behavioural=-0.40, weight_resource=0.20)
        with self.assertRaises(ValueError):
            RiskEngineConfig(weight_ml=0.40, weight_behavioural=0.40, weight_resource=-0.20)

    def test_zero_total_weight_raises_value_error(self):
        """Total weight equal to 0.0 must raise ValueError."""
        with self.assertRaises(ValueError):
            RiskEngineConfig(weight_ml=0.0, weight_behavioural=0.0, weight_resource=0.0)

    def test_invalid_negative_score_raises(self):
        """Negative scores must raise ValueError."""
        with self.assertRaises(ValueError):
            self.engine.normalize_score(-5.0, "test")

    def test_invalid_excessive_score_raises(self):
        """Scores above 100.0 must raise ValueError."""
        with self.assertRaises(ValueError):
            self.engine.normalize_score(150.0, "test")

    def test_nan_infinity_raises(self):
        """NaN and Infinity must raise ValueError."""
        with self.assertRaises(ValueError):
            self.engine.normalize_score(float("nan"), "test")
        with self.assertRaises(ValueError):
            self.engine.normalize_score(float("inf"), "test")

    def test_configurable_custom_weights(self):
        """Custom weights should be normalized and applied correctly."""
        custom_cfg = RiskEngineConfig(
            weight_ml=0.50,
            weight_behavioural=0.30,
            weight_resource=0.20,
            low_threshold=25.0,
            high_threshold=75.0,
        )
        custom_engine = RiskEngine(custom_cfg)
        detection = DetectionSignalInput(
            ml_anomaly_score=100.0,
            behavioural_score=50.0,
            resource_anomaly_score=0.0,
        )
        res = custom_engine.calculate_risk(detection)
        # 0.50*100 + 0.30*50 + 0.20*0 = 50 + 15 = 65
        self.assertEqual(res.risk_score, 65.0)
        self.assertEqual(res.risk_level, "medium")


if __name__ == "__main__":
    unittest.main()

