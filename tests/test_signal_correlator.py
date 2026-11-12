"""
tests/test_signal_correlator.py
===============================
Unit tests for ECHO M3 SignalCorrelator.
"""

import unittest
from correlation.models import ProcessTelemetryInput, DetectionSignalInput
from correlation.process_context import ProcessContextManager
from correlation.signal_correlator import SignalCorrelator


class TestSignalCorrelator(unittest.TestCase):
    """Test suite for signal correlation, identity matching, and parent-child tracking."""

    def setUp(self):
        self.ctx = ProcessContextManager()
        self.correlator = SignalCorrelator(context_manager=self.ctx)

    def test_correlation_basic_matching(self):
        """Correlates telemetry with detection and creates canonical identities."""
        telem = ProcessTelemetryInput(
            pid=4521,
            process_name="firefox",
            process_start_time="2026-11-12T10:00:00Z",
            username="vboxuser",
        )
        detection = DetectionSignalInput(
            ml_anomaly_score=15.0,
            behavioural_score=10.0,
        )
        correlated = self.correlator.correlate(telem, detection)

        self.assertEqual(correlated.telemetry.pid, 4521)
        self.assertEqual(correlated.detection.ml_anomaly_score, 15.0)
        self.assertEqual(correlated.process_type_identity, "type::vboxuser::firefox")
        self.assertIn("inst::vboxuser::firefox::4521", correlated.process_instance_identity)

    def test_missing_detection_handling(self):
        """Correlator gracefully handles None detection by creating a safe default."""
        telem = ProcessTelemetryInput(pid=1234, process_name="bash")
        correlated = self.correlator.correlate(telem, None)
        self.assertIsNotNone(correlated.detection)
        self.assertIsNone(correlated.detection.ml_anomaly_score)

    def test_parent_child_suspicion_flag(self):
        """If parent process had prior anomalies, child receives parent_is_suspicious flag."""
        # 1. Establish parent PID 5000 with high risk / anomaly
        parent_telem = ProcessTelemetryInput(pid=5000, process_name="malicious_script", process_start_time="2026-11-12T09:00:00Z")
        from correlation.models import RiskScoreResult
        self.ctx.update_context(parent_telem, RiskScoreResult(risk_score=85.0, risk_level="high"))

        # 2. Spawn child process with ppid=5000
        child_telem = ProcessTelemetryInput(
            pid=5001,
            ppid=5000,
            process_name="curl",
            process_start_time="2026-11-12T09:05:00Z",
        )
        correlated = self.correlator.correlate(child_telem, DetectionSignalInput(ml_anomaly_score=10.0))
        self.assertTrue(correlated.parent_is_suspicious)

    def test_batch_correlation(self):
        """Batch correlation matches detections by PID correctly."""
        telems = [
            ProcessTelemetryInput(pid=101, process_name="p1"),
            ProcessTelemetryInput(pid=102, process_name="p2"),
        ]
        detections = {
            101: DetectionSignalInput(ml_anomaly_score=10.0),
            102: DetectionSignalInput(ml_anomaly_score=90.0),
        }
        batch = self.correlator.correlate_batch(telems, detections)
        self.assertEqual(len(batch), 2)
        self.assertEqual(batch[0].detection.ml_anomaly_score, 10.0)
        self.assertEqual(batch[1].detection.ml_anomaly_score, 90.0)


if __name__ == "__main__":
    unittest.main()

