"""
tests/test_process_context.py
=============================
Unit tests for ECHO M3 ProcessContextManager.
"""

import unittest
from correlation.models import ProcessTelemetryInput, RiskScoreResult
from correlation.process_context import ProcessContextManager


class TestProcessContext(unittest.TestCase):
    """Test suite for process instance tracking, PID reuse, and memory bounds."""

    def setUp(self):
        self.mgr = ProcessContextManager(max_processes=5, max_history_per_instance=5)

    def test_new_instance_creation(self):
        """First observation should create an active tracking instance."""
        telem = ProcessTelemetryInput(
            pid=1001,
            process_name="nginx",
            process_start_time="2026-11-12T10:00:00Z",
            username="www-data",
        )
        record, is_new = self.mgr.get_or_create_instance(telem)
        self.assertTrue(is_new)
        self.assertEqual(record.pid, 1001)
        self.assertEqual(record.process_name, "nginx")
        self.assertEqual(record.observation_count, 1)
        self.assertTrue(record.is_active)

    def test_repeated_observations_tracking(self):
        """Subsequent observations on the same instance increment counts and append scores."""
        telem = ProcessTelemetryInput(
            pid=1001,
            process_name="nginx",
            process_start_time="2026-11-12T10:00:00Z",
            username="www-data",
        )
        risk1 = RiskScoreResult(risk_score=20.0, risk_level="low")
        risk2 = RiskScoreResult(risk_score=75.0, risk_level="high")

        rec1 = self.mgr.update_context(telem, risk1)
        self.assertEqual(rec1.observation_count, 1)

        rec2 = self.mgr.update_context(telem, risk2)
        self.assertEqual(rec2.observation_count, 2)
        self.assertEqual(rec2.anomaly_count, 1)
        self.assertEqual(rec2.consecutive_high_risk_count, 1)
        self.assertEqual(list(rec2.recent_risk_scores), [20.0, 75.0])

    def test_pid_reuse_detection(self):
        """When an OS reuses a PID for a new process, the old instance is retired."""
        telem_old = ProcessTelemetryInput(
            pid=5555,
            process_name="short_lived_task",
            process_start_time="2026-11-12T10:00:00Z",
            username="vboxuser",
        )
        old_record, _ = self.mgr.get_or_create_instance(telem_old)
        self.assertTrue(old_record.is_active)

        # Later, PID 5555 is assigned to a different binary with a new start time
        telem_new = ProcessTelemetryInput(
            pid=5555,
            process_name="new_worker",
            process_start_time="2026-11-12T10:15:00Z",
            username="vboxuser",
        )
        new_record, is_new = self.mgr.get_or_create_instance(telem_new)
        self.assertTrue(is_new)
        self.assertFalse(old_record.is_active, "Old instance must be retired upon PID reuse.")
        self.assertTrue(new_record.is_active)
        self.assertNotEqual(old_record.instance_identity, new_record.instance_identity)

    def test_risk_trend_calculation(self):
        """Risk trend identifies increasing, decreasing, or stable trajectories."""
        telem = ProcessTelemetryInput(pid=3333, process_name="miner", process_start_time="2026-11-12T10:00:00Z")
        self.mgr.update_context(telem, RiskScoreResult(risk_score=20.0, risk_level="low"))
        self.mgr.update_context(telem, RiskScoreResult(risk_score=50.0, risk_level="medium"))
        rec = self.mgr.update_context(telem, RiskScoreResult(risk_score=80.0, risk_level="high"))
        self.assertEqual(rec.get_risk_trend(), "increasing")

    def test_lru_capacity_eviction(self):
        """Cache strictly bounds memory by evicting oldest instances when capacity is reached."""
        for i in range(10):
            telem = ProcessTelemetryInput(
                pid=1000 + i,
                process_name=f"proc_{i}",
                process_start_time="2026-11-12T10:00:00Z",
            )
            self.mgr.get_or_create_instance(telem)

        # Capacity was set to 5
        self.assertEqual(self.mgr.active_instances_count(), 5)


if __name__ == "__main__":
    unittest.main()

