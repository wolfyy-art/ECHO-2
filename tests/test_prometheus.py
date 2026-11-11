"""
tests/test_prometheus.py
========================
Unit tests for ECHO M4 Prometheus Metrics Exporter.
Verifies metric generation, formatting, and valid exposition format.
"""

import sys
import unittest
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dashboard.database import (
    init_database,
    insert_process_event,
    insert_alert,
    insert_response_action,
    insert_verification_result,
)
from dashboard.prometheus.exporter import generate_prometheus_metrics


class TestPrometheusExporter(unittest.TestCase):
    """Test metric generation for Prometheus scraping."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.tmp_dir) / "test_echo.db"
        init_database(self.db_path)

        # Seed data
        insert_process_event(
            event_id="prom-evt-1",
            pid=5000,
            process_name="test_proc",
            process_start_time="2026-01-01T00:00:00Z",
            cpu_percent=12.5,
            memory_percent=4.0,
            risk_level="medium",
            db_path=self.db_path,
        )
        insert_alert(
            alert_id="prom-alert-1",
            event_id="prom-evt-1",
            severity="medium",
            reason="Test alert",
            status="open",
            db_path=self.db_path,
        )
        insert_response_action(
            action_id="prom-act-1",
            event_id="prom-evt-1",
            action_type="simulate_restriction",
            execution_mode="simulation",
            approval_status="approved",
            result="success",
            db_path=self.db_path,
        )
        insert_verification_result(
            verification_id="prom-vrf-1",
            action_id="prom-act-1",
            success=True,
            details="Test verification passed",
            collateral_impact="none",
            db_path=self.db_path,
        )

    def test_metrics_output_format(self):
        metrics = generate_prometheus_metrics(self.db_path)
        self.assertIn("echo_process_events_total", metrics)
        self.assertIn("echo_active_alerts", metrics)
        self.assertIn("echo_response_actions_total", metrics)
        self.assertIn("echo_verification_success_rate", metrics)
        self.assertIn('risk_level="medium"', metrics)
        self.assertIn('severity="medium"', metrics)
        self.assertIn('action_type="simulate_restriction"', metrics)
        self.assertTrue(metrics.endswith("\n"))


if __name__ == "__main__":
    unittest.main()
