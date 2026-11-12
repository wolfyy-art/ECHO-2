"""
tests/test_prometheus.py
========================
Unit tests for ECHO M4 Prometheus Metrics Exporter.

Tests metric generation, formatting, and valid exposition format.

Monitoring contract being verified
------------------------------------
1. All expected metric families are present in the output.
2. Metric TYPE declarations are correct (gauge for SQLite snapshot counts).
3. echo_verification_success_rate is OMITTED when no verification records exist
   (not reported as 1.0 / 100%).
4. echo_verification_success_rate reflects the correct ratio when records exist.
5. echo_exporter_scrape_timestamp_seconds is always emitted.
6. The output ends with a trailing newline (Prometheus requirement).
7. Grafana datasource URL points to Prometheus (9090), not the exporter (9108).
"""

import sys
import re
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

        # Seed one record of each type for the populated-DB tests
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

    # -----------------------------------------------------------------------
    # Pre-existing test — must remain passing
    # -----------------------------------------------------------------------

    def test_metrics_output_format(self):
        """Pre-existing: populated DB must produce all expected metric families."""
        metrics = generate_prometheus_metrics(self.db_path)
        self.assertIn("echo_process_events_total", metrics)
        self.assertIn("echo_active_alerts", metrics)
        self.assertIn("echo_response_actions_total", metrics)
        self.assertIn("echo_verification_success_rate", metrics)
        self.assertIn('risk_level="medium"', metrics)
        self.assertIn('severity="medium"', metrics)
        self.assertIn('action_type="simulate_restriction"', metrics)
        self.assertTrue(metrics.endswith("\n"))

    # -----------------------------------------------------------------------
    # New: success rate omitted on empty database
    # -----------------------------------------------------------------------

    def test_empty_db_omits_verification_success_rate(self):
        """With no verification records, success rate metric must NOT be emitted."""
        empty_db = Path(self.tmp_dir) / "empty_echo.db"
        init_database(empty_db)
        metrics = generate_prometheus_metrics(empty_db)
        # The HELP/TYPE headers are always emitted, but no data line must follow
        lines = metrics.splitlines()
        data_lines = [
            l for l in lines
            if l.startswith("echo_verification_success_rate")
            and not l.startswith("#")
        ]
        self.assertEqual(
            len(data_lines), 0,
            f"Success rate must be omitted when no verifications exist, "
            f"but found: {data_lines}",
        )

    def test_empty_db_does_not_report_100_percent(self):
        """Empty DB must not produce echo_verification_success_rate 1.0000."""
        empty_db = Path(self.tmp_dir) / "empty2_echo.db"
        init_database(empty_db)
        metrics = generate_prometheus_metrics(empty_db)
        self.assertNotIn(
            "echo_verification_success_rate 1.0000", metrics,
            "Empty DB must not report 100% success rate",
        )

    def test_populated_db_reports_correct_success_rate(self):
        """With 1 success and 0 failures, success rate must be 1.0."""
        metrics = generate_prometheus_metrics(self.db_path)
        self.assertIn("echo_verification_success_rate 1.0000", metrics)

    def test_mixed_verifications_correct_success_rate(self):
        """With 1 success and 1 failure, success rate must be 0.5."""
        insert_response_action(
            action_id="prom-act-2",
            event_id="prom-evt-1",
            action_type="simulate_restriction",
            execution_mode="simulation",
            approval_status="approved",
            result="success",
            db_path=self.db_path,
        )
        insert_verification_result(
            verification_id="prom-vrf-2",
            action_id="prom-act-2",
            success=False,
            details="Test verification failed",
            collateral_impact="detected",
            db_path=self.db_path,
        )
        metrics = generate_prometheus_metrics(self.db_path)
        self.assertIn("echo_verification_success_rate 0.5000", metrics)

    # -----------------------------------------------------------------------
    # New: scrape timestamp always emitted
    # -----------------------------------------------------------------------

    def test_scrape_timestamp_emitted(self):
        """echo_exporter_scrape_timestamp_seconds must always be in the output."""
        metrics = generate_prometheus_metrics(self.db_path)
        self.assertIn("echo_exporter_scrape_timestamp_seconds", metrics)

    def test_scrape_timestamp_emitted_on_empty_db(self):
        """Scrape timestamp must be emitted even when the DB is empty."""
        empty_db = Path(self.tmp_dir) / "empty3_echo.db"
        init_database(empty_db)
        metrics = generate_prometheus_metrics(empty_db)
        self.assertIn("echo_exporter_scrape_timestamp_seconds", metrics)

    def test_scrape_timestamp_is_numeric(self):
        """The scrape timestamp value must be a valid float."""
        metrics = generate_prometheus_metrics(self.db_path)
        for line in metrics.splitlines():
            if line.startswith("echo_exporter_scrape_timestamp_seconds") and not line.startswith("#"):
                parts = line.split()
                self.assertEqual(len(parts), 2, f"Unexpected line format: {line}")
                try:
                    float(parts[1])
                except ValueError:
                    self.fail(f"Scrape timestamp is not a valid float: {parts[1]}")
                return
        self.fail("echo_exporter_scrape_timestamp_seconds data line not found")

    # -----------------------------------------------------------------------
    # New: TYPE declarations are gauge for SQLite snapshot metrics
    # -----------------------------------------------------------------------

    def test_process_events_declared_as_gauge(self):
        """echo_process_events_total must be declared TYPE gauge (SQLite snapshot)."""
        metrics = generate_prometheus_metrics(self.db_path)
        self.assertIn("# TYPE echo_process_events_total gauge", metrics)

    def test_alerts_total_declared_as_gauge(self):
        """echo_alerts_total must be declared TYPE gauge (SQLite snapshot)."""
        metrics = generate_prometheus_metrics(self.db_path)
        self.assertIn("# TYPE echo_alerts_total gauge", metrics)

    def test_response_actions_declared_as_gauge(self):
        """echo_response_actions_total must be declared TYPE gauge (SQLite snapshot)."""
        metrics = generate_prometheus_metrics(self.db_path)
        self.assertIn("# TYPE echo_response_actions_total gauge", metrics)

    def test_verification_results_declared_as_gauge(self):
        """echo_verification_results_total must be declared TYPE gauge (SQLite snapshot)."""
        metrics = generate_prometheus_metrics(self.db_path)
        self.assertIn("# TYPE echo_verification_results_total gauge", metrics)

    def test_active_alerts_declared_as_gauge(self):
        """echo_active_alerts must be declared TYPE gauge."""
        metrics = generate_prometheus_metrics(self.db_path)
        self.assertIn("# TYPE echo_active_alerts gauge", metrics)

    # -----------------------------------------------------------------------
    # New: output format requirements
    # -----------------------------------------------------------------------

    def test_output_ends_with_newline(self):
        """Prometheus exposition format requires output to end with a newline."""
        metrics = generate_prometheus_metrics(self.db_path)
        self.assertTrue(metrics.endswith("\n"), "Metrics output must end with a newline")

    def test_no_counter_type_declarations(self):
        """No metric must be incorrectly declared as counter (all are gauges here)."""
        metrics = generate_prometheus_metrics(self.db_path)
        self.assertNotIn("# TYPE echo_process_events_total counter", metrics)
        self.assertNotIn("# TYPE echo_alerts_total counter", metrics)
        self.assertNotIn("# TYPE echo_response_actions_total counter", metrics)
        self.assertNotIn("# TYPE echo_verification_results_total counter", metrics)

    # -----------------------------------------------------------------------
    # New: Grafana datasource configuration
    # -----------------------------------------------------------------------

    def test_grafana_datasource_points_to_prometheus_not_exporter(self):
        """Grafana datasource must point to port 9090 (Prometheus), not 9108 (exporter)."""
        datasource_path = (
            Path(__file__).resolve().parent.parent
            / "dashboard" / "grafana" / "provisioning"
            / "datasources" / "datasource.yml"
        )
        self.assertTrue(datasource_path.exists(), "datasource.yml not found")
        content = datasource_path.read_text(encoding="utf-8")
        self.assertNotIn(
            ":9108", content,
            "Grafana datasource must NOT point to the exporter port 9108",
        )
        self.assertIn(
            ":9090", content,
            "Grafana datasource must point to Prometheus port 9090",
        )


if __name__ == "__main__":
    unittest.main()
