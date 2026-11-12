"""
dashboard/prometheus/exporter.py
================================
ECHO — M4: Prometheus Metrics Exporter
Author: Mayank (M4)

Exposes ECHO metrics directly to Prometheus in standard OpenMetrics exposition format.
Zero external pip dependencies: uses Python standard library http.server.

Exposed Metrics
---------------
- echo_process_events_total{risk_level="..."}
    Gauge — point-in-time count of process events by risk level.
    Declared as gauge because it reflects a SQLite snapshot count, not a
    Prometheus monotonically increasing counter.

- echo_active_alerts{severity="..."}
    Gauge — current count of open (unresolved) alerts by severity.

- echo_alerts_total{severity="...",status="..."}
    Gauge — point-in-time count of all alert records by severity and status.

- echo_response_actions_total{action_type="...",result="...",execution_mode="..."}
    Gauge — point-in-time count of response actions by type, result, and mode.

- echo_verification_results_total{success="...",collateral_impact="..."}
    Gauge — point-in-time count of verification outcomes.

- echo_verification_success_rate
    Gauge — ratio of successful verifications to total verifications (0.0–1.0).
    OMITTED when no verification records exist (rather than reporting a
    misleading 1.0 / 100% for an empty database).

- echo_exporter_scrape_timestamp_seconds
    Gauge — Unix timestamp of the most recent metric scrape.

Deployment Notes
----------------
Prometheus scrapes this exporter on port 9108.
Grafana must be configured to query Prometheus on port 9090, NOT this exporter.
See: dashboard/grafana/provisioning/datasources/datasource.yml
"""

import sys
import time
import logging
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import List

# Ensure project root is in sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from dashboard.database import (
    DB_PATH,
    _get_connection,
)

logger = logging.getLogger(__name__)


def generate_prometheus_metrics(db_path: Path = DB_PATH) -> str:
    """
    Query the SQLite database and format all ECHO metrics into Prometheus text format.

    Parameters
    ----------
    db_path : Path
        Path to the SQLite database to query.

    Returns
    -------
    str
        OpenMetrics-compatible text with a trailing newline.

    Design decisions
    ----------------
    - All SQLite COUNT(*) metrics are declared as TYPE gauge, not counter.
      A Prometheus counter must be monotonically increasing; a SQLite row count
      can decrease (e.g. if records are deleted) and represents a point-in-time
      snapshot, which is a gauge by definition.
    - echo_verification_success_rate is omitted entirely when no verification
      records exist.  Emitting 1.0 (100%) for an empty table would misrepresent
      the system's operational state.
    - echo_exporter_scrape_timestamp_seconds is always emitted so dashboards can
      detect staleness.
    """
    lines: List[str] = []
    scrape_ts = time.time()

    conn = _get_connection(db_path)
    try:
        # 1. Process events by risk level (gauge — SQLite snapshot count)
        lines.append("# HELP echo_process_events_total Point-in-time count of process telemetry events by risk level.")
        lines.append("# TYPE echo_process_events_total gauge")
        rows = conn.execute(
            "SELECT risk_level, COUNT(*) as count FROM process_events GROUP BY risk_level"
        ).fetchall()
        for r in rows:
            lines.append(f'echo_process_events_total{{risk_level="{r["risk_level"]}"}} {r["count"]}')

        # 2. Active (open) alerts by severity (gauge — subset of alerts table)
        lines.append("# HELP echo_active_alerts Current count of open/unresolved security alerts by severity.")
        lines.append("# TYPE echo_active_alerts gauge")
        rows = conn.execute(
            "SELECT severity, COUNT(*) as count FROM alerts WHERE status = 'open' GROUP BY severity"
        ).fetchall()
        for r in rows:
            lines.append(f'echo_active_alerts{{severity="{r["severity"]}"}} {r["count"]}')

        # 3. All alerts by severity and lifecycle status (gauge — SQLite snapshot)
        lines.append("# HELP echo_alerts_total Point-in-time count of all alert records by severity and status.")
        lines.append("# TYPE echo_alerts_total gauge")
        rows = conn.execute(
            "SELECT severity, status, COUNT(*) as count FROM alerts GROUP BY severity, status"
        ).fetchall()
        for r in rows:
            lines.append(
                f'echo_alerts_total{{severity="{r["severity"]}",status="{r["status"]}"}} {r["count"]}'
            )

        # 4. Response actions by type, mode, and result (gauge — SQLite snapshot)
        lines.append("# HELP echo_response_actions_total Point-in-time count of response actions by type, mode, and result.")
        lines.append("# TYPE echo_response_actions_total gauge")
        rows = conn.execute(
            "SELECT action_type, execution_mode, result, COUNT(*) as count "
            "FROM response_actions GROUP BY action_type, execution_mode, result"
        ).fetchall()
        for r in rows:
            lines.append(
                f'echo_response_actions_total{{'
                f'action_type="{r["action_type"]}",'
                f'execution_mode="{r["execution_mode"]}",'
                f'result="{r["result"]}"}} {r["count"]}'
            )

        # 5. Verification results by success and collateral impact (gauge — SQLite snapshot)
        lines.append("# HELP echo_verification_results_total Point-in-time count of closed-loop verification outcomes.")
        lines.append("# TYPE echo_verification_results_total gauge")
        rows = conn.execute(
            "SELECT success, collateral_impact, COUNT(*) as count "
            "FROM verification_results GROUP BY success, collateral_impact"
        ).fetchall()
        total_verifications = 0
        total_successes = 0
        for r in rows:
            success_str = "true" if r["success"] == 1 else "false"
            lines.append(
                f'echo_verification_results_total{{'
                f'success="{success_str}",'
                f'collateral_impact="{r["collateral_impact"]}"}} {r["count"]}'
            )
            total_verifications += r["count"]
            if r["success"] == 1:
                total_successes += r["count"]

        # 6. Verification success rate — OMITTED when no records exist.
        # Reporting 1.0 (100%) for an empty table is misleading.
        # Prometheus will treat a missing series as "no data", which is accurate.
        lines.append("# HELP echo_verification_success_rate Ratio of passed closed-loop verifications (0.0–1.0). Absent when no verifications recorded.")
        lines.append("# TYPE echo_verification_success_rate gauge")
        if total_verifications > 0:
            success_rate = total_successes / total_verifications
            lines.append(f"echo_verification_success_rate {success_rate:.4f}")
        # else: intentionally omitted — no data is more honest than 1.0

        # 7. Scrape timestamp — always emitted so dashboards can detect staleness.
        lines.append("# HELP echo_exporter_scrape_timestamp_seconds Unix timestamp of the most recent exporter scrape.")
        lines.append("# TYPE echo_exporter_scrape_timestamp_seconds gauge")
        lines.append(f"echo_exporter_scrape_timestamp_seconds {scrape_ts:.3f}")

    finally:
        conn.close()

    lines.append("")  # Prometheus requires a trailing newline
    return "\n".join(lines)


class EchoMetricsHandler(BaseHTTPRequestHandler):
    """HTTP handler serving Prometheus metrics on /metrics."""

    db_path: Path = DB_PATH

    def do_GET(self):
        if self.path in ("/metrics", "/"):
            try:
                metrics_text = generate_prometheus_metrics(self.db_path)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                self.end_headers()
                self.wfile.write(metrics_text.encode("utf-8"))
            except Exception as exc:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Exporter Error: {exc}".encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Suppress default stdout noise during scraping
        pass


def start_exporter(port: int = 9108, host: str = "0.0.0.0", db_path: Path = DB_PATH):
    """Start the Prometheus exporter HTTP server."""
    EchoMetricsHandler.db_path = db_path
    server = HTTPServer((host, port), EchoMetricsHandler)
    logger.info("ECHO Prometheus exporter running on http://%s:%d/metrics", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Stopping exporter...")
    finally:
        server.server_close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    port = 9108
    print(f"Starting ECHO Prometheus Exporter on http://localhost:{port}/metrics ...")
    start_exporter(port=port)
