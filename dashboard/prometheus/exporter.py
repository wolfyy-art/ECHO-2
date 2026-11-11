"""
dashboard/prometheus/exporter.py
================================
ECHO — M4: Prometheus Metrics Exporter
Author: Mayank (M4)

Exposes ECHO metrics directly to Prometheus in standard OpenMetrics exposition format.
Zero external pip dependencies: uses Python standard library http.server.

Exposed Metrics:
----------------
- echo_process_events_total{risk_level="..."}       (Counter)
- echo_active_alerts{severity="..."}                 (Gauge)
- echo_alerts_total{severity="...",status="..."}     (Counter)
- echo_response_actions_total{action_type="...",result="...",execution_mode="..."} (Counter)
- echo_verification_results_total{success="...",collateral_impact="..."} (Counter)
- echo_verification_success_rate                    (Gauge: 0.0 - 1.0)
- echo_exporter_scrape_timestamp_seconds            (Gauge)
"""

import sys
import logging
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, List

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
    """
    lines: List[str] = []

    conn = _get_connection(db_path)
    try:
        # 1. Process events by risk level
        lines.append("# HELP echo_process_events_total Total process telemetry events captured by risk level.")
        lines.append("# TYPE echo_process_events_total counter")
        rows = conn.execute(
            "SELECT risk_level, COUNT(*) as count FROM process_events GROUP BY risk_level"
        ).fetchall()
        for r in rows:
            lines.append(f'echo_process_events_total{{risk_level="{r["risk_level"]}"}} {r["count"]}')

        # 2. Active alerts by severity
        lines.append("# HELP echo_active_alerts Current count of open/unresolved security alerts.")
        lines.append("# TYPE echo_active_alerts gauge")
        rows = conn.execute(
            "SELECT severity, COUNT(*) as count FROM alerts WHERE status = 'open' GROUP BY severity"
        ).fetchall()
        for r in rows:
            lines.append(f'echo_active_alerts{{severity="{r["severity"]}"}} {r["count"]}')

        # 3. All alerts total
        lines.append("# HELP echo_alerts_total Total alerts recorded by severity and status.")
        lines.append("# TYPE echo_alerts_total counter")
        rows = conn.execute(
            "SELECT severity, status, COUNT(*) as count FROM alerts GROUP BY severity, status"
        ).fetchall()
        for r in rows:
            lines.append(f'echo_alerts_total{{severity="{r["severity"]}",status="{r["status"]}"}} {r["count"]}')

        # 4. Response actions
        lines.append("# HELP echo_response_actions_total Total response actions initiated.")
        lines.append("# TYPE echo_response_actions_total counter")
        rows = conn.execute(
            "SELECT action_type, execution_mode, result, COUNT(*) as count FROM response_actions GROUP BY action_type, execution_mode, result"
        ).fetchall()
        for r in rows:
            lines.append(
                f'echo_response_actions_total{{action_type="{r["action_type"]}",execution_mode="{r["execution_mode"]}",result="{r["result"]}"}} {r["count"]}'
            )

        # 5. Verification results
        lines.append("# HELP echo_verification_results_total Closed-loop verification outcomes.")
        lines.append("# TYPE echo_verification_results_total counter")
        rows = conn.execute(
            "SELECT success, collateral_impact, COUNT(*) as count FROM verification_results GROUP BY success, collateral_impact"
        ).fetchall()
        total_verifications = 0
        total_successes = 0
        for r in rows:
            success_str = "true" if r["success"] == 1 else "false"
            lines.append(
                f'echo_verification_results_total{{success="{success_str}",collateral_impact="{r["collateral_impact"]}"}} {r["count"]}'
            )
            total_verifications += r["count"]
            if r["success"] == 1:
                total_successes += r["count"]

        # 6. Verification success rate gauge
        success_rate = (total_successes / total_verifications) if total_verifications > 0 else 1.0
        lines.append("# HELP echo_verification_success_rate Ratio of passed closed-loop verifications.")
        lines.append("# TYPE echo_verification_success_rate gauge")
        lines.append(f"echo_verification_success_rate {success_rate:.4f}")

    finally:
        conn.close()

    lines.append("")  # Prometheus requires trailing newline
    return "\n".join(lines)


class EchoMetricsHandler(BaseHTTPRequestHandler):
    """HTTP handler serving Prometheus metrics on /metrics."""

    db_path: Path = DB_PATH

    def do_GET(self):
        if self.path == "/metrics" or self.path == "/":
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
        # Override to suppress default stdout spam during scraping
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
