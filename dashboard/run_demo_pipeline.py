"""
dashboard/run_demo_pipeline.py
==============================
ECHO — M4: End-to-End Closed-Loop Pipeline Demonstration
Author: Mayank (M4)

Demonstrates the complete ECHO workflow:
1. Ingests simulated process telemetry (M1/M2/M3 feed).
2. Generates security alerts for anomalous detections.
3. Triggers the Response Engine to apply safe simulation-mode containment.
4. Performs Closed-Loop Verification to validate containment and assert zero collateral damage.
5. Exposes updated metrics to Prometheus.

Usage:
    python dashboard/run_demo_pipeline.py
"""

import sys
import uuid
import logging
from pathlib import Path

# Add project root to sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from dashboard.database import (
    init_database,
    insert_process_event,
    insert_alert,
    get_recent_process_events,
    get_active_alerts,
    get_response_history,
    get_verification_history,
)
from response.engine import ResponseEngine
from verification.verifier import ClosedLoopVerifier
from dashboard.prometheus.exporter import generate_prometheus_metrics

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ECHO_PIPELINE")


def run_pipeline():
    print("=" * 70)
    print(" ECHO: Endpoint Correlation & Host Orchestration — Closed Loop Demo")
    print("=" * 70)

    # Step 1: Database Initialization
    logger.info("[Step 1] Ensuring SQLite database foundation is initialized...")
    init_database()

    # Step 2: Ingest Scored Process Event
    event_id = f"evt-e2e-{uuid.uuid4().hex[:8]}"
    pid = 49152
    process_name = "[DEMO] unauthorized_miner.bin"
    logger.info("[Step 2] Ingesting scored event from M1/M2/M3: %s (PID %d)...", process_name, pid)

    insert_process_event(
        event_id=event_id,
        pid=pid,
        process_name=process_name,
        process_start_time="2026-10-22T19:30:00.000000Z",
        cpu_percent=98.6,
        memory_percent=18.4,
        risk_level="high",
        anomaly_score=0.96,
    )

    # Step 3: Raise Security Alert
    alert_id = f"alt-e2e-{uuid.uuid4().hex[:8]}"
    logger.info("[Step 3] Raising High-Severity Alert: %s...", alert_id)
    insert_alert(
        alert_id=alert_id,
        event_id=event_id,
        severity="high",
        reason=f"Process '{process_name}' (PID {pid}) exhibited 98.6% CPU and anomaly score 0.96.",
    )

    # Step 4: Safe Response Execution (Phase 2)
    logger.info("[Step 4] Triggering ResponseEngine in SIMULATION mode...")
    engine = ResponseEngine()
    resp_result = engine.execute_response(
        event_id=event_id,
        action_type="simulate_restriction",
        execution_mode="simulation",
        approval_status="approved",
    )
    action_id = resp_result["action_id"]
    logger.info("Response executed: Action ID = %s, Result = %s", action_id, resp_result["result"])

    # Step 5: Closed-Loop Verification (Phase 2)
    logger.info("[Step 5] Triggering ClosedLoopVerifier...")
    verifier = ClosedLoopVerifier()
    verif_result = verifier.verify_response(
        action_id=action_id,
        simulated_metrics={
            "collateral_impact_detected": False,
            "unrelated_processes_impacted": 0,
        },
    )
    logger.info(
        "Verification complete: Success = %s, Collateral Impact = %s",
        verif_result["success"],
        verif_result["collateral_impact"],
    )

    # Step 6: Verify Prometheus Metrics Output (Phase 3)
    logger.info("[Step 6] Generating Prometheus Metrics Export (Phase 3)...")
    metrics_preview = generate_prometheus_metrics()

    print("\n" + "-" * 70)
    print(" SUMMARY OF CLOSED-LOOP EXECUTION")
    print("-" * 70)
    print(f" • Event Ingested     : {event_id} ({process_name}, PID {pid})")
    print(f" • Alert Raised       : {alert_id} [HIGH]")
    print(f" • Response Executed  : {action_id} (simulate_restriction -> {resp_result['result']})")
    print(f" • Verified Status    : {verif_result['verification_id']} (Passed: {verif_result['success']})")
    print(f" • Collateral Impact  : {verif_result['collateral_impact']}")
    print("-" * 70)
    print("\nPrometheus Metric Sample (Lines):")
    for line in metrics_preview.splitlines()[:10]:
        print(f"   {line}")
    print("=" * 70)
    print(" Pipeline demonstration executed successfully with zero OS impact.")


if __name__ == "__main__":
    run_pipeline()
