"""
run_echo.py
===========
ECHO — End-to-End Three-Process Demonstration Pipeline
Author: Suhani (M2), Rishit (M3), Mayank (M4), Kshitij (M1)

Demonstrates the core innovation of ECHO:

On a single host, 3 distinct processes are running concurrently:
  - Process A (nginx, PID 1010)        : Normal web client (low traffic) → ALLOWED
  - Process B (rsync_backup, PID 1020) : Heavy file transfer             → ALLOWED
  - Process C (worker_daemon, PID 1030): Anomalous compute/socket spike  → DETECTED & CONTAINED

Shows:
  1. Dual-Layer Detection (MAD Statistical Profiling + Isolation Forest ML).
  2. Multi-Signal Risk Correlation: R = w_m * M + w_a * A + w_r * Q.
  3. Graduated Policy Decision & Simulation-Mode Containment.
  4. Closed-Loop Post-Action Verification with explicit simulated telemetry.

PREREQUISITES
-------------
The Isolation Forest model artifact must be trained before running this demo:

    python models/train.py --db-path /tmp/echo_train.db

This demo will NOT auto-train the model.  If the artifact is missing,
it will print clear instructions and exit.

SAFETY NOTES
------------
- All actions run in simulation mode.  No real OS changes are made.
- The approval_status="approved" passed to dispatch_decision() is a DEMO
  SIMULATION of operator approval.  In production, approval must come from
  an explicit human decision, not from a default parameter value.
- The simulated_metrics passed to verify_response() are DEMO-ONLY placeholders.
  They do not represent real host telemetry.  The verification result is
  labelled "[SIMULATED EVIDENCE]" in the output accordingly.
"""

import sys
import uuid
import logging
from pathlib import Path
from datetime import datetime, timezone
import pandas as pd

_PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_PROJECT_ROOT))

from dashboard.database import (
    DB_PATH,
    init_database,
    insert_process_event,
    get_recent_process_events,
    get_active_alerts,
    get_response_history,
    get_verification_history,
    _utc_now,
)
from detection.isolation_forest import ProcessIsolationForest, APPROVED_FEATURE_COLUMNS
from correlation.engine import CorrelationEngine, CorrelationWeights
from correlation.policy import PolicyEngine
from verification.verifier import ClosedLoopVerifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ECHO_DEMO")

_MODEL_PATH = _PROJECT_ROOT / "models" / "isolation_forest.joblib"


def _require_model() -> ProcessIsolationForest:
    """
    Load the trained model artifact.  Exit with clear instructions if missing.
    Does NOT auto-train — training must be done explicitly with an isolated DB.
    """
    if not _MODEL_PATH.exists():
        print(
            f"\nERROR: Model artifact not found at:\n"
            f"  {_MODEL_PATH}\n\n"
            f"Train the model first using an isolated database:\n"
            f"  python models/train.py --db-path /tmp/echo_train.db\n\n"
            f"Then re-run this demo.\n",
            file=sys.stderr,
        )
        sys.exit(1)
    return ProcessIsolationForest.load(_MODEL_PATH)


def run_three_process_scenario() -> None:
    print("=" * 80)
    print("      ECHO: ENDPOINT CORRELATION & HOST ORCHESTRATION")
    print("           Multi-Process Behavioral Defense Demo")
    print("=" * 80)

    # 1. Initialize Database
    logger.info("[1/5] Ensuring SQLite database foundation is initialized...")
    init_database(DB_PATH)

    # 2. Load Trained Model Artifact (exits with instructions if missing)
    logger.info("[2/5] Loading serialized Isolation Forest model from: %s", _MODEL_PATH.name)
    model = _require_model()

    # 3. Setup Engines
    weights = CorrelationWeights(w_m=0.40, w_a=0.40, w_r=0.20)
    corr_engine  = CorrelationEngine(db_path=DB_PATH, model=model, weights=weights)
    policy_engine = PolicyEngine(db_path=DB_PATH, default_execution_mode="simulation")
    verifier     = ClosedLoopVerifier(db_path=DB_PATH)
    now_iso      = _utc_now()

    # 4. Define the 3 Concurrent Processes in a live 5-second window
    test_cases = [
        {
            "role":              "Process A (Web Client)",
            "pid":               1010,
            "ppid":              1,
            "process_name":      "nginx",
            "username":          "www-data",
            "cpu_mean":          2.1,
            "cpu_max":           2.8,
            "cpu_std":           0.15,
            "memory_mean":       0.75,
            "memory_max":        0.80,
            "memory_rss_mean":   32000000,
            "num_threads_mean":  4.0,
            "num_threads_max":   4,
            "open_sockets_count":    5,
            "distinct_remote_ips":   3,
            "sample_count":      5,
            "cpu_mem_ratio":     2.8,
            "socket_thread_ratio": 1.25,
            "exe_path":          "/usr/sbin/nginx",
            "parent_name":       "systemd",
        },
        {
            "role":              "Process B (Backup Transfer)",
            "pid":               1020,
            "ppid":              1,
            "process_name":      "rsync_backup",
            "username":          "backup",
            "cpu_mean":          18.2,
            "cpu_max":           22.0,
            "cpu_std":           0.80,
            "memory_mean":       2.50,
            "memory_max":        2.70,
            "memory_rss_mean":   105000000,
            "num_threads_mean":  3.0,
            "num_threads_max":   3,
            "open_sockets_count":    24,
            "distinct_remote_ips":   2,
            "sample_count":      5,
            "cpu_mem_ratio":     7.28,
            "socket_thread_ratio": 8.0,
            "exe_path":          "/usr/bin/rsync",
            "parent_name":       "systemd",
        },
        {
            "role":              "Process C (Compromised Worker)",
            "pid":               1030,
            "ppid":              1000,
            "process_name":      "worker_daemon",
            "username":          "vboxuser",
            # ANOMALOUS SPIKE: Normal baseline for worker_daemon is ~0.5% CPU & 1 socket.
            "cpu_mean":          96.5,
            "cpu_max":           99.8,
            "cpu_std":           1.20,
            "memory_mean":       6.80,
            "memory_max":        7.20,
            "memory_rss_mean":   285000000,
            "num_threads_mean":  16.0,
            "num_threads_max":   16,
            "open_sockets_count":    68,
            "distinct_remote_ips":   35,
            "sample_count":      5,
            "cpu_mem_ratio":     14.19,
            "socket_thread_ratio": 4.25,
            "exe_path":          "/tmp/.hidden_miner",
            "parent_name":       "bash",
        },
    ]

    print("\n[3/5] Evaluating Process Telemetry through Correlation & Policy Engine:")
    print("-" * 80)
    print(
        f"{'PROCESS':<24} | {'CPU %':<7} | {'SOCKS':<5} | "
        f"{'ML (M)':<6} | {'MAD (A)':<7} | {'RISK (R)':<8} | DECISION"
    )
    print("-" * 80)

    evaluated_results = []

    for item in test_cases:
        pname    = item["process_name"]
        pid      = item["pid"]
        event_id = f"evt-live-{uuid.uuid4().hex[:8]}"

        # Build 1-row DataFrame for ML scoring
        feature_dict = {col: [item.get(col, 0.0)] for col in APPROVED_FEATURE_COLUMNS}
        df_row = pd.DataFrame(feature_dict)

        # 1. Correlate all three signals (ML + MAD + rules)
        risk_result = corr_engine.correlate_process_event(
            event_dict=item,
            df_feature_row=df_row,
            exe_path=item["exe_path"],
            parent_name=item["parent_name"],
        )

        # 2. Persist process event to the database
        insert_process_event(
            event_id=event_id,
            timestamp=now_iso,
            pid=pid,
            process_name=pname,
            process_start_time=now_iso,
            cpu_percent=item["cpu_mean"],
            memory_percent=item["memory_mean"],
            anomaly_score=risk_result.composite_risk_R,
            risk_level=risk_result.risk_level,
            db_path=DB_PATH,
        )

        # 3. Policy evaluation
        decision = policy_engine.evaluate_policy(event_id, risk_result)

        # 4. Dispatch with explicit demo approval.
        # DEMO NOTE: approval_status="approved" is passed here to simulate an operator
        # confirming the action in the demo scenario.  In a production deployment,
        # this approval must come from a real human decision, not a default parameter.
        dispatch_output = policy_engine.dispatch_decision(
            decision,
            approval_status="approved",  # DEMO: simulating operator approval
        )

        # 5. Closed-loop verification for actions that were dispatched
        verify_output = None
        action_rec = dispatch_output.get("response_action")
        if action_rec and action_rec.get("action_id") and action_rec.get("result") == "success":
            # DEMO NOTE: These metrics are DEMO-ONLY simulated placeholders.
            # They do not reflect real host telemetry.  The verifier will label
            # the result "[SIMULATED EVIDENCE]" in the details string accordingly.
            verify_output = verifier.verify_response(
                action_id=action_rec["action_id"],
                simulated_metrics={
                    "collateral_impact_detected":    False,
                    "unrelated_processes_impacted":  0,
                },
            )

        evaluated_results.append({
            "role":     item["role"],
            "pname":    pname,
            "pid":      pid,
            "cpu":      item["cpu_mean"],
            "socks":    item["open_sockets_count"],
            "risk_res": risk_result,
            "decision": decision,
            "action":   action_rec,
            "verify":   verify_output,
        })

        if decision.recommended_action == "log_only":
            status_tag = "ALLOW (Normal)"
        elif decision.recommended_action == "simulate_restriction":
            status_tag = "RESTRICT (Simulated)"
        else:
            status_tag = f"[{decision.recommended_action.upper()}]"

        print(
            f"{item['role']:<24} | "
            f"{item['cpu_mean']:>5.1f}% | "
            f"{item['open_sockets_count']:>5} | "
            f"{risk_result.ml_score_M:>6.2f} | "
            f"{risk_result.mad_score_A:>7.2f} | "
            f"{risk_result.composite_risk_R:>8.2f} | "
            f"{status_tag}"
        )

    print("-" * 80)

    # 6. Detailed findings
    print("\n[4/5] Detailed Security Findings:")
    for res in evaluated_results:
        rr = res["risk_res"]
        print(f"\n • {res['role']} (PID {res['pid']}):")
        print(
            f"   - Anomaly Breakdown : ML={rr.ml_score_M:.2f}, "
            f"MAD={rr.mad_score_A:.2f}, Rules={rr.rule_score_Q:.2f}"
        )
        print(f"   - Composite Risk (R): {rr.composite_risk_R:.2f} ({rr.risk_level.upper()})")
        print(f"   - Policy Action     : {res['decision'].recommended_action}")
        if rr.triggered_rules:
            print(f"   - Rules Triggered   : {', '.join(rr.triggered_rules)}")
        if res["action"]:
            print(
                f"   - Action Dispatched : ID={res['action']['action_id']} "
                f"({res['action']['execution_mode']} mode, result={res['action']['result']})"
            )
        if res["verify"]:
            vr = res["verify"]
            print(
                f"   - Closed-Loop Check : outcome={vr.get('verification_outcome', '?')}, "
                f"collateral={vr['collateral_impact']}"
            )
            print(f"     {vr['details'][:120]}{'...' if len(vr['details']) > 120 else ''}")

    print("\n" + "=" * 80)
    print(" [5/5] Demonstration Complete.")
    print("       REMINDER: All actions ran in simulation mode.")
    print("       No real processes were terminated or restricted.")
    print("       Verification results are based on simulated telemetry, not real host state.")
    print("=" * 80)


if __name__ == "__main__":
    run_three_process_scenario()
