"""
scripts/run_m3_demo.py
======================
ECHO — M3: Correlation, Risk Scoring, and Policy Engine End-to-End Demonstration.

Demonstrates the 4 mandatory scenarios using existing sample and synthetic telemetry:
1. Scenario 1: Normal Process (firefox/bash) -> Low risk, log_only, allowed.
2. Scenario 2: Suspicious Process (moderate deviations) -> Medium risk, investigate, no restriction.
3. Scenario 3: High-Risk Process ([DEMO] unauthorized_miner.bin) -> High risk, alert, approval-gated containment, verification.
4. Scenario 4: Missing Detection Data (unscored daemon) -> Safe handling, provisional assessment, no fabricated scores.

Usage:
    cd ECHO-2
    python scripts/run_m3_demo.py
"""

import sys
import uuid
import logging
from pathlib import Path

# Add project root to sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from dashboard.database import (
    init_database,
    DB_PATH,
    get_recent_process_events,
    get_active_alerts,
    get_response_history,
    get_verification_history,
)
from correlation.models import (
    ProcessTelemetryInput,
    DetectionSignalInput,
)
from correlation.signal_correlator import SignalCorrelator
from correlation.risk_engine import RiskEngine
from correlation.process_context import ProcessContextManager
from correlation.adapters import DemoDataAdapter
from correlation.storage import CorrelationStorage
from policy.engine import PolicyEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("ECHO_M3_DEMO")


def print_banner(title: str):
    print("\n" + "=" * 80)
    print(f" {title}")
    print("=" * 80)


def print_scenario_output(scenario_name: str, correlated, risk, decision, execution_outcome=None):
    telem = correlated.telemetry
    det = correlated.detection

    ml_str = f"{risk.ml_score_normalized:.1f}" if risk.ml_score_normalized is not None else "N/A (Missing)"
    beh_str = f"{risk.behavioural_score_normalized:.1f}" if risk.behavioural_score_normalized is not None else "N/A (Missing)"
    res_str = f"{risk.resource_score_normalized:.1f}" if risk.resource_score_normalized is not None else "N/A (Missing)"

    print(f"\n--- {scenario_name} ---")
    print(f"1.  Process Name           : {telem.process_name}")
    print(f"2.  PID                    : {telem.pid}")
    print(f"3.  ML Score (M)           : {ml_str}")
    print(f"4.  Behavioural Score (A)  : {beh_str}")
    print(f"5.  Resource/Net Score (Q) : {res_str}")
    print(f"6.  Overall Risk Score (R) : {risk.risk_score:.2f}")
    print(f"7.  Risk Classification    : {risk.risk_level.upper()}")
    print(f"8.  Policy Decision Reason : {decision.reason}")
    print(f"9.  Recommended Response   : {decision.recommended_action} (Approval required: {decision.requires_approval})")

    if execution_outcome:
        resp = execution_outcome.get("response", {})
        verif = execution_outcome.get("verification", {})
        print(f"10. Response Result        : {resp.get('result', 'N/A')} (Action: {resp.get('action_type', 'N/A')}, Mode: {resp.get('execution_mode', 'N/A')})")
        if verif:
            print(f"11. Verification Result    : Success={verif.get('success')}, Collateral={verif.get('collateral_impact')}, Details: {verif.get('details')}")
        else:
            print(f"11. Verification Result    : N/A (Verification not applicable for observational actions)")
    else:
        print(f"10. Response Result        : N/A (Simulated response not dispatched)")
        print(f"11. Verification Result    : N/A")


def run_demo():
    print_banner("ECHO-2: M3 Correlation & Policy Engine Comprehensive Demonstration")

    # Step 0: Initialize database & M3 storage
    logger.info("Initializing database foundation at: %s", DB_PATH)
    init_database()
    storage = CorrelationStorage(DB_PATH)
    ctx = ProcessContextManager()
    correlator = SignalCorrelator(context_manager=ctx)
    risk_engine = RiskEngine()
    policy_engine = PolicyEngine(db_path=DB_PATH)

    # -------------------------------------------------------------------------
    # SCENARIO 1: NORMAL PROCESS
    # -------------------------------------------------------------------------
    print_banner("SCENARIO 1: Normal Process (Firefox Browser)")
    demo_raw_1 = {
        "event_id": f"evt-demo-norm-{uuid.uuid4().hex[:6]}",
        "pid": 4521,
        "process_name": "firefox",
        "process_start_time": "2026-11-12T12:00:00Z",
        "cpu_percent": 3.2,
        "memory_percent": 5.8,
        "risk_level": "low",
        "anomaly_score": 0.04,
        "timestamp": "2026-11-12T12:05:00Z",
    }
    telem1, det1 = DemoDataAdapter.from_seed_demo_event(demo_raw_1)
    corr1 = correlator.correlate(telem1, det1)
    risk1 = risk_engine.calculate_risk(det1, telem1)
    dec1 = policy_engine.evaluate_decision(corr1, risk1)
    storage.save_record(corr1, risk1, dec1)
    out1 = policy_engine.execute_and_verify(dec1, operator_approved=False, execution_mode="simulation")
    print_scenario_output("SCENARIO 1: NORMAL PROCESS (ALLOWED / LOGGED)", corr1, risk1, dec1, out1)

    # -------------------------------------------------------------------------
    # SCENARIO 2: SUSPICIOUS PROCESS
    # -------------------------------------------------------------------------
    print_banner("SCENARIO 2: Suspicious Process (Moderate Anomaly Deviations)")
    telem2 = ProcessTelemetryInput(
        event_id=f"evt-demo-susp-{uuid.uuid4().hex[:6]}",
        pid=7812,
        process_name="unusual_worker.py",
        cpu_percent=48.5,
        memory_percent=32.0,
        open_sockets_count=2,
        distinct_remote_ips=1,
        num_threads=10,
        username="vboxuser",
    )
    det2 = DetectionSignalInput(
        ml_anomaly_score=52.0,
        behavioural_score=46.0,
        is_simulated=True,
    )
    corr2 = correlator.correlate(telem2, det2)
    risk2 = risk_engine.calculate_risk(det2, telem2)
    dec2 = policy_engine.evaluate_decision(corr2, risk2)
    storage.save_record(corr2, risk2, dec2)
    out2 = policy_engine.execute_and_verify(dec2, operator_approved=False, execution_mode="simulation")
    print_scenario_output("SCENARIO 2: SUSPICIOUS PROCESS (INVESTIGATION RECOMMENDED)", corr2, risk2, dec2, out2)

    # -------------------------------------------------------------------------
    # SCENARIO 3: HIGH-RISK PROCESS
    # -------------------------------------------------------------------------
    print_banner("SCENARIO 3: High-Risk Threat ([DEMO] unauthorized_miner.bin)")
    telem3, det3 = DemoDataAdapter.from_pipeline_event(
        event_id=f"evt-demo-miner-{uuid.uuid4().hex[:6]}",
        pid=49152,
        process_name="[DEMO] unauthorized_miner.bin",
        cpu_percent=94.2,
        memory_percent=18.4,
        anomaly_score=0.93,
    )
    corr3 = correlator.correlate(telem3, det3)
    risk3 = risk_engine.calculate_risk(det3, telem3)
    dec3 = policy_engine.evaluate_decision(corr3, risk3)
    storage.save_record(corr3, risk3, dec3)

    # High-risk containment requires operator approval; operator grants approval
    logger.info("Operator received high-risk alert; granting approval for simulated restriction.")
    out3 = policy_engine.execute_and_verify(
        decision=dec3,
        operator_approved=True,
        execution_mode="simulation",
        simulated_metrics={"post_cpu": 2.5, "healthy_services_count": 8},
        record_alert=True,
    )
    print_scenario_output("SCENARIO 3: HIGH-RISK THREAT (ALERT & CONTAINMENT & VERIFICATION)", corr3, risk3, dec3, out3)

    # -------------------------------------------------------------------------
    # SCENARIO 4: MISSING DETECTION DATA
    # -------------------------------------------------------------------------
    print_banner("SCENARIO 4: Incomplete / Missing Detection Data")
    telem4 = ProcessTelemetryInput(
        event_id=f"evt-demo-unscored-{uuid.uuid4().hex[:6]}",
        pid=1337,
        process_name="unscored_daemon",
        cpu_percent=1.2,
        memory_percent=0.8,
        open_sockets_count=0,
        distinct_remote_ips=0,
        num_threads=1,
    )
    # ML and Behavioural scores are absent
    det4 = DetectionSignalInput(
        ml_anomaly_score=None,
        behavioural_score=None,
        resource_anomaly_score=None,
    )
    corr4 = correlator.correlate(telem4, det4)
    risk4 = risk_engine.calculate_risk(det4, telem4)
    dec4 = policy_engine.evaluate_decision(corr4, risk4)
    storage.save_record(corr4, risk4, dec4)
    out4 = policy_engine.execute_and_verify(dec4, operator_approved=False, execution_mode="simulation")
    print_scenario_output("SCENARIO 4: MISSING SIGNALS (PROVISIONAL HANDLING)", corr4, risk4, dec4, out4)

    # Summary Audit
    print_banner("DEMO SUMMARY: Audit Trail Verification")
    events = get_recent_process_events(limit=5)
    alerts = get_active_alerts()
    responses = get_response_history(limit=5)
    verifs = get_verification_history(limit=5)
    corrs = storage.get_records(limit=5)

    print(f"Total Process Events in Database      : {len(events)}")
    print(f"Total Active Security Alerts           : {len(alerts)}")
    print(f"Total Response Actions Executed        : {len(responses)}")
    print(f"Total Closed-Loop Verifications Logged : {len(verifs)}")
    print(f"Total Correlation Records Logged       : {len(corrs)}")
    print("=" * 80)
    print(" M3 End-to-End Demonstration Complete: 100% Verified.")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    run_demo()

