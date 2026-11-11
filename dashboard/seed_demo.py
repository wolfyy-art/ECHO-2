"""
dashboard/seed_demo.py
======================
ECHO — M4: Demo / Seed Data Loader
Author : Mayank (M4)

Purpose
-------
Inserts a small set of clearly synthetic, demo-only records into the
ECHO database so that dashboards and tests have realistic-looking data
to display immediately after cloning the repository.

IMPORTANT SAFETY NOTICE
-----------------------
* Every record inserted by this script is SYNTHETIC — it does NOT
  represent any real process that was ever running on any machine.
* No OS-level action has been taken. No process has been terminated,
  no network rule has been changed, and no firewall has been touched.
* The script is safe to run multiple times IF you clear the database
  first (just delete data/echo.db and re-run init_database()).

Usage
-----
    cd echo-project
    python dashboard/seed_demo.py
"""

import sys
import logging
from pathlib import Path
from datetime import datetime, timezone, timedelta

# Allow importing database.py from the dashboard/ package without installing it.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dashboard.database import (
    init_database,
    insert_process_event,
    insert_alert,
    insert_response_action,
    insert_verification_result,
)

# Show INFO-level messages so the operator can watch progress.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helper — generate a UTC timestamp N minutes in the past
# ---------------------------------------------------------------------------

def _past(minutes: int) -> str:
    """Return an ISO-8601 UTC timestamp N minutes before now."""
    t = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    return t.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


# ---------------------------------------------------------------------------
# Synthetic demo records
# ---------------------------------------------------------------------------
# IDs are deliberately readable strings rather than random UUIDs so that
# they are easy to spot in the database and in test output.

DEMO_EVENTS = [
    # Normal browser activity — low risk, no alert
    {
        "event_id":           "demo-evt-001",
        "pid":                4521,
        "process_name":       "firefox",
        "process_start_time": _past(60),
        "cpu_percent":        3.2,
        "memory_percent":     5.8,
        "risk_level":         "low",
        "anomaly_score":      0.04,
        "timestamp":          _past(59),
    },
    # Normal terminal activity — low risk, no alert
    {
        "event_id":           "demo-evt-002",
        "pid":                7834,
        "process_name":       "bash",
        "process_start_time": _past(45),
        "cpu_percent":        0.1,
        "memory_percent":     0.3,
        "risk_level":         "low",
        "anomaly_score":      0.02,
        "timestamp":          _past(44),
    },
    # Suspicious process — high CPU, unknown parent, medium risk
    {
        "event_id":           "demo-evt-003",
        "pid":                13007,
        "process_name":       "[DEMO] crypto_miner_sim",
        "process_start_time": _past(30),
        "cpu_percent":        91.4,
        "memory_percent":     12.7,
        "risk_level":         "high",
        "anomaly_score":      0.93,
        "timestamp":          _past(29),
    },
]

DEMO_ALERTS = [
    # High-severity alert for the suspicious process
    {
        "alert_id":  "demo-alert-001",
        "event_id":  "demo-evt-003",
        "severity":  "high",
        "reason":    (
            "[DEMO DATA] Anomaly score 0.93 exceeds threshold 0.80. "
            "Process '[DEMO] crypto_miner_sim' (PID 13007) shows CPU usage of 91.4%% "
            "with no recognised parent process. Flagged by M2 anomaly detector."
        ),
        "status":    "open",
        "timestamp": _past(28),
    },
]

DEMO_RESPONSE_ACTIONS = [
    # Simulated restriction — NOTE: no actual OS action was performed
    {
        "action_id":       "demo-action-001",
        "event_id":        "demo-evt-003",
        "action_type":     "simulate_restriction",
        "execution_mode":  "simulation",
        "approval_status": "approved",
        "result":          "success",
        "error_message":   None,
        "timestamp":       _past(27),
    },
]

DEMO_VERIFICATION_RESULTS = [
    # Verification of the simulated action
    {
        "verification_id":  "demo-verify-001",
        "action_id":        "demo-action-001",
        "success":          True,
        "details":          (
            "[DEMO DATA] Post-action verification: simulated network restriction "
            "was recorded successfully. Process '[DEMO] crypto_miner_sim' (PID 13007) "
            "was NOT actually killed or blocked — this is a simulation-mode record only."
        ),
        "collateral_impact": "none",
        "timestamp":         _past(26),
    },
]


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def seed_demo_data() -> None:
    """Insert all synthetic demo records into the ECHO database."""
    logger.info("=== ECHO M4 — Demo Data Seeder ===")
    logger.info("Ensuring database schema exists ...")
    init_database()

    logger.info("Inserting %d demo process event(s) ...", len(DEMO_EVENTS))
    for evt in DEMO_EVENTS:
        insert_process_event(**evt)
        logger.info("  + process_event: %s  (%s)", evt["event_id"], evt["process_name"])

    logger.info("Inserting %d demo alert(s) ...", len(DEMO_ALERTS))
    for alr in DEMO_ALERTS:
        insert_alert(**alr)
        logger.info("  + alert: %s  (severity=%s)", alr["alert_id"], alr["severity"])

    logger.info("Inserting %d demo response action(s) ...", len(DEMO_RESPONSE_ACTIONS))
    for act in DEMO_RESPONSE_ACTIONS:
        insert_response_action(**act)
        logger.info("  + response_action: %s  (type=%s)", act["action_id"], act["action_type"])

    logger.info("Inserting %d demo verification result(s) ...", len(DEMO_VERIFICATION_RESULTS))
    for vrf in DEMO_VERIFICATION_RESULTS:
        insert_verification_result(**vrf)
        logger.info(
            "  + verification_result: %s  (success=%s)",
            vrf["verification_id"], vrf["success"],
        )

    logger.info("Demo data seeding complete.")
    logger.info(
        "REMINDER: All inserted records are synthetic. "
        "No real process was terminated and no OS-level action was performed."
    )


if __name__ == "__main__":
    seed_demo_data()
