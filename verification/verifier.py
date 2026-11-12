"""
verification/verifier.py
========================
ECHO — M4: Closed-Loop Verification Subsystem
Author: Mayank (M4)

Performs post-response validation to establish a closed-loop security posture:
1. Verifies if the defensive response succeeded.
2. Checks whether the target process anomaly/threat is contained.
3. Detects collateral impact (e.g. unintended disruptions to unrelated processes).
4. Persists verification outcomes into verification_results table.

Verification Outcomes
---------------------
Three distinct outcomes are possible and must remain distinguishable:

  success      — The action succeeded AND explicit post-action telemetry was
                 provided AND that telemetry showed no collateral impact.

  failure      — The action itself failed or was skipped before execution, OR
                 collateral impact was positively detected in the provided
                 telemetry.

  inconclusive — The action succeeded but no post-action telemetry was
                 provided.  Missing evidence must never be treated as proof of
                 successful containment.  Recorded as success=False,
                 collateral_impact="unknown".

Simulation Label
----------------
When verification relies on simulated_metrics (not real host telemetry),
the details string explicitly states this.  Simulated results must never be
presented as evidence of real host containment.

Collateral Impact Values
------------------------
  "none"     — Telemetry was provided and confirmed no collateral impact.
  "detected" — Telemetry was provided and confirmed collateral impact.
  "unknown"  — No telemetry was provided, or the action never ran.
               Missing evidence is NOT equivalent to "none".
"""

import uuid
import logging
from typing import Dict, Any, Optional
from pathlib import Path

from dashboard.database import (
    DB_PATH,
    insert_verification_result,
    _get_connection,
    _utc_now,
)

logger = logging.getLogger(__name__)

# Returned in the dict under key "verification_outcome" for caller convenience.
# Not stored in the database — the database already encodes this via
# (success, collateral_impact) as a tuple.
OUTCOME_SUCCESS       = "success"
OUTCOME_FAILURE       = "failure"
OUTCOME_INCONCLUSIVE  = "inconclusive"


class ClosedLoopVerifier:
    """
    Closed-Loop Verification Engine.
    """

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path

    def _lookup_action(self, action_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve response action with its associated process event."""
        conn = _get_connection(self.db_path)
        try:
            sql = """
                SELECT
                    ra.action_id, ra.event_id, ra.timestamp, ra.action_type,
                    ra.execution_mode, ra.approval_status, ra.result, ra.error_message,
                    pe.process_name, pe.pid, pe.cpu_percent, pe.memory_percent, pe.risk_level
                FROM response_actions ra
                JOIN process_events pe ON ra.event_id = pe.event_id
                WHERE ra.action_id = ?
            """
            row = conn.execute(sql, (action_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def verify_response(
        self,
        action_id: str,
        simulated_metrics: Optional[Dict[str, Any]] = None,
        verification_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Perform closed-loop verification of an executed response action.

        Parameters
        ----------
        action_id : str
            Response action identifier to verify.
        simulated_metrics : Optional[Dict[str, Any]]
            Post-action telemetry supplied by the caller for verification
            analysis.  MUST be explicitly provided to achieve a successful
            verification outcome.  If None or omitted, the verification is
            recorded as INCONCLUSIVE — missing evidence is never interpreted
            as proof of successful containment.
            Recognised keys:
              - "collateral_impact_detected" (bool): True if collateral found.
              - "unrelated_processes_impacted" (int): Count of affected procs.
        verification_id : Optional[str]
            Verification ID; auto-generated with UUID4 if omitted.

        Returns
        -------
        Dict[str, Any]
            Verification record with:
              - verification_id, action_id, timestamp
              - success (bool)
              - details (str)
              - collateral_impact: "none" | "detected" | "unknown"
              - verification_outcome: "success" | "failure" | "inconclusive"
        """
        if not verification_id:
            verification_id = f"vrf-{uuid.uuid4().hex[:12]}"

        action = self._lookup_action(action_id)
        if not action:
            error_msg = f"Cannot verify response: Action '{action_id}' not found in database."
            logger.error(error_msg)
            raise ValueError(error_msg)

        timestamp = _utc_now()
        action_result = action["result"]
        action_type = action["action_type"]
        execution_mode = action["execution_mode"]
        pid = action["pid"]
        pname = action["process_name"]

        # ------------------------------------------------------------------
        # Branch 1: Action itself did not succeed (failed or skipped).
        # We have no information about whether anything changed on the host,
        # therefore collateral_impact must be "unknown", not "none".
        # ------------------------------------------------------------------
        if action_result != "success":
            success = False
            collateral_impact = "unknown"   # No action ran → no evidence either way
            outcome = OUTCOME_FAILURE
            details = (
                f"Verification failed: Target action '{action_id}' ({action_type}) "
                f"had result='{action_result}' and was not executed. "
                f"Collateral impact cannot be assessed (recorded as 'unknown')."
            )
            if action.get("error_message"):
                details += f" Reason: {action['error_message']}"

            insert_verification_result(
                verification_id=verification_id,
                action_id=action_id,
                success=success,
                details=details,
                collateral_impact=collateral_impact,
                timestamp=timestamp,
                db_path=self.db_path,
            )
            return {
                "verification_id": verification_id,
                "action_id": action_id,
                "success": success,
                "details": details,
                "collateral_impact": collateral_impact,
                "verification_outcome": outcome,
                "timestamp": timestamp,
            }

        # ------------------------------------------------------------------
        # Branch 2: Action succeeded but NO post-action telemetry provided.
        # Missing evidence must be recorded as INCONCLUSIVE, never as success.
        # ------------------------------------------------------------------
        if simulated_metrics is None:
            success = False
            collateral_impact = "unknown"
            outcome = OUTCOME_INCONCLUSIVE
            details = (
                f"Verification inconclusive: Action '{action_id}' ({action_type}) "
                f"on process '{pname}' (PID {pid}) reported success, but no "
                f"post-action telemetry was provided. Containment cannot be "
                f"confirmed and collateral impact cannot be assessed. "
                f"Provide simulated_metrics to complete verification."
            )
            logger.warning(
                "Verification %s is inconclusive: action %s succeeded but "
                "no post-action metrics were provided.",
                verification_id, action_id,
            )
            insert_verification_result(
                verification_id=verification_id,
                action_id=action_id,
                success=success,
                details=details,
                collateral_impact=collateral_impact,
                timestamp=timestamp,
                db_path=self.db_path,
            )
            return {
                "verification_id": verification_id,
                "action_id": action_id,
                "success": success,
                "details": details,
                "collateral_impact": collateral_impact,
                "verification_outcome": outcome,
                "timestamp": timestamp,
            }

        # ------------------------------------------------------------------
        # Branch 3: Action succeeded AND post-action telemetry was provided.
        # Evaluate the telemetry to determine success or collateral failure.
        # Label the evidence as simulated when execution_mode == "simulation".
        # ------------------------------------------------------------------
        collateral_detected = bool(simulated_metrics.get("collateral_impact_detected", False))
        unrelated_affected = int(simulated_metrics.get("unrelated_processes_impacted", 0))

        # Simulation label — simulated results must be clearly distinguished
        # from real host telemetry.
        is_simulated = (execution_mode == "simulation")
        evidence_label = "[SIMULATED EVIDENCE] " if is_simulated else "[LIVE EVIDENCE] "

        if collateral_detected or unrelated_affected > 0:
            collateral_impact = "detected"
            success = False
            outcome = OUTCOME_FAILURE
            details = (
                f"{evidence_label}Verification failed: collateral impact detected. "
                f"{unrelated_affected} unrelated service(s) were impacted while "
                f"executing {action_type} on '{pname}' (PID {pid}). "
                f"{'Note: Collateral data is from simulation, not real host.' if is_simulated else ''}"
            )
        else:
            collateral_impact = "none"
            success = True
            outcome = OUTCOME_SUCCESS
            details = (
                f"{evidence_label}Verification passed: {action_type} for process "
                f"'{pname}' (PID {pid}) completed in {execution_mode} mode. "
                f"Provided telemetry shows zero collateral impact on adjacent "
                f"processes. "
                f"{'Note: This result is based on simulated telemetry, not real host state.' if is_simulated else ''}"
            )

        insert_verification_result(
            verification_id=verification_id,
            action_id=action_id,
            success=success,
            details=details,
            collateral_impact=collateral_impact,
            timestamp=timestamp,
            db_path=self.db_path,
        )

        return {
            "verification_id": verification_id,
            "action_id": action_id,
            "success": success,
            "details": details,
            "collateral_impact": collateral_impact,
            "verification_outcome": outcome,
            "timestamp": timestamp,
        }
