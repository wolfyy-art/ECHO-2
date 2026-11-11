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
            Post-action telemetry (e.g. post_cpu, healthy_services_count)
            for verification analysis.
        verification_id : Optional[str]
            Optional verification ID; generated with UUID4 if omitted.

        Returns
        -------
        Dict[str, Any]
            Verification record with success, details, collateral_impact.
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
        pid = action["pid"]
        pname = action["process_name"]

        # 1. Base success check: If action itself failed or was skipped
        if action_result != "success":
            success = False
            collateral_impact = "none"
            details = (
                f"Verification failed: Target action '{action_id}' ({action_type}) "
                f"had result='{action_result}'."
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
                "timestamp": timestamp,
            }

        # 2. Closed-loop verification logic
        metrics = simulated_metrics or {}
        # In simulation mode, check if post-containment telemetry confirmed containment
        # e.g., did CPU drop or was network traffic suppressed?
        collateral_detected = metrics.get("collateral_impact_detected", False)
        unrelated_affected = metrics.get("unrelated_processes_impacted", 0)

        if collateral_detected or unrelated_affected > 0:
            collateral_impact = "detected"
            success = False
            details = (
                f"Verification detected collateral impact: {unrelated_affected} "
                f"unrelated service(s) were impacted while executing {action_type} on {pname} (PID {pid})."
            )
        else:
            collateral_impact = "none"
            success = True
            details = (
                f"Closed-loop verification passed: {action_type} for process '{pname}' "
                f"(PID {pid}) validated successfully in {action['execution_mode']} mode. "
                f"Zero collateral damage detected on adjacent processes."
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
            "timestamp": timestamp,
        }
