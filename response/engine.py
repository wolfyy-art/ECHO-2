"""
response/engine.py
==================
ECHO — M4: Safe Response Execution Engine
Author: Mayank (M4)

Executes defensive and containment actions decided by the M3 policy engine.
Guarantees:
- Default execution mode is 'simulation' (no OS process signals or firewall changes).
- Enforces pre-execution safety rules via SafetyChecker.
- Persists all executed actions to the SQLite database (response_actions table).
"""

import uuid
import logging
from typing import Dict, Any, Optional, Tuple
from pathlib import Path

from dashboard.database import (
    DB_PATH,
    insert_response_action,
    _get_connection,
    _utc_now,
)
from response.safety import SafetyChecker

logger = logging.getLogger(__name__)


class ResponseEngine:
    """
    Safe Response Execution Engine for ECHO.
    """

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path

    def _lookup_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve process event metadata from the database."""
        conn = _get_connection(self.db_path)
        try:
            sql = "SELECT * FROM process_events WHERE event_id = ?"
            row = conn.execute(sql, (event_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def execute_response(
        self,
        event_id: str,
        action_type: str,
        execution_mode: str = "simulation",
        approval_status: str = "approved",
        action_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute or simulate a response action for a given process event.

        Parameters
        ----------
        event_id : str
            Parent process event ID.
        action_type : str
            One of: 'alert', 'investigate', 'simulate_restriction',
            'log_only', 'notify_operator'.
        execution_mode : str
            'simulation' (default) or 'live'.
        approval_status : str
            'pending', 'approved', or 'rejected'.
        action_id : Optional[str]
            Optional action ID; auto-generated with UUID4 if omitted.

        Returns
        -------
        Dict[str, Any]
            Action record containing action_id, result, details, etc.
        """
        if not action_id:
            action_id = f"resp-{uuid.uuid4().hex[:12]}"

        # 1. Lookup parent event
        event = self._lookup_event(event_id)
        if not event:
            error_msg = f"Cannot execute response: Event '{event_id}' not found in database."
            logger.error(error_msg)
            raise ValueError(error_msg)

        pid = event["pid"]
        process_name = event["process_name"]

        # 2. Check safety rules
        allowed, rejection_reason = SafetyChecker.validate_action(
            pid=pid,
            process_name=process_name,
            action_type=action_type,
            execution_mode=execution_mode,
            approval_status=approval_status,
        )

        timestamp = _utc_now()

        if not allowed:
            logger.warning("Response action %s blocked: %s", action_id, rejection_reason)
            result = "skipped" if approval_status == "rejected" else "failed"
            insert_response_action(
                action_id=action_id,
                event_id=event_id,
                action_type=action_type,
                execution_mode=execution_mode,
                approval_status=approval_status,
                result=result,
                error_message=rejection_reason,
                timestamp=timestamp,
                db_path=self.db_path,
            )
            return {
                "action_id": action_id,
                "event_id": event_id,
                "action_type": action_type,
                "execution_mode": execution_mode,
                "approval_status": approval_status,
                "result": result,
                "error_message": rejection_reason,
                "timestamp": timestamp,
            }

        # 3. Execute action (simulation or live)
        result = "pending"
        error_msg = None
        details = {}

        try:
            if execution_mode == "simulation":
                result, details = self._simulate_action(action_type, pid, process_name)
            else:
                # Live mode is strictly guard-railed in current phase
                result = "skipped"
                error_msg = "Live execution mode is gated; host modification not permitted in this phase."
                details = {"reason": error_msg}
        except Exception as exc:
            result = "failed"
            error_msg = str(exc)
            logger.exception("Error executing action %s: %s", action_id, exc)

        # 4. Record action in database
        insert_response_action(
            action_id=action_id,
            event_id=event_id,
            action_type=action_type,
            execution_mode=execution_mode,
            approval_status=approval_status,
            result=result,
            error_message=error_msg,
            timestamp=timestamp,
            db_path=self.db_path,
        )

        return {
            "action_id": action_id,
            "event_id": event_id,
            "action_type": action_type,
            "execution_mode": execution_mode,
            "approval_status": approval_status,
            "result": result,
            "error_message": error_msg,
            "timestamp": timestamp,
            "details": details,
        }

    def _simulate_action(self, action_type: str, pid: int, process_name: str) -> Tuple[str, Dict[str, Any]]:
        """
        Simulate defensive actions without making any actual OS modifications.
        """
        if action_type == "simulate_restriction":
            return "success", {
                "simulated_action": "network_bandwidth_throttling",
                "target_pid": pid,
                "target_process": process_name,
                "applied_cgroup_limit": "512kbit/s (simulated)",
                "firewall_rule": f"DROP TCP outbound from PID {pid} port 4444 (simulated)",
                "os_modified": False,
            }
        elif action_type == "investigate":
            return "success", {
                "simulated_action": "process_snapshot",
                "target_pid": pid,
                "target_process": process_name,
                "inspected_handles": 14,
                "active_connections": 2,
                "os_modified": False,
            }
        elif action_type == "alert":
            return "success", {
                "simulated_action": "operator_alert",
                "severity": "high",
                "target_pid": pid,
            }
        elif action_type == "notify_operator":
            return "success", {
                "simulated_action": "pager_notification",
                "channel": "security_ops_console",
            }
        elif action_type == "log_only":
            return "success", {
                "simulated_action": "audit_log_entry",
                "target_pid": pid,
            }
        else:
            return "skipped", {"reason": f"Unhandled action type: {action_type}"}
