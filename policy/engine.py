"""
policy/engine.py
================
ECHO — M3: Central Policy & Enforcement Orchestration Engine.

Orchestrates the complete decision cycle:
1. Evaluates security rules on correlated events and risk scores (PolicyRules).
2. Maps decisions to M4 Response Engine (ActionMapper).
3. Dispatches defensive responses under safe simulation mode.
4. Triggers ClosedLoopVerifier to assert zero collateral impact.
5. Emits security alerts into the central SQLite database (alerts table).
"""

import uuid
import logging
from typing import Dict, Any, Optional
from pathlib import Path

from correlation.models import (
    CorrelatedSignal,
    RiskScoreResult,
    PolicyDecision,
)
from policy.rules import PolicyRules, PolicyRulesConfig
from policy.action_mapper import ActionMapper
from response.engine import ResponseEngine
from verification.verifier import ClosedLoopVerifier
from dashboard.database import (
    DB_PATH,
    insert_alert,
    _get_connection,
)

logger = logging.getLogger(__name__)


class PolicyEngine:
    """
    Central Policy Engine for ECHO-2 M3.
    """

    def __init__(
        self,
        rules: Optional[PolicyRules] = None,
        db_path: Path = DB_PATH,
    ):
        self.rules = rules or PolicyRules()
        self.db_path = Path(db_path)
        self.response_engine = ResponseEngine(db_path=self.db_path)
        self.verifier = ClosedLoopVerifier(db_path=self.db_path)

    def evaluate_decision(
        self,
        correlated: CorrelatedSignal,
        risk: RiskScoreResult,
    ) -> PolicyDecision:
        """
        Evaluate policy rules and generate a structured PolicyDecision.
        """
        return self.rules.evaluate(correlated=correlated, risk=risk)

    def execute_and_verify(
        self,
        decision: PolicyDecision,
        operator_approved: bool = False,
        execution_mode: str = "simulation",
        simulated_metrics: Optional[Dict[str, Any]] = None,
        record_alert: bool = True,
    ) -> Dict[str, Any]:
        """
        Execute a policy decision via M4, record any required alerts, and verify containment.

        Parameters
        ----------
        decision : PolicyDecision
            M3 policy decision.
        operator_approved : bool
            Whether operator granted approval for containment.
        execution_mode : str
            'simulation' (default).
        simulated_metrics : Optional[Dict[str, Any]]
            Post-action telemetry metrics for verification analysis.
        record_alert : bool
            Whether to insert an alert in the database for medium/high risk events.

        Returns
        -------
        Dict[str, Any]
            Full lifecycle summary: decision, response_action, verification.
        """
        # 1. Coordinate with M4 contract: verify parent event exists in process_events
        conn = _get_connection(self.db_path)
        event_exists = False
        try:
            row = conn.execute("SELECT 1 FROM process_events WHERE event_id = ?", (decision.event_id,)).fetchone()
            event_exists = bool(row)
        finally:
            conn.close()

        # If parent event is missing, auto-ingest via M4's public API if telemetry metadata was passed in context
        if not event_exists and "telemetry" in decision.context_metadata:
            telem_data = decision.context_metadata["telemetry"]
            try:
                from dashboard.database import insert_process_event
                insert_process_event(
                    event_id=decision.event_id,
                    pid=decision.pid,
                    process_name=decision.process_name,
                    process_start_time=telem_data.get("process_start_time", decision.timestamp),
                    cpu_percent=float(telem_data.get("cpu_percent", 0.0)),
                    memory_percent=float(telem_data.get("memory_percent", 0.0)),
                    risk_level=decision.risk_level,
                    anomaly_score=decision.risk_score / 100.0,
                    timestamp=decision.timestamp,
                    db_path=self.db_path,
                )
                event_exists = True
                logger.info("Auto-registered parent event %s in process_events for M4 contract.", decision.event_id)
            except Exception as exc:
                logger.warning("Could not auto-register missing parent event %s: %s", decision.event_id, exc)

        # 2. Optionally insert alert into alerts table for medium/high events
        alert_record = None
        if event_exists and record_alert and decision.risk_level in {"medium", "high"}:
            alert_id = f"alrt-{uuid.uuid4().hex[:12]}"
            severity = decision.risk_level # 'medium' or 'high'
            try:
                insert_alert(
                    alert_id=alert_id,
                    event_id=decision.event_id,
                    severity=severity,
                    reason=decision.reason,
                    status="open",
                    timestamp=decision.timestamp,
                    db_path=self.db_path,
                )
                alert_record = {"alert_id": alert_id, "severity": severity, "status": "open"}
                logger.info("Recorded security alert %s for event %s", alert_id, decision.event_id)
            except Exception as exc:
                logger.warning("Could not persist alert to database: %s", exc)

        # 3. Dispatch response action via M4 ResponseEngine if parent event exists
        if not event_exists:
            err_msg = (
                f"M4 Precondition Failed: Event '{decision.event_id}' does not exist in 'process_events'. "
                f"Under M4 interface contract, telemetry must be recorded prior to response action dispatch."
            )
            logger.error(err_msg)
            return {
                "decision": decision.to_dict(),
                "alert": None,
                "response": {
                    "action_id": None,
                    "event_id": decision.event_id,
                    "result": "failed",
                    "error_message": err_msg,
                },
                "verification": None,
            }

        response_result = ActionMapper.execute_mapped_response(
            decision=decision,
            response_engine=self.response_engine,
            operator_approved=operator_approved,
            execution_mode=execution_mode,
        )

        # 3. Perform Closed-Loop Verification
        verification_result = None
        action_id = response_result.get("action_id")
        if action_id:
            try:
                verification_result = self.verifier.verify_response(
                    action_id=action_id,
                    simulated_metrics=simulated_metrics,
                )
            except Exception as exc:
                logger.warning("Closed-loop verification failed or skipped: %s", exc)

        return {
            "decision": decision.to_dict(),
            "alert": alert_record,
            "response": response_result,
            "verification": verification_result,
        }

