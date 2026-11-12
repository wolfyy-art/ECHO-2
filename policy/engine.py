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
        # 1. Optionally insert alert into alerts table for medium/high events
        alert_record = None
        if record_alert and decision.risk_level in {"medium", "high"}:
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
                # If parent event doesn't exist yet in process_events table, log warning
                logger.warning("Could not persist alert to database (parent event may not be committed): %s", exc)

        # 2. Dispatch response action via M4 ResponseEngine
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

