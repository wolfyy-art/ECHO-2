"""
correlation/policy.py
=====================
ECHO — Phase 7: Context-Aware Security Policy Engine
Author: Rishit (M3) & Mayank (M4)

Translates composite risk scores (R) into graduated security response actions:
- Low Risk (R < 0.35)    -> Action: 'log_only' (Continuous monitoring)
- Medium Risk (0.35-0.65)-> Action: 'investigate' (Collect forensics, raise Medium alert)
- High Risk (0.65-0.85)  -> Action: 'simulate_restriction' (Raise High alert, reversible isolation)
- Critical Risk (>=0.85) -> Action: 'simulate_restriction' / 'notify_operator' (Urgent containment)

Enforces safety constraints, execution mode safeguards (simulation default),
and checks against protected OS processes before dispatching to ResponseEngine.
"""

import logging
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional, Tuple
from pathlib import Path

from dashboard.database import (
    DB_PATH,
    insert_alert,
    _utc_now,
)
from response.safety import SafetyChecker, is_protected_process
from response.engine import ResponseEngine
from correlation.engine import CorrelatedRiskResult

logger = logging.getLogger(__name__)


@dataclass
class PolicyDecision:
    """
    Actionable security decision issued by the Policy Engine.
    """
    event_id: str
    process_name: str
    pid: int
    composite_risk_R: float
    risk_level: str
    recommended_action: str  # 'log_only', 'investigate', 'simulate_restriction', 'notify_operator'
    alert_severity: Optional[str]  # None, 'low', 'medium', 'high'
    is_action_permitted: bool
    rejection_reason: Optional[str]
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PolicyEngine:
    """
    Translates risk evaluation into proportionate, safe defensive decisions.
    """

    def __init__(
        self,
        db_path: Path = DB_PATH,
        response_engine: Optional[ResponseEngine] = None,
        default_execution_mode: str = "simulation",
    ):
        self.db_path = Path(db_path)
        self.response_engine = response_engine or ResponseEngine(db_path=self.db_path)
        self.execution_mode = default_execution_mode
        self.safety_checker = SafetyChecker()

    def evaluate_policy(
        self,
        event_id: str,
        risk_result: CorrelatedRiskResult,
        operator_approved: bool = True,
    ) -> PolicyDecision:
        """
        Evaluate a correlated risk result and determine the appropriate action.
        """
        R = risk_result.composite_risk_R
        pname = risk_result.process_name
        pid = risk_result.pid

        # 1. Determine Graduated Action and Severity Ladder
        if R >= 0.85:
            rec_action = "simulate_restriction"
            alert_sev = "high"
            rationale = "Critical multi-signal threat: immediate containment recommended."
        elif R >= 0.65:
            rec_action = "simulate_restriction"
            alert_sev = "high"
            rationale = "Elevated risk exceeding threshold: reversible restriction recommended."
        elif R >= 0.35:
            rec_action = "investigate"
            alert_sev = "medium"
            rationale = "Moderate deviation detected: forensic logging and investigation initiated."
        else:
            rec_action = "log_only"
            alert_sev = None
            rationale = "Process behavior remains within baseline tolerances."

        # 2. Check Safety Allowlist Constraints
        is_protected, reason = is_protected_process(pid=pid, process_name=pname)
        if is_protected:
            permitted = False
            rejection = f"Safety Block: {reason}"
            rec_action = "log_only"
            alert_sev = "low" if alert_sev else None
            rationale = f"Action constrained by OS safety policy: {reason}"
        else:
            permitted = True
            rejection = None

        return PolicyDecision(
            event_id=event_id,
            process_name=pname,
            pid=pid,
            composite_risk_R=R,
            risk_level=risk_result.risk_level,
            recommended_action=rec_action,
            alert_severity=alert_sev,
            is_action_permitted=permitted,
            rejection_reason=rejection,
            rationale=rationale,
        )

    def dispatch_decision(
        self,
        decision: PolicyDecision,
        approval_status: str = "approved",
    ) -> Dict[str, Any]:
        """
        Execute the policy decision: optionally raise an alert and invoke the response engine.
        """
        result_payload: Dict[str, Any] = {
            "decision": decision.to_dict(),
            "alert_id": None,
            "response_action": None,
        }

        # Raise Alert if severity is defined
        if decision.alert_severity:
            import uuid
            alert_id = f"alt-{uuid.uuid4().hex[:12]}"
            insert_alert(
                alert_id=alert_id,
                event_id=decision.event_id,
                severity=decision.alert_severity,
                reason=decision.rationale,
                db_path=self.db_path,
            )
            result_payload["alert_id"] = alert_id
            logger.info("Raised %s-severity alert: %s", decision.alert_severity.upper(), alert_id)

        # Dispatch to Response Engine if action is permitted and not just log_only
        if decision.is_action_permitted and decision.recommended_action != "log_only":
            action_record = self.response_engine.execute_response(
                event_id=decision.event_id,
                action_type=decision.recommended_action,
                execution_mode=self.execution_mode,
                approval_status=approval_status,
            )
            result_payload["response_action"] = action_record
            logger.info(
                "Dispatched response action: %s -> %s",
                decision.recommended_action,
                action_record.get("result"),
            )

        return result_payload

