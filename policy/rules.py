"""
policy/rules.py
===============
ECHO — M3: Security Policy Rules & Decision Logic.

Implements decision rules mapping composite risk scores, process context,
and system safety allowlists into structured response recommendations.

Policy Matrix:
- LOW (0-29):
    Recommended Action: 'log_only'
    Approval Required : False
    Behavior          : Allow process, log baseline telemetry.
- MEDIUM (30-69):
    Recommended Action: 'investigate'
    Approval Required : False
    Behavior          : Flag suspicious activity, snapshot process telemetry.
- HIGH (70-100):
    Recommended Action: 'alert' (or 'simulate_restriction' if containment needed)
    Approval Required : True for containment, False for notification.
    Behavior          : Raise security alert; operator approval required before restriction.

Safety Invariants:
- Protected system binaries (systemd, sshd, python, etc.) and system PIDs (0, 1, self)
  are strictly protected from containment actions.
- Missing or provisional data falls back to safe observational actions ('investigate' or 'log_only').
- Zero automatic termination or unapproved host restriction.
"""

import logging
from typing import Dict, Any, Optional, Tuple
from correlation.models import (
    CorrelatedSignal,
    RiskScoreResult,
    PolicyDecision,
)
from response.safety import is_protected_process

logger = logging.getLogger(__name__)


class PolicyRulesConfig:
    """
    Configurable parameters for policy rules.
    """
    def __init__(
        self,
        auto_contain_high_risk: bool = True,
        escalate_repeated_anomalies: bool = True,
    ):
        self.auto_contain_high_risk = auto_contain_high_risk
        self.escalate_repeated_anomalies = escalate_repeated_anomalies


class PolicyRules:
    """
    Evaluates correlated risk signals against security policies.
    """

    def __init__(self, config: Optional[PolicyRulesConfig] = None):
        self.config = config or PolicyRulesConfig()

    def evaluate(
        self,
        correlated: CorrelatedSignal,
        risk: RiskScoreResult,
    ) -> PolicyDecision:
        """
        Evaluate policy for a correlated signal and risk score.

        Parameters
        ----------
        correlated : CorrelatedSignal
            Correlated telemetry and context.
        risk : RiskScoreResult
            Computed composite risk score and level.

        Returns
        -------
        PolicyDecision
            Structured decision with recommended action and approval requirements.
        """
        pid = correlated.telemetry.pid
        pname = correlated.telemetry.process_name
        event_id = correlated.telemetry.event_id
        score = risk.risk_score
        level = risk.risk_level

        # 1. System Safety Check (Protected PIDs and system binaries)
        is_protected, protect_reason = is_protected_process(pid, pname)

        if is_protected:
            # Protected processes must NEVER be restricted or terminated
            if level == "high":
                action = "alert"
                req_approval = False
                reason = f"Protected process '{pname}' (PID {pid}) flagged high risk ({score:.1f}). Restrictive containment prohibited; operator alert raised: {protect_reason}"
            elif level == "medium":
                action = "log_only"
                req_approval = False
                reason = f"Protected process '{pname}' (PID {pid}) moderate deviation ({score:.1f}). Logged for security review: {protect_reason}"
            else:
                action = "log_only"
                req_approval = False
                reason = f"Protected process '{pname}' operating normally ({score:.1f})."

            return PolicyDecision(
                decision_id=f"dec-prot-{correlated.correlation_id[-8:]}",
                event_id=event_id,
                pid=pid,
                process_name=pname,
                process_identity=correlated.process_type_identity,
                risk_score=score,
                risk_level=level,
                recommended_action=action,
                requires_approval=req_approval,
                is_protected=True,
                reason=reason,
                context_metadata={
                    "protection_reason": protect_reason,
                    "is_provisional": risk.is_provisional,
                },
            )

        # 2. Missing / Provisional Data Fallback Rule
        if risk.is_provisional:
            missing_str = ", ".join(risk.missing_signals)
            if level == "high":
                action = "alert"
                req_approval = True
                reason = f"High provisional risk ({score:.1f}) with missing signals [{missing_str}]. Alert raised; manual inspection required."
            elif level == "medium":
                action = "investigate"
                req_approval = False
                reason = f"Moderate provisional risk ({score:.1f}) with missing signals [{missing_str}]. Telemetry snapshot recommended."
            else:
                action = "log_only"
                req_approval = False
                reason = f"Telemetry received with missing signals [{missing_str}]. Low risk; logging observation."

            return PolicyDecision(
                decision_id=f"dec-prov-{correlated.correlation_id[-8:]}",
                event_id=event_id,
                pid=pid,
                process_name=pname,
                process_identity=correlated.process_type_identity,
                risk_score=score,
                risk_level=level,
                recommended_action=action,
                requires_approval=req_approval,
                is_protected=False,
                reason=reason,
                context_metadata={
                    "is_provisional": True,
                    "missing_signals": risk.missing_signals,
                },
            )

        # 3. Standard Policy Evaluation by Risk Level
        if level == "high":
            # High-risk non-protected process
            if self.config.auto_contain_high_risk:
                action = "simulate_restriction"
                req_approval = True # Containment ALWAYS requires operator approval
                reason = (
                    f"CRITICAL: High composite risk score ({score:.1f} >= 70.0). "
                    f"Recommended simulated containment (cgroup throttling / network sandbox). "
                    f"Operator approval required. {risk.explanation}"
                )
            else:
                action = "alert"
                req_approval = False
                reason = f"High composite risk ({score:.1f}). Security alert generated. {risk.explanation}"

        elif level == "medium":
            action = "investigate"
            req_approval = False
            # Check repeated offender escalation
            if self.config.escalate_repeated_anomalies and correlated.is_repeated_anomaly:
                reason = (
                    f"SUSPICIOUS (ESCALATED): Process '{pname}' has repeated anomalies "
                    f"({correlated.prior_anomaly_count} prior). Score={score:.1f}. In-depth investigation recommended."
                )
            elif correlated.parent_is_suspicious:
                reason = (
                    f"SUSPICIOUS (HIERARCHY): Process '{pname}' spawned by anomalous parent PID. "
                    f"Score={score:.1f}. Process tree inspection recommended."
                )
            else:
                reason = f"Suspicious activity detected (Score={score:.1f}). Telemetry snapshot recommended. {risk.explanation}"

        else: # low risk
            action = "log_only"
            req_approval = False
            reason = f"Normal operational telemetry (Score={score:.1f} < 30.0). Process allowed and logged."

        return PolicyDecision(
            decision_id=f"dec-{correlated.correlation_id[-8:]}",
            event_id=event_id,
            pid=pid,
            process_name=pname,
            process_identity=correlated.process_type_identity,
            risk_score=score,
            risk_level=level,
            recommended_action=action,
            requires_approval=req_approval,
            is_protected=False,
            reason=reason,
            context_metadata={
                "prior_anomalies": correlated.prior_anomaly_count,
                "repeated_anomaly": correlated.is_repeated_anomaly,
                "parent_suspicious": correlated.parent_is_suspicious,
            },
        )

