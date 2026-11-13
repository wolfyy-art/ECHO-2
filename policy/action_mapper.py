"""
policy/action_mapper.py
=======================
ECHO — M3: Action Mapper & M4 Response Bridge.

Translates high-level M3 PolicyDecisions into concrete, validated parameters
for the M4 ResponseEngine (response/engine.py).
Ensures:
- Respects simulation-only mode defaults (no destructive host actions).
- Translates approval requirements into valid approval statuses ('approved' vs 'pending').
- Guarantees valid action types ('alert', 'investigate', 'simulate_restriction', 'log_only', 'notify_operator').
- Passes exact foreign-key event IDs to maintain referential integrity.
"""

import logging
from typing import Dict, Any, Optional
from correlation.models import PolicyDecision
from response.engine import ResponseEngine

logger = logging.getLogger(__name__)

# Valid actions accepted by M4 response/engine.py
VALID_M4_ACTIONS = {
    "alert",
    "investigate",
    "simulate_restriction",
    "log_only",
    "notify_operator",
}


class ActionMapper:
    """
    Translates PolicyDecision to M4 ResponseEngine parameters.
    """

    @staticmethod
    def map_to_response_args(
        decision: PolicyDecision,
        operator_approved: bool = False,
        execution_mode: str = "simulation",
    ) -> Dict[str, Any]:
        """
        Build parameter dictionary ready for ResponseEngine.execute_response().

        Parameters
        ----------
        decision : PolicyDecision
            M3 policy decision.
        operator_approved : bool
            Whether human operator has explicitly granted approval for containment actions.
        execution_mode : str
            'simulation' (default) or 'live'.

        Returns
        -------
        Dict[str, Any]
            Kwargs for ResponseEngine.execute_response.
        """
        action_type = decision.recommended_action
        if action_type not in VALID_M4_ACTIONS:
            logger.warning("Unrecognised action '%s'; falling back to 'log_only'", action_type)
            action_type = "log_only"

        # Determine approval status:
        # If approval is required by policy, only mark approved if operator explicitly consented
        if decision.requires_approval:
            approval_status = "approved" if operator_approved else "pending"
        else:
            approval_status = "approved"

        return {
            "event_id": decision.event_id,
            "action_type": action_type,
            "execution_mode": execution_mode,
            "approval_status": approval_status,
        }

    @staticmethod
    def execute_mapped_response(
        decision: PolicyDecision,
        response_engine: ResponseEngine,
        operator_approved: bool = False,
        execution_mode: str = "simulation",
    ) -> Dict[str, Any]:
        """
        Translate policy decision and execute via M4 ResponseEngine.

        Returns
        -------
        Dict[str, Any]
            Action record returned by ResponseEngine.
        """
        args = ActionMapper.map_to_response_args(
            decision=decision,
            operator_approved=operator_approved,
            execution_mode=execution_mode,
        )

        logger.info(
            "Dispatching decision %s to M4: action=%s, mode=%s, approval=%s",
            decision.decision_id, args["action_type"], args["execution_mode"], args["approval_status"]
        )

        return response_engine.execute_response(**args)

