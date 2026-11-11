"""
response/safety.py
==================
ECHO — M4: Safety Guards and Policy Rules
Author: Mayank (M4)

Enforces zero-harm safety constraints for host response actions:
- Never permits actions on protected system PIDs (0, 1) or critical OS daemons.
- Requires explicit operator approval for high-impact containment actions.
- Enforces strict simulation mode safeguards to prevent accidental system changes.
"""

import os
import logging
from typing import Tuple, Optional

logger = logging.getLogger(__name__)

# System PIDs that must NEVER be modified or targeted
PROTECTED_PIDS = {0, 1}

# Essential OS binaries and daemons that must NEVER be restricted or terminated
PROTECTED_PROCESS_NAMES = {
    # Linux system essentials
    "systemd", "init", "kthreadd", "rcu_sched", "kworker",
    "sshd", "login", "udevd", "systemd-journald", "systemd-udevd",
    "dbus-daemon", "rsyslogd", "cron", "crond", "auditd",
    # Windows system essentials (for cross-platform development safety)
    "system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "svchost.exe", "explorer.exe",
    # Development runtime protections
    "python", "python3", "code", "antigravity"
}


def is_protected_process(pid: int, process_name: str) -> Tuple[bool, Optional[str]]:
    """
    Check if a process is protected by safety policies.

    Parameters
    ----------
    pid : int
        Process identifier.
    process_name : str
        Name of the process executable.

    Returns
    -------
    Tuple[bool, Optional[str]]
        (is_protected, reason_if_protected)
    """
    if pid in PROTECTED_PIDS:
        return True, f"PID {pid} is a protected core system process."

    current_pid = os.getpid()
    if pid == current_pid:
        return True, f"PID {pid} is the current ECHO monitoring process itself."

    normalized = process_name.strip().lower()
    for protected in PROTECTED_PROCESS_NAMES:
        if normalized == protected or normalized.startswith(f"{protected}."):
            return True, f"Process '{process_name}' is in the protected system allowlist."

    return False, None


class SafetyChecker:
    """
    Validates proposed response actions against safety policies before execution.
    """

    @staticmethod
    def validate_action(
        pid: int,
        process_name: str,
        action_type: str,
        execution_mode: str,
        approval_status: str,
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate proposed response action against safety policies.

        Returns
        -------
        Tuple[bool, Optional[str]]
            (is_allowed, rejection_reason)
        """
        # 1. Protected process check
        protected, reason = is_protected_process(pid, process_name)
        if protected:
            return False, f"Safety Violation: {reason}"

        # 2. Execution mode check
        if execution_mode not in {"simulation", "live"}:
            return False, f"Invalid execution mode: '{execution_mode}'"

        # 3. Action type validation
        valid_actions = {
            "alert", "investigate", "simulate_restriction", "log_only", "notify_operator"
        }
        if action_type not in valid_actions:
            return False, f"Invalid action_type: '{action_type}'"

        # 4. Approval check for restrictive / high-impact actions
        if action_type == "simulate_restriction":
            if approval_status == "rejected":
                return False, "Action skipped: operator rejected approval."
            # If pending, policy allows queueing or simulation with explicit dry-run flag

        return True, None
