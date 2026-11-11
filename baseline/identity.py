"""
baseline/identity.py
====================
ECHO — Process Identity Specification & Resolution.

Distinguishes between:
1. Process-Type Identity:
   Stable identity based on process execution metadata (process_name, executable path or
   executable identity, and execution username). Represents the class or executable definition
   of a process across system invocations.
   Format: `type::<username>::<process_name>` or `type::<username>::<process_name>::<exe_hash>`

2. Process-Instance Identity:
   Ephemeral, unique instance representing a single execution of a process on a host.
   Incorporates PID and process creation time (or start window) to prevent PID recycling
   from erroneously conflating previous and new process executions.
   Format: `inst::<username>::<process_name>::<pid>::<start_time>`
"""

from dataclasses import dataclass
from typing import Optional, Dict, Any


def build_process_type_identity(
    process_name: str,
    username: Optional[str] = None,
    executable_identity: Optional[str] = None,
) -> str:
    """
    Build a canonical, stable process-type identifier.

    Parameters
    ----------
    process_name : str
        Name of the binary/executable (e.g. 'nginx', 'python').
    username : Optional[str]
        User executing the process (e.g. 'root', 'vboxuser').
    executable_identity : Optional[str]
        Optional executable path or package identifier.

    Returns
    -------
    str
        Canonical process-type identity.
    """
    u = (username or "unknown").strip().lower()
    p = (process_name or "unknown").strip()
    if executable_identity and executable_identity.strip() and executable_identity.strip() != "unknown":
        return f"type::{u}::{p}::{executable_identity.strip()}"
    return f"type::{u}::{p}"


def build_process_instance_identity(
    process_name: str,
    pid: int,
    process_start_time: Optional[str] = None,
    username: Optional[str] = None,
) -> str:
    """
    Build a unique process-instance identifier that protects against PID reuse.

    Parameters
    ----------
    process_name : str
        Process name.
    pid : int
        Process identifier.
    process_start_time : Optional[str]
        ISO-8601 UTC process creation time.
    username : Optional[str]
        Process owner.

    Returns
    -------
    str
        Canonical process-instance identity.
    """
    u = (username or "unknown").strip().lower()
    p = (process_name or "unknown").strip()
    st = (process_start_time or "unknown_start").strip()
    return f"inst::{u}::{p}::{pid}::{st}"
