"""
collector/models.py
===================
ECHO — Data Models for Process and Network Telemetry.
"""

from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any


@dataclass
class ProcessTelemetry:
    """
    Detailed telemetry snapshot of an individual Linux process.
    """
    pid: int
    ppid: int
    process_name: str
    username: Optional[str]
    exe: Optional[str]
    cmdline: Optional[str]
    cpu_percent: float
    memory_percent: float
    memory_rss: int
    num_threads: int
    process_start_time: str
    status: str
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert telemetry object to dictionary."""
        return asdict(self)


@dataclass
class NetworkTelemetry:
    """
    Socket/connection telemetry attributed to a Linux process when available.
    """
    pid: int
    local_address: str
    local_port: Optional[int]
    remote_address: Optional[str]
    remote_port: Optional[int]
    status: str
    protocol: str
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert network object to dictionary."""
        return asdict(self)


@dataclass
class CollectionStats:
    """
    Statistics collected during a telemetry collection cycle.
    """
    cycle_index: int
    processes_observed: int
    records_collected: int
    network_records_collected: int
    errors_encountered: int
    cycle_duration_seconds: float
