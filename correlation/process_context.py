"""
correlation/process_context.py
==============================
ECHO — M3: Process Context Manager.

Maintains bounded temporal and behavioral context for processes across observation cycles.
Features:
- Distinguishes process-type from process-instance to safely handle PID recycling.
- Tracks historical risk scores, consecutive anomalies, and risk trends.
- Enforces strict memory bounds via configurable LRU / max capacity limits.
- Detects repeated suspicious behaviour and escalates context flags.
"""

import collections
import logging
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone

from correlation.models import RiskScoreResult, ProcessTelemetryInput

# Try importing from baseline.identity; fallback to pure Python if baseline/__init__.py fails
try:
    from baseline.identity import (
        build_process_type_identity,
        build_process_instance_identity,
    )
except (ImportError, ModuleNotFoundError):
    def build_process_type_identity(
        process_name: str,
        username: Optional[str] = None,
        executable_identity: Optional[str] = None,
    ) -> str:
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
        u = (username or "unknown").strip().lower()
        p = (process_name or "unknown").strip()
        st = (process_start_time or "unknown_start").strip()
        return f"inst::{u}::{p}::{pid}::{st}"

logger = logging.getLogger(__name__)


@dataclass
class ProcessInstanceRecord:
    """
    Historical behavioral tracking record for an individual process execution instance.
    """
    instance_identity: str
    process_type_identity: str
    pid: int
    process_name: str
    username: Optional[str]
    process_start_time: str
    first_seen_timestamp: str
    last_seen_timestamp: str
    observation_count: int = 1
    anomaly_count: int = 0
    consecutive_high_risk_count: int = 0
    recent_risk_scores: collections.deque = field(default_factory=lambda: collections.deque(maxlen=20))
    recent_risk_levels: collections.deque = field(default_factory=lambda: collections.deque(maxlen=20))
    is_active: bool = True

    def record_observation(
        self,
        risk_result: RiskScoreResult,
        timestamp: str,
    ) -> None:
        """Update instance record with a new observation cycle."""
        self.observation_count += 1
        self.last_seen_timestamp = timestamp
        self.recent_risk_scores.append(risk_result.risk_score)
        self.recent_risk_levels.append(risk_result.risk_level)

        if risk_result.risk_level in {"medium", "high"}:
            self.anomaly_count += 1

        if risk_result.risk_level == "high":
            self.consecutive_high_risk_count += 1
        else:
            self.consecutive_high_risk_count = 0

    def get_risk_trend(self) -> str:
        """
        Determine whether risk is increasing, decreasing, or stable.
        Returns: 'increasing', 'decreasing', 'stable', or 'insufficient_data'.
        """
        if len(self.recent_risk_scores) < 3:
            return "insufficient_data"
        scores = list(self.recent_risk_scores)
        diff = scores[-1] - scores[0]
        if diff > 15.0:
            return "increasing"
        elif diff < -15.0:
            return "decreasing"
        return "stable"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "instance_identity": self.instance_identity,
            "process_type_identity": self.process_type_identity,
            "pid": self.pid,
            "process_name": self.process_name,
            "username": self.username,
            "process_start_time": self.process_start_time,
            "first_seen_timestamp": self.first_seen_timestamp,
            "last_seen_timestamp": self.last_seen_timestamp,
            "observation_count": self.observation_count,
            "anomaly_count": self.anomaly_count,
            "consecutive_high_risk_count": self.consecutive_high_risk_count,
            "recent_risk_scores": list(self.recent_risk_scores),
            "recent_risk_levels": list(self.recent_risk_levels),
            "risk_trend": self.get_risk_trend(),
            "is_active": self.is_active,
        }


class ProcessContextManager:
    """
    Thread-safe, memory-bounded manager for process history and context.
    """

    def __init__(
        self,
        max_processes: int = 1000,
        max_history_per_instance: int = 20,
    ):
        self.max_processes = max_processes
        self.max_history_per_instance = max_history_per_instance
        # Map instance_identity -> ProcessInstanceRecord (OrderedDict for LRU eviction)
        self._instances: collections.OrderedDict[str, ProcessInstanceRecord] = collections.OrderedDict()
        # Map PID -> latest instance_identity (for PID reuse tracking)
        self._pid_to_instance: Dict[int, str] = {}

    def get_or_create_instance(
        self,
        telemetry: ProcessTelemetryInput,
    ) -> Tuple[ProcessInstanceRecord, bool]:
        """
        Resolve or create a ProcessInstanceRecord, detecting PID reuse when applicable.

        Returns
        -------
        Tuple[ProcessInstanceRecord, bool]
            (instance_record, is_new_instance)
        """
        pid = telemetry.pid
        pname = telemetry.process_name
        user = telemetry.username
        start_time = telemetry.process_start_time or telemetry.timestamp
        obs_time = telemetry.timestamp

        type_id = build_process_type_identity(
            process_name=pname,
            username=user,
        )
        instance_id = build_process_instance_identity(
            process_name=pname,
            pid=pid,
            process_start_time=start_time,
            username=user,
        )

        # Check PID reuse: if PID is already tracked under a DIFFERENT instance identity
        if pid in self._pid_to_instance:
            prev_instance_id = self._pid_to_instance[pid]
            if prev_instance_id != instance_id:
                # PID has been recycled by OS! Mark the old instance as terminated
                if prev_instance_id in self._instances:
                    self._instances[prev_instance_id].is_active = False
                    logger.debug(
                        "Detected PID %d recycling: retiring old instance %s for new instance %s",
                        pid, prev_instance_id, instance_id
                    )

        if instance_id in self._instances:
            # Move to end for LRU recency
            self._instances.move_to_end(instance_id)
            record = self._instances[instance_id]
            self._pid_to_instance[pid] = instance_id
            return record, False

        # Evict oldest instance if at capacity
        if len(self._instances) >= self.max_processes:
            evicted_id, _ = self._instances.popitem(last=False)
            logger.debug("ProcessContextManager reached capacity; evicted oldest instance %s", evicted_id)

        # Create new record
        record = ProcessInstanceRecord(
            instance_identity=instance_id,
            process_type_identity=type_id,
            pid=pid,
            process_name=pname,
            username=user,
            process_start_time=start_time,
            first_seen_timestamp=obs_time,
            last_seen_timestamp=obs_time,
            observation_count=1,
            anomaly_count=0,
            consecutive_high_risk_count=0,
            recent_risk_scores=collections.deque(maxlen=self.max_history_per_instance),
            recent_risk_levels=collections.deque(maxlen=self.max_history_per_instance),
            is_active=True,
        )
        self._instances[instance_id] = record
        self._pid_to_instance[pid] = instance_id
        return record, True

    def update_context(
        self,
        telemetry: ProcessTelemetryInput,
        risk_result: RiskScoreResult,
    ) -> ProcessInstanceRecord:
        """
        Record a new observation and risk score in the process context.
        """
        record, is_new = self.get_or_create_instance(telemetry)
        if not is_new:
            record.record_observation(risk_result, telemetry.timestamp)
        else:
            # First observation
            record.recent_risk_scores.append(risk_result.risk_score)
            record.recent_risk_levels.append(risk_result.risk_level)
            if risk_result.risk_level in {"medium", "high"}:
                record.anomaly_count = 1
            if risk_result.risk_level == "high":
                record.consecutive_high_risk_count = 1

        return record

    def get_instance(self, instance_identity: str) -> Optional[ProcessInstanceRecord]:
        """Retrieve instance record by ID."""
        return self._instances.get(instance_identity)

    def get_instance_by_pid(self, pid: int) -> Optional[ProcessInstanceRecord]:
        """Retrieve the active instance record for a given PID."""
        inst_id = self._pid_to_instance.get(pid)
        return self._instances.get(inst_id) if inst_id else None

    def active_instances_count(self) -> int:
        """Count currently tracked instances."""
        return len(self._instances)

    def clear(self) -> None:
        """Clear all context cache."""
        self._instances.clear()
        self._pid_to_instance.clear()
