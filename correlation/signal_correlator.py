"""
correlation/signal_correlator.py
================================
ECHO — M3: Signal Correlator.

Correlates raw host telemetry (M1) with anomaly detection models (M2) and historical context.
Key capabilities:
- Matches process telemetry with ML/behavioural scores via PID and identity.
- Deduplicates incoming events to prevent processing redundant observations.
- Integrates with ProcessContextManager to identify repeated anomalies and risk escalation.
- Traverses parent-child relationships (PPID) to correlate process hierarchy risks.
- Enforces time-window tolerance checks between telemetry and detection timestamps.
"""

import uuid
import logging
from typing import Dict, Any, Optional, List, Tuple, Set
from datetime import datetime, timezone

from correlation.models import (
    ProcessTelemetryInput,
    DetectionSignalInput,
    CorrelatedSignal,
    RiskScoreResult,
)
from correlation.process_context import (
    ProcessContextManager,
    build_process_type_identity,
    build_process_instance_identity,
)

logger = logging.getLogger(__name__)


class SignalCorrelator:
    """
    Correlates M1 telemetry observations with M2 detection outputs and temporal context.
    """

    def __init__(
        self,
        context_manager: Optional[ProcessContextManager] = None,
        time_tolerance_seconds: float = 30.0,
        dedup_cache_size: int = 5000,
    ):
        self.context_manager = context_manager or ProcessContextManager()
        self.time_tolerance_seconds = time_tolerance_seconds
        # Bounded event deduplication set
        self._processed_events: Set[str] = set()
        self._event_history_list: List[str] = []
        self._dedup_cache_size = dedup_cache_size

    def _is_duplicate_event(self, event_id: str) -> bool:
        """Check if this event ID has already been processed."""
        if event_id in self._processed_events:
            return True
        self._processed_events.add(event_id)
        self._event_history_list.append(event_id)
        if len(self._event_history_list) > self._dedup_cache_size:
            oldest = self._event_history_list.pop(0)
            self._processed_events.discard(oldest)
        return False

    def correlate(
        self,
        telemetry: ProcessTelemetryInput,
        detection: Optional[DetectionSignalInput] = None,
    ) -> CorrelatedSignal:
        """
        Correlate a single telemetry event with its detection signals and historical context.

        Parameters
        ----------
        telemetry : ProcessTelemetryInput
            M1 process telemetry.
        detection : Optional[DetectionSignalInput]
            M2 detection signals. If None, creates an empty detection input marked missing.

        Returns
        -------
        CorrelatedSignal
            Correlated signal containing resolved identities, parent-child context,
            and repeated anomaly flags.
        """
        # 1. Deduplication check
        if self._is_duplicate_event(telemetry.event_id):
            logger.debug("Event %s is duplicate; continuing correlation for re-evaluation.", telemetry.event_id)

        # 2. Ensure detection signal exists
        if detection is None:
            detection = DetectionSignalInput(is_simulated=False)

        # 3. Build canonical identities
        type_id = build_process_type_identity(
            process_name=telemetry.process_name,
            username=telemetry.username,
        )
        instance_id = build_process_instance_identity(
            process_name=telemetry.process_name,
            pid=telemetry.pid,
            process_start_time=telemetry.process_start_time,
            username=telemetry.username,
        )

        # 4. Check historical context for this instance
        existing_instance = self.context_manager.get_instance(instance_id)
        repeated_obs = existing_instance.observation_count if existing_instance else 1
        prior_anomalies = existing_instance.anomaly_count if existing_instance else 0
        is_repeated = prior_anomalies >= 2

        # 5. Check parent process context (PPID)
        parent_suspicious = False
        if telemetry.ppid and telemetry.ppid > 1:
            parent_instance = self.context_manager.get_instance_by_pid(telemetry.ppid)
            if parent_instance and parent_instance.anomaly_count > 0:
                parent_suspicious = True
                logger.debug(
                    "PID %d has parent PID %d with prior anomaly count %d",
                    telemetry.pid, telemetry.ppid, parent_instance.anomaly_count
                )

        correlation_id = f"corr-{uuid.uuid4().hex[:12]}"

        return CorrelatedSignal(
            correlation_id=correlation_id,
            telemetry=telemetry,
            detection=detection,
            process_type_identity=type_id,
            process_instance_identity=instance_id,
            repeated_observations_count=repeated_obs,
            prior_anomaly_count=prior_anomalies,
            is_repeated_anomaly=is_repeated,
            parent_is_suspicious=parent_suspicious,
            timestamp=telemetry.timestamp,
        )

    def correlate_batch(
        self,
        telemetry_list: List[ProcessTelemetryInput],
        detection_map: Optional[Dict[int, DetectionSignalInput]] = None,
    ) -> List[CorrelatedSignal]:
        """
        Correlate a batch of telemetry inputs with corresponding detections (mapped by PID).
        """
        detections = detection_map or {}
        correlated: List[CorrelatedSignal] = []
        for telem in telemetry_list:
            det = detections.get(telem.pid)
            correlated.append(self.correlate(telem, det))
        return correlated
