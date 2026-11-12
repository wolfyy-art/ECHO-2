"""
correlation package
===================
ECHO — M3: Correlation Engine and Risk Scoring Subsystem.
"""

from correlation.models import (
    ProcessTelemetryInput,
    DetectionSignalInput,
    RiskScoreResult,
    CorrelatedSignal,
    PolicyDecision,
)
from correlation.risk_engine import (
    RiskEngine,
    RiskEngineConfig,
)
from correlation.process_context import (
    ProcessContextManager,
    ProcessInstanceRecord,
)
from correlation.signal_correlator import SignalCorrelator
from correlation.adapters import DemoDataAdapter
from correlation.storage import CorrelationStorage

__all__ = [
    "ProcessTelemetryInput",
    "DetectionSignalInput",
    "RiskScoreResult",
    "CorrelatedSignal",
    "PolicyDecision",
    "RiskEngine",
    "RiskEngineConfig",
    "ProcessContextManager",
    "ProcessInstanceRecord",
    "SignalCorrelator",
    "DemoDataAdapter",
    "CorrelationStorage",
]
