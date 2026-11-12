"""
correlation/risk_engine.py
==========================
ECHO — M3: Risk Scoring Engine.

Calculates multi-factor composite risk scores for processes:
    R = (w_m * M) + (w_a * A) + (w_q * Q)

Where:
    M = ML anomaly score (Isolation Forest, normalized to 0-100)
    A = Behavioural anomaly score (MAD baseline deviation, normalized to 0-100)
    Q = Resource / network activity anomaly score (context-aware, normalized to 0-100)
    R = Composite risk score (0-100)

Risk Classifications:
    0  to 29 -> 'low'
    30 to 69 -> 'medium'
    70 to 100 -> 'high'

Guarantees:
- Input score validation (rejects NaN, Inf, < 0, > 100).
- Configurable weights with automatic normalization.
- Safe missing-signal strategies (never silently zeros out missing signals).
- Context-aware resource anomaly estimation (high CPU alone is not marked anomalous).
"""

import math
import logging
from typing import Optional, Dict, Any, List, Tuple
from correlation.models import DetectionSignalInput, ProcessTelemetryInput, RiskScoreResult

logger = logging.getLogger(__name__)


class RiskEngineConfig:
    """
    Configuration for the Risk Scoring Engine.
    """
    def __init__(
        self,
        weight_ml: float = 0.40,
        weight_behavioural: float = 0.35,
        weight_resource: float = 0.25,
        low_threshold: float = 30.0,
        high_threshold: float = 70.0,
        missing_strategy: str = "provisional_rescale",
    ):
        """
        Parameters
        ----------
        weight_ml : float
            Weight for ML anomaly score (M). Default 0.40.
        weight_behavioural : float
            Weight for Behavioural MAD score (A). Default 0.35.
        weight_resource : float
            Weight for Resource/Network score (Q). Default 0.25.
        low_threshold : float
            Threshold below which risk is 'low'. Default 30.0.
        high_threshold : float
            Threshold at or above which risk is 'high'. Default 70.0.
        missing_strategy : str
            Strategy for missing signals: 'provisional_rescale' (default) or 'strict_insufficient'.
        """
        total_w = weight_ml + weight_behavioural + weight_resource
        if total_w <= 0.0:
            raise ValueError("Sum of weights must be greater than 0.")
        if low_threshold < 0 or high_threshold > 100 or low_threshold >= high_threshold:
            raise ValueError("Invalid thresholds: 0 <= low_threshold < high_threshold <= 100 required.")
        if missing_strategy not in {"provisional_rescale", "strict_insufficient"}:
            raise ValueError(f"Unknown missing_strategy: {missing_strategy}")

        # Normalize weights so they sum to 1.0
        self.w_ml = weight_ml / total_w
        self.w_behavioural = weight_behavioural / total_w
        self.w_resource = weight_resource / total_w
        self.low_threshold = low_threshold
        self.high_threshold = high_threshold
        self.missing_strategy = missing_strategy

    def to_dict(self) -> Dict[str, Any]:
        return {
            "weight_ml": round(self.w_ml, 4),
            "weight_behavioural": round(self.w_behavioural, 4),
            "weight_resource": round(self.w_resource, 4),
            "low_threshold": self.low_threshold,
            "high_threshold": self.high_threshold,
            "missing_strategy": self.missing_strategy,
        }


class RiskEngine:
    """
    Calculates multi-factor risk scores and classifies risk levels.
    """

    def __init__(self, config: Optional[RiskEngineConfig] = None):
        self.config = config or RiskEngineConfig()

    @staticmethod
    def normalize_score(score: Optional[float], signal_name: str) -> Optional[float]:
        """
        Normalize input score to 0.0 - 100.0 scale.
        Accepts:
            None -> None
            0.0 to 1.0 -> multiplied by 100.0
            0.0 to 100.0 -> preserved
        Rejects:
            < 0, > 100, NaN, Infinity -> raises ValueError
        """
        if score is None:
            return None

        if not isinstance(score, (int, float)):
            raise ValueError(f"Score for '{signal_name}' must be numeric or None, got {type(score).__name__}")

        if math.isnan(score) or math.isinf(score):
            raise ValueError(f"Score for '{signal_name}' cannot be NaN or Infinity.")

        if score < 0.0:
            raise ValueError(f"Score for '{signal_name}' cannot be negative (got {score}).")

        # If score is given in [0.0, 1.0] scale, convert to [0.0, 100.0]
        # Note: exactly 1.0 is treated as 100.0 if explicitly from probability/ML output
        if 0.0 <= score <= 1.0:
            return round(score * 100.0, 2)
        elif 1.0 < score <= 100.0:
            return round(float(score), 2)
        else:
            raise ValueError(f"Score for '{signal_name}' exceeds maximum allowed 100.0 (got {score}).")

    def classify_risk(self, risk_score: Optional[float]) -> str:
        """
        Map a numerical risk score (0-100) to a risk level:
        0 - 29   -> 'low'
        30 - 69  -> 'medium'
        70 - 100 -> 'high'
        None     -> 'unknown'
        """
        if risk_score is None:
            return "unknown"
        if risk_score < self.config.low_threshold:
            return "low"
        elif risk_score < self.config.high_threshold:
            return "medium"
        else:
            return "high"

    def estimate_resource_anomaly(
        self,
        telemetry: ProcessTelemetryInput,
    ) -> float:
        """
        Context-aware resource & network anomaly score (Q) in [0.0, 100.0].
        
        Important:
        - High CPU alone does NOT imply dangerous activity (e.g. compilation, rendering).
        - Spikes in CPU or memory are combined with network socket activity and thread counts.
        - Abnormal pattern: High compute + multiple open sockets + external IPs + high thread churn.
        """
        cpu = max(0.0, min(100.0, float(telemetry.cpu_percent)))
        mem = max(0.0, min(100.0, float(telemetry.memory_percent)))
        sockets = max(0, int(telemetry.open_sockets_count))
        remote_ips = max(0, int(telemetry.distinct_remote_ips))
        threads = max(1, int(telemetry.num_threads))

        # Base compute load (0 to 30 points)
        compute_load = (0.6 * cpu + 0.4 * mem) * 0.30

        # Network exposure (0 to 45 points)
        # Sockets with remote connections indicate active network communication
        net_score = 0.0
        if sockets > 0:
            net_score += min(20.0, sockets * 4.0)
        if remote_ips > 0:
            net_score += min(25.0, remote_ips * 8.0)

        # Thread anomaly (0 to 25 points)
        thread_score = 0.0
        if threads > 32:
            thread_score = min(25.0, (threads - 32) * 0.5)

        # Contextual multiplier:
        # If high CPU is present alongside network activity, the suspicion increases
        suspicion = compute_load + net_score + thread_score
        return round(min(100.0, max(0.0, suspicion)), 2)

    def calculate_risk(
        self,
        detection: DetectionSignalInput,
        telemetry: Optional[ProcessTelemetryInput] = None,
    ) -> RiskScoreResult:
        """
        Calculate composite risk score R from detection signals and optional telemetry.

        Parameters
        ----------
        detection : DetectionSignalInput
            Signals from M2 (ML anomaly, behavioural score, resource score).
        telemetry : Optional[ProcessTelemetryInput]
            Optional M1 telemetry to contextually compute resource score if omitted.

        Returns
        -------
        RiskScoreResult
            Comprehensive score result with breakdown and weights used.
        """
        m_norm = self.normalize_score(detection.ml_anomaly_score, "ml_anomaly_score")
        a_norm = self.normalize_score(detection.behavioural_score, "behavioural_score")
        q_norm = self.normalize_score(detection.resource_anomaly_score, "resource_anomaly_score")

        # If resource score was not provided, but telemetry is available, contextually estimate it
        if q_norm is None and telemetry is not None:
            q_norm = self.estimate_resource_anomaly(telemetry)

        # Track missing signals
        missing: List[str] = []
        if m_norm is None:
            missing.append("ML anomaly score (M)")
        if a_norm is None:
            missing.append("Behavioural anomaly score (A)")
        if q_norm is None:
            missing.append("Resource/network anomaly score (Q)")

        # Case 1: All signals are missing
        if len(missing) == 3:
            return RiskScoreResult(
                risk_score=0.0,
                risk_level="unknown",
                ml_score_normalized=None,
                behavioural_score_normalized=None,
                resource_score_normalized=None,
                weights_used=self.config.to_dict(),
                is_provisional=True,
                missing_signals=missing,
                explanation="No anomaly signals available. Assessment is provisional with risk level 'unknown'.",
            )

        # Case 2: Strict missing strategy requested and signals are missing
        if missing and self.config.missing_strategy == "strict_insufficient":
            return RiskScoreResult(
                risk_score=0.0,
                risk_level="unknown",
                ml_score_normalized=m_norm,
                behavioural_score_normalized=a_norm,
                resource_score_normalized=q_norm,
                weights_used=self.config.to_dict(),
                is_provisional=True,
                missing_signals=missing,
                explanation=f"Strict policy: Missing critical signals [{', '.join(missing)}]. Assessment marked unknown.",
            )

        # Case 3: Provisional rescale (re-weights available signals proportionally)
        available_weights: Dict[str, float] = {}
        contributions: Dict[str, float] = {}

        if m_norm is not None:
            available_weights["M"] = self.config.w_ml
        if a_norm is not None:
            available_weights["A"] = self.config.w_behavioural
        if q_norm is not None:
            available_weights["Q"] = self.config.w_resource

        sum_avail = sum(available_weights.values())
        if sum_avail <= 0.0:
            raise RuntimeError("Internal error: sum of available weights is non-positive.")

        effective_weights = {k: v / sum_avail for k, v in available_weights.items()}

        composite_risk = 0.0
        if m_norm is not None:
            contrib = effective_weights["M"] * m_norm
            composite_risk += contrib
            contributions["M"] = contrib
        if a_norm is not None:
            contrib = effective_weights["A"] * a_norm
            composite_risk += contrib
            contributions["A"] = contrib
        if q_norm is not None:
            contrib = effective_weights["Q"] * q_norm
            composite_risk += contrib
            contributions["Q"] = contrib

        composite_risk = round(min(100.0, max(0.0, composite_risk)), 2)
        risk_level = self.classify_risk(composite_risk)
        is_provisional = len(missing) > 0

        # Construct explanation
        parts = []
        if m_norm is not None:
            parts.append(f"ML={m_norm:.1f} (w={effective_weights['M']:.2f})")
        if a_norm is not None:
            parts.append(f"Behavioural={a_norm:.1f} (w={effective_weights['A']:.2f})")
        if q_norm is not None:
            parts.append(f"Resource/Net={q_norm:.1f} (w={effective_weights['Q']:.2f})")

        explanation = f"Calculated R={composite_risk:.1f} [{risk_level.upper()}] from {', '.join(parts)}."
        if is_provisional:
            explanation += f" Note: Provisional assessment due to missing: {', '.join(missing)}."

        return RiskScoreResult(
            risk_score=composite_risk,
            risk_level=risk_level,
            ml_score_normalized=m_norm,
            behavioural_score_normalized=a_norm,
            resource_score_normalized=q_norm,
            weights_used={k: round(v, 4) for k, v in effective_weights.items()},
            is_provisional=is_provisional,
            missing_signals=missing,
            explanation=explanation,
        )

