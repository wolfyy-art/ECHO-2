"""
correlation/engine.py
=====================
ECHO — Phase 6: Multi-Signal Correlation & Composite Risk Scoring Engine
Author: Rishit (M3) & Suhani (M2)

Combines:
1. M: Machine Learning Anomaly Score from Isolation Forest (detection/).
2. A: Per-Process Statistical Deviation Score from MAD baselines (baseline/).
3. Q: Contextual Rule-based Evidence Score (execution path, parent process, sockets).

Formula:
    R = w_m * M + w_a * A + w_r * Q

Properties:
- Normalized risk score: R in [0.0, 1.0].
- Transparent & explainable: audit trail decomposes the contribution of each signal.
- Independent weighting: avoids double-counting correlated features.
"""

import math
import logging
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

import numpy as np
import pandas as pd

from dashboard.database import DB_PATH
from baseline.comparator import BaselineComparator
from detection.isolation_forest import ProcessIsolationForest

logger = logging.getLogger(__name__)


@dataclass
class CorrelationWeights:
    """
    Weights for multi-signal risk formulation.
    Must satisfy w_m + w_a + w_r == 1.0.
    """
    w_m: float = 0.40  # ML anomaly score weight
    w_a: float = 0.40  # Statistical MAD score weight
    w_r: float = 0.20  # Contextual rules score weight

    def __post_init__(self):
        total = self.w_m + self.w_a + self.w_r
        if not math.isclose(total, 1.0, rel_tol=1e-3):
            raise ValueError(f"Correlation weights must sum to 1.0, got {total:.4f}")


@dataclass
class CorrelatedRiskResult:
    """
    Structured outcome of a multi-signal correlation evaluation.
    """
    process_name: str
    pid: int
    ml_score_M: float
    mad_score_A: float
    rule_score_Q: float
    composite_risk_R: float
    risk_level: str  # 'low', 'medium', 'high'
    triggered_rules: List[str]
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ContextRuleEngine:
    """
    Evaluates contextual heuristics (Q score in [0.0, 1.0]).
    Inspects execution paths, parent-child relationships, and network topology.
    """

    # Suspicious binary execution paths commonly seen in exploits/malware
    SUSPICIOUS_PATHS = ("/tmp", "/dev/shm", "/var/tmp", "/run/user", "temp")

    # Interactive shells spawned unexpectedly
    SUSPICIOUS_SHELLS = ("sh", "bash", "zsh", "dash", "powershell.exe", "cmd.exe")

    # Parent processes that should rarely spawn network or shell tools directly
    SUSPICIOUS_PARENTS = ("nginx", "apache2", "httpd", "mysqld", "postgres")

    @classmethod
    def evaluate(
        cls,
        process_name: str,
        exe_path: Optional[str] = None,
        parent_name: Optional[str] = None,
        open_sockets: int = 0,
        distinct_remote_ips: int = 0,
    ) -> Tuple[float, List[str]]:
        """
        Evaluate context rules and return a normalized Q score in [0.0, 1.0].
        """
        triggered: List[str] = []
        score = 0.0

        pname = (process_name or "").lower()
        parent = (parent_name or "").lower()
        path = (exe_path or "").lower()

        # Rule 1: Binary running from volatile / world-writable directories
        for susp_path in cls.SUSPICIOUS_PATHS:
            if susp_path in path:
                score += 0.35
                triggered.append(f"Execution from volatile/writable directory: '{susp_path}'")
                break

        # Rule 2: Web server or database spawning interactive shell
        if parent in cls.SUSPICIOUS_PARENTS and pname in cls.SUSPICIOUS_SHELLS:
            score += 0.40
            triggered.append(f"Web/DB daemon '{parent}' spawned interactive shell '{pname}'")

        # Rule 3: Extreme socket / remote endpoint burst
        if open_sockets >= 40:
            score += 0.25
            triggered.append(f"Abnormally high concurrent open sockets: {open_sockets}")
        elif distinct_remote_ips >= 20:
            score += 0.20
            triggered.append(f"High number of distinct remote endpoints: {distinct_remote_ips}")

        # Rule 4: Suspicious process naming conventions (hidden dotfile binaries, miner names)
        if pname.startswith(".") or "miner" in pname or "xmr" in pname:
            score += 0.30
            triggered.append(f"Suspicious executable name pattern: '{process_name}'")

        normalized_q = min(1.0, round(score, 4))
        return normalized_q, triggered


class CorrelationEngine:
    """
    Multi-Signal Correlation Engine for ECHO.
    Computes: R = w_m * M + w_a * A + w_r * Q
    """

    def __init__(
        self,
        db_path: Path = DB_PATH,
        model: Optional[ProcessIsolationForest] = None,
        weights: Optional[CorrelationWeights] = None,
    ):
        self.db_path = Path(db_path)
        self.model = model
        self.weights = weights or CorrelationWeights()
        self.comparator = BaselineComparator(db_path=self.db_path)
        self.rule_engine = ContextRuleEngine()

    def correlate_process_event(
        self,
        event_dict: Dict[str, Any],
        df_feature_row: Optional[pd.DataFrame] = None,
        exe_path: Optional[str] = None,
        parent_name: Optional[str] = None,
    ) -> CorrelatedRiskResult:
        """
        Perform complete correlation across ML, MAD, and contextual rules.

        Parameters
        ----------
        event_dict : Dict[str, Any]
            Process observation dictionary containing process_name, pid, cpu_percent, etc.
        df_feature_row : Optional[pd.DataFrame]
            1-row DataFrame containing the 13 approved features for ML scoring.
        exe_path : Optional[str]
            Executable path.
        parent_name : Optional[str]
            Parent process executable name.

        Returns
        -------
        CorrelatedRiskResult
            Composite score and diagnostic audit trail.
        """
        pname = event_dict.get("process_name", "unknown")
        pid = int(event_dict.get("pid", 0))

        # 1. Statistical Baseline Anomaly Score (A)
        try:
            comp_result = self.comparator.compare_window(event_dict)
            score_A = float(comp_result.get("combined_anomaly_score", 0.0))
        except Exception as exc:
            logger.debug("Failed to compute MAD score for %s (PID %d): %s", pname, pid, exc)
            score_A = 0.0

        # 2. Machine Learning Anomaly Score (M)
        score_M = 0.0
        if self.model and self.model.is_fitted and df_feature_row is not None and not df_feature_row.empty:
            try:
                scores = self.model.score_samples(df_feature_row)
                if len(scores) > 0:
                    score_M = float(scores[0])
            except Exception as exc:
                logger.debug("Failed to compute ML score for %s: %s", pname, exc)
                score_M = 0.0

        # 3. Contextual Rule Score (Q)
        open_sockets = int(event_dict.get("open_sockets_count", 0))
        remote_ips = int(event_dict.get("distinct_remote_ips", 0))
        score_Q, triggered_rules = self.rule_engine.evaluate(
            process_name=pname,
            exe_path=exe_path,
            parent_name=parent_name,
            open_sockets=open_sockets,
            distinct_remote_ips=remote_ips,
        )

        # 4. Composite Risk Calculation: R = w_m * M + w_a * A + w_r * Q
        R = (
            self.weights.w_m * score_M
            + self.weights.w_a * score_A
            + self.weights.w_r * score_Q
        )
        R = min(1.0, max(0.0, round(float(R), 4)))

        # 5. Categorize Risk Level
        if R >= 0.65:
            risk_level = "high"
        elif R >= 0.35:
            risk_level = "medium"
        else:
            risk_level = "low"

        # 6. Build Human-Readable Explanation
        explanation = (
            f"Composite Risk R={R:.2f} [{risk_level.upper()}] for {pname} (PID {pid}): "
            f"ML={score_M:.2f} (w={self.weights.w_m}), "
            f"MAD={score_A:.2f} (w={self.weights.w_a}), "
            f"Rules={score_Q:.2f} (w={self.weights.w_r}). "
            f"Triggers: {triggered_rules if triggered_rules else 'None'}"
        )

        return CorrelatedRiskResult(
            process_name=pname,
            pid=pid,
            ml_score_M=score_M,
            mad_score_A=score_A,
            rule_score_Q=score_Q,
            composite_risk_R=R,
            risk_level=risk_level,
            triggered_rules=triggered_rules,
            explanation=explanation,
        )
