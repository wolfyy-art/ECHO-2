"""
detection/isolation_forest.py
=============================
ECHO — Isolation Forest Anomaly Detector.

Implements an unsupervised ensemble of Isolation Trees using Scikit-Learn.
Consumes approved numerical process feature vectors and maps decision function
scores into a normalized [0.0, 1.0] anomaly score.
"""

import math
import logging
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Tuple, Union
from pathlib import Path
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)

# Approved numerical features for anomaly detection (13 dimensions)
APPROVED_FEATURE_COLUMNS = [
    "cpu_mean",
    "cpu_max",
    "cpu_std",
    "memory_mean",
    "memory_max",
    "memory_rss_mean",
    "num_threads_mean",
    "num_threads_max",
    "open_sockets_count",
    "distinct_remote_ips",
    "sample_count",
    "cpu_mem_ratio",
    "socket_thread_ratio",
]


@dataclass
class IsolationForestConfig:
    """
    Configuration parameters for Isolation Forest model.
    """
    n_estimators: int = 100
    random_state: int = 42
    max_samples: Union[str, int] = "auto"
    contamination: float = 0.05

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ProcessIsolationForest:
    """
    Unsupervised process anomaly detector using Isolation Forest.
    """

    def __init__(self, config: Optional[IsolationForestConfig] = None):
        self.config = config or IsolationForestConfig()
        self.model = IsolationForest(
            n_estimators=self.config.n_estimators,
            random_state=self.config.random_state,
            max_samples=self.config.max_samples,
            contamination=self.config.contamination,
            n_jobs=-1,
        )
        self.is_fitted = False
        self.feature_columns = list(APPROVED_FEATURE_COLUMNS)
        self.score_offset_ = 0.0

    def prepare_feature_matrix(self, df: pd.DataFrame) -> Tuple[np.ndarray, List[int]]:
        """
        Extract and validate numerical feature matrix.
        Missing or NaN values are identified and preserved without silent 0.0 conversion.

        Returns
        -------
        Tuple[np.ndarray, List[int]]
            (feature_matrix, valid_row_indices)
        """
        missing_cols = [c for c in self.feature_columns if c not in df.columns]
        if missing_cols:
            raise ValueError(f"DataFrame is missing required feature columns: {missing_cols}")

        sub = df[self.feature_columns].copy()

        # Check for NaN / invalid entries
        valid_mask = ~sub.isna().any(axis=1)
        valid_indices = df.index[valid_mask].tolist()

        if not valid_mask.all():
            n_invalid = int((~valid_mask).sum())
            logger.warning("Found %d rows with missing feature values. Rows will be handled explicitly.", n_invalid)

        X = sub.loc[valid_mask].to_numpy(dtype=float)
        return X, valid_indices

    def fit(self, df_train: pd.DataFrame) -> "ProcessIsolationForest":
        """
        Fit Isolation Forest ensemble on training feature DataFrame.

        Parameters
        ----------
        df_train : pd.DataFrame
            Windowed training telemetry.

        Returns
        -------
        self
        """
        X_train, valid_idx = self.prepare_feature_matrix(df_train)
        if len(X_train) == 0:
            raise ValueError("Cannot train Isolation Forest: no valid training observations available.")

        self.model.fit(X_train)
        self.is_fitted = True

        # Store the decision offset (threshold quantile) defined by contamination
        self.score_offset_ = float(self.model.offset_)
        logger.info(
            "Fitted Isolation Forest on %d observations (features=%d, contamination=%.2f, offset=%.4f).",
            len(X_train), X_train.shape[1], self.config.contamination, self.score_offset_,
        )
        return self

    def score_samples(self, df: pd.DataFrame) -> np.ndarray:
        """
        Compute continuous normalized anomaly scores in [0.0, 1.0].

        By scikit-learn convention:
        - decision_function(X) returns (score_offset - raw_anomaly_score).
        - Higher decision_function means more normal; lower (negative) means more anomalous.
        We convert this monotonically to an anomaly score:
          S = 1.0 / (1.0 + exp(decision_function))
        where S in (0, 1), with higher values indicating greater abnormality.
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before calling score_samples.")

        X, valid_idx = self.prepare_feature_matrix(df)
        if len(X) == 0:
            return np.array([])

        raw_decisions = self.model.decision_function(X)

        # Sigmoid conversion: decision=0 (decision threshold) maps to S ≈ 0.50
        # Negative decisions map to S > 0.50 (anomalous), positive to S < 0.50 (normal)
        normalized_scores = 1.0 / (1.0 + np.exp(raw_decisions))
        return np.round(normalized_scores, 4)

    def predict_labels(self, df: pd.DataFrame) -> np.ndarray:
        """
        Predict binary labels: -1 for outlier/anomaly, 1 for inlier/normal.
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before calling predict_labels.")

        X, _ = self.prepare_feature_matrix(df)
        if len(X) == 0:
            return np.array([])
        return self.model.predict(X)

    def save(self, filepath: Path) -> Path:
        """Serialize model artifact to disk."""
        if not self.is_fitted:
            raise RuntimeError("Cannot save unfitted model.")
        p = Path(filepath)
        p.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, str(p))
        logger.info("Saved model artifact to: %s", p)
        return p

    @staticmethod
    def load(filepath: Path) -> "ProcessIsolationForest":
        """Deserialize model artifact from disk."""
        p = Path(filepath)
        if not p.exists():
            raise FileNotFoundError(f"Model artifact not found at: {p}")
        obj = joblib.load(str(p))
        if not isinstance(obj, ProcessIsolationForest):
            raise TypeError(f"Loaded object is not a ProcessIsolationForest instance: {type(obj)}")
        return obj
