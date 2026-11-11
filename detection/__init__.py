"""
detection/__init__.py
=====================
ECHO — Anomaly Detection Model Package.
"""

from detection.isolation_forest import (
    ProcessIsolationForest,
    IsolationForestConfig,
    APPROVED_FEATURE_COLUMNS,
)
from detection.metrics import (
    compute_spearman_rank_correlation,
    compute_top_k_jaccard_overlap,
    compute_latency_percentiles,
)
from detection.evaluation import DetectionEvaluator, ChronologicalSplit

__all__ = [
    "ProcessIsolationForest",
    "IsolationForestConfig",
    "APPROVED_FEATURE_COLUMNS",
    "compute_spearman_rank_correlation",
    "compute_top_k_jaccard_overlap",
    "compute_latency_percentiles",
    "DetectionEvaluator",
    "ChronologicalSplit",
]
