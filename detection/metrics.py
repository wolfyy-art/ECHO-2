"""
detection/metrics.py
====================
ECHO — Anomaly Detection Evaluation Metrics & Utilities.

Provides evaluation routines for unsupervised anomaly detection:
- Rank correlation (Spearman rho) between detectors
- Set-based top-k anomaly overlap (Jaccard index)
- Disagreement categorization
- Statistical latency profiling (mean, median, p95)
"""

import math
import time
from typing import Sequence, Dict, Any, List, Tuple, Optional
import numpy as np
import scipy.stats as stats


def compute_spearman_rank_correlation(
    scores_a: Sequence[float],
    scores_b: Sequence[float],
) -> Tuple[float, float]:
    """
    Compute Spearman rank-order correlation coefficient and p-value between two anomaly score distributions.

    Parameters
    ----------
    scores_a : Sequence[float]
        First set of continuous anomaly scores.
    scores_b : Sequence[float]
        Second set of continuous anomaly scores.

    Returns
    -------
    Tuple[float, float]
        (correlation_coefficient, p_value)
    """
    arr_a = np.asarray(scores_a, dtype=float)
    arr_b = np.asarray(scores_b, dtype=float)

    valid_mask = (~np.isnan(arr_a)) & (~np.isnan(arr_b))
    if np.sum(valid_mask) < 2:
        return 0.0, 1.0

    res = stats.spearmanr(arr_a[valid_mask], arr_b[valid_mask])
    rho = float(res.statistic) if hasattr(res, "statistic") else float(res[0])
    pval = float(res.pvalue) if hasattr(res, "pvalue") else float(res[1])

    if math.isnan(rho):
        rho = 0.0
    return round(rho, 4), round(pval, 6)


def compute_top_k_jaccard_overlap(
    scores_a: Sequence[float],
    scores_b: Sequence[float],
    top_fraction: float = 0.05,
) -> Dict[str, Any]:
    """
    Calculate the Jaccard similarity index between the top-k percentile outliers of two detectors:
      J(A, B) = |A ∩ B| / |A ∪ B|

    Parameters
    ----------
    scores_a : Sequence[float]
        Detector A scores.
    scores_b : Sequence[float]
        Detector B scores.
    top_fraction : float
        Top percentile fraction to define outliers (e.g. 0.05 for top 5%).

    Returns
    -------
    Dict[str, Any]
        Detailed overlap statistics.
    """
    arr_a = np.asarray(scores_a, dtype=float)
    arr_b = np.asarray(scores_b, dtype=float)

    n = len(arr_a)
    if n == 0 or len(arr_b) != n:
        return {"jaccard_index": 0.0, "intersection_count": 0, "union_count": 0, "k": 0}

    k = max(1, int(math.ceil(n * top_fraction)))

    # Indices of top k scores
    top_a = set(np.argsort(arr_a)[-k:])
    top_b = set(np.argsort(arr_b)[-k:])

    intersection = top_a.intersection(top_b)
    union = top_a.union(top_b)

    jaccard = len(intersection) / len(union) if union else 0.0

    return {
        "jaccard_index": round(jaccard, 4),
        "k": k,
        "top_fraction": top_fraction,
        "intersection_count": len(intersection),
        "union_count": len(union),
    }


def compute_latency_percentiles(latencies_ms: Sequence[float]) -> Dict[str, float]:
    """
    Compute average, median, p95, and maximum latency in milliseconds.

    Parameters
    ----------
    latencies_ms : Sequence[float]
        Collection of inference runtimes in milliseconds.

    Returns
    -------
    Dict[str, float]
        Runtimes summary.
    """
    arr = np.asarray(latencies_ms, dtype=float)
    if len(arr) == 0:
        return {"mean_ms": 0.0, "median_ms": 0.0, "p95_ms": 0.0, "max_ms": 0.0}

    return {
        "mean_ms": round(float(np.mean(arr)), 4),
        "median_ms": round(float(np.median(arr)), 4),
        "p95_ms": round(float(np.percentile(arr, 95)), 4),
        "max_ms": round(float(np.max(arr)), 4),
    }
