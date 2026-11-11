"""
baseline/mad.py
================
ECHO — Median Absolute Deviation (MAD) & Modified Z-Score Engine.

Implements robust, non-parametric statistical dispersion and deviation scoring:
  MAD = median(|Xi - median(X)|)
  Modified Z-Score = 0.6745 * (value - median) / MAD

The constant 0.6745 scales the MAD so that for normally distributed data,
MAD represents approximately 1 standard deviation (since P(Z <= 0.6745) ≈ 0.75).
"""

import math
from typing import Sequence, Union, Optional, Tuple, Dict, Any
import numpy as np


def compute_median_and_mad(
    values: Union[Sequence[float], np.ndarray],
) -> Tuple[float, float]:
    """
    Compute median and Median Absolute Deviation (MAD) for a 1D sequence of numbers.

    Parameters
    ----------
    values : Sequence[float] or np.ndarray
        Sample values.

    Returns
    -------
    Tuple[float, float]
        (median, mad)
    """
    arr = np.asarray(values, dtype=float)
    arr = arr[~np.isnan(arr)]
    if len(arr) == 0:
        return 0.0, 0.0

    med = float(np.median(arr))
    abs_deviations = np.abs(arr - med)
    mad = float(np.median(abs_deviations))
    return round(med, 4), round(mad, 4)


def compute_modified_z_score(
    value: float,
    median: float,
    mad: float,
    epsilon: float = 1e-4,
) -> float:
    """
    Calculate Boris Iglewicz and David Hoaglin's Modified Z-Score.

    Formula:
        M_i = 0.6745 * (x_i - median) / MAD

    Safety Guards:
    - If MAD == 0:
        If value == median, score is 0.0 (no anomaly).
        If value != median, uses epsilon or fallback scale to prevent infinity.
    - If value is NaN or None, returns 0.0.

    Parameters
    ----------
    value : float
        Observed metric reading.
    median : float
        Baseline median for the metric.
    mad : float
        Baseline MAD for the metric.
    epsilon : float
        Floor to prevent division by zero when MAD is zero.

    Returns
    -------
    float
        Signed modified Z-score (positive indicates reading is above median).
    """
    if value is None or math.isnan(value):
        return 0.0

    diff = value - median

    if abs(diff) < 1e-9:
        return 0.0

    # If MAD is near zero, use a robust scale floor based on the magnitude of the median,
    # or fallback to epsilon to avoid assigning huge Z-scores to tiny normal variations.
    scale = mad
    if scale <= epsilon:
        # Scale floor: 10% of median or epsilon, whichever is larger
        scale = max(0.10 * abs(median), epsilon)

    z = 0.6745 * diff / scale

    # Cap to avoid pathological overflow in extreme spikes
    if z > 1000.0:
        return 1000.0
    elif z < -1000.0:
        return -1000.0

    return round(float(z), 4)


class MADScorer:
    """
    Multi-feature deviation scorer based on per-process baselines and MAD metrics.
    """

    def __init__(self, anomaly_threshold: float = 3.5):
        """
        Parameters
        ----------
        anomaly_threshold : float
            Modified Z-score threshold above which a metric is deemed anomalous.
            Iglewicz and Hoaglin recommend 3.5 for exploratory outlier detection.
        """
        if anomaly_threshold <= 0:
            raise ValueError(f"anomaly_threshold must be positive (> 0), got {anomaly_threshold}")
        self.anomaly_threshold = anomaly_threshold

    def score_feature(
        self,
        feature_name: str,
        observed_value: float,
        expected_median: float,
        mad: float,
    ) -> Dict[str, Any]:
        """
        Score a single observed feature against its baseline median and MAD.

        Returns
        -------
        Dict[str, Any]
            Detailed deviation evaluation.
        """
        z_score = compute_modified_z_score(observed_value, expected_median, mad)
        is_anomalous = abs(z_score) >= self.anomaly_threshold

        explanation = (
            f"{feature_name} observed={observed_value:.2f} (median={expected_median:.2f}, MAD={mad:.2f}, "
            f"Z={z_score:+.2f}). "
            f"{'EXCEEDS anomaly threshold ' + str(self.anomaly_threshold) if is_anomalous else 'Within expected bounds.'}"
        )

        return {
            "feature_name": feature_name,
            "observed_value": round(float(observed_value), 4),
            "expected_median": round(float(expected_median), 4),
            "mad": round(float(mad), 4),
            "modified_z_score": z_score,
            "is_anomalous": is_anomalous,
            "explanation": explanation,
        }
