"""
preprocessing/features.py
=========================
ECHO — Feature Normalization and Extraction.

Transforms windowed aggregations into structured numerical and categorical
feature vectors ready for baseline ML models and MAD profiling.
"""

import logging
from typing import List, Tuple
import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)

# Core numerical features for ML and behavioral profiling
NUMERICAL_FEATURE_COLUMNS = [
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
]


class FeatureExtractor:
    """
    Normalizes and formats feature matrices for downstream ML and statistical profiling.
    """

    @staticmethod
    def extract_features(df_windows: pd.DataFrame) -> pd.DataFrame:
        """
        Produce a clean feature DataFrame with normalized metrics and derived rates.

        Parameters
        ----------
        df_windows : pd.DataFrame
            Window-aggregated data.

        Returns
        -------
        pd.DataFrame
            Engineered feature DataFrame.
        """
        if df_windows.empty:
            return pd.DataFrame()

        df_feat = df_windows.copy()

        # Derived feature: CPU to Memory ratio (identifies compute-heavy vs RAM-heavy processes)
        df_feat["cpu_mem_ratio"] = df_feat["cpu_mean"] / (df_feat["memory_mean"] + 1e-5)

        # Derived feature: Socket to thread ratio
        df_feat["socket_thread_ratio"] = df_feat["open_sockets_count"] / (df_feat["num_threads_mean"] + 1e-5)

        # Round numerical features to 4 decimal places for consistency
        float_cols = df_feat.select_dtypes(include=[np.number]).columns
        df_feat[float_cols] = df_feat[float_cols].round(4)

        return df_feat

    @staticmethod
    def get_feature_matrix(df_features: pd.DataFrame) -> Tuple[np.ndarray, List[str]]:
        """
        Extract numerical feature numpy array and column names for ML training/inference.

        Parameters
        ----------
        df_features : pd.DataFrame
            Feature dataset.

        Returns
        -------
        Tuple[np.ndarray, List[str]]
            (feature_matrix, feature_column_names)
        """
        cols = [c for c in NUMERICAL_FEATURE_COLUMNS if c in df_features.columns]
        if "cpu_mem_ratio" in df_features.columns:
            cols.append("cpu_mem_ratio")
        if "socket_thread_ratio" in df_features.columns:
            cols.append("socket_thread_ratio")

        if df_features.empty:
            return np.empty((0, len(cols))), cols

        X = df_features[cols].to_numpy(dtype=float)
        return X, cols
