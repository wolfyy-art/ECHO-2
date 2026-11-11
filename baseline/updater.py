"""
baseline/updater.py
===================
ECHO — Controlled Baseline Updater & Contamination Prevention.

Implements controlled updating of process behavioural baselines:
- Contamination Safeguard: Outlier observations (Modified Z >= threshold)
  are quarantined and rejected during baseline refresh to prevent poisoning.
- Rolling Horizon: Retains a clean 30-day sliding window of telemetry.
- Version Tracking: Increments version strings (e.g. 1.0.0 -> 1.0.1).
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from pathlib import Path
import pandas as pd

from dashboard.database import DB_PATH
from baseline.profiler import BehaviouralProfiler
from baseline.comparator import BaselineComparator
from baseline.storage import BaselineStorage

logger = logging.getLogger(__name__)


class BaselineUpdater:
    """
    Manages robust, contamination-resistant baseline updates.
    """

    def __init__(
        self,
        db_path: Path = DB_PATH,
        anomaly_threshold: float = 3.5,
        model_version: str = "1.0.1",
    ):
        self.db_path = Path(db_path)
        self.anomaly_threshold = anomaly_threshold
        self.model_version = model_version
        self.profiler = BehaviouralProfiler(db_path=self.db_path, model_version=model_version)
        self.comparator = BaselineComparator(db_path=self.db_path, anomaly_threshold=anomaly_threshold)
        self.storage = BaselineStorage(self.db_path)

    def filter_clean_telemetry(self, df_features: pd.DataFrame) -> Tuple[pd.DataFrame, int]:
        """
        Quarantine and filter out anomalous outlier observations prior to baseline re-learning.

        Returns
        -------
        Tuple[pd.DataFrame, int]
            (df_clean_observations, quarantined_outlier_count)
        """
        if df_features.empty:
            return df_features, 0

        clean_indices = []
        quarantined = 0

        for idx, row in df_features.iterrows():
            rec = row.to_dict()
            # If a prior baseline exists, check if this observation is an extreme outlier
            eval_res = self.comparator.compare_window(rec)
            if eval_res["baseline_available"] and eval_res["anomaly_detected"]:
                quarantined += 1
            else:
                clean_indices.append(idx)

        df_clean = df_features.loc[clean_indices].copy()
        return df_clean, quarantined

    def update_baselines(self, days: float = 30.0) -> Dict[str, Any]:
        """
        Execute controlled baseline update with contamination prevention.

        Returns
        -------
        Dict[str, Any]
            Update summary containing counts of inspected, clean, quarantined records,
            and updated baselines.
        """
        logger.info("Executing controlled baseline update (rolling %s days)...", days)

        df_raw = self.profiler.load_historical_data(days=days)
        total_obs = len(df_raw)

        if total_obs == 0:
            return {
                "total_observations": 0,
                "clean_observations": 0,
                "quarantined_outliers": 0,
                "baselines_updated": 0,
            }

        df_clean, quarantined = self.filter_clean_telemetry(df_raw)
        logger.info(
            "Telemetry contamination check: %d observations inspected, %d clean, %d quarantined outliers.",
            total_obs, len(df_clean), quarantined,
        )

        baselines = []
        grouped = df_clean.groupby("process_name")
        for pname, group in grouped:
            if len(group) >= self.profiler.min_observations:
                profile = self.profiler.profile_process_group(pname, group, target_days=days)
                profile["model_version"] = self.model_version
                baselines.append(profile)

        saved_count = self.storage.save_baselines(baselines)
        logger.info("Updated %d baselines to model version %s.", saved_count, self.model_version)

        return {
            "total_observations": total_obs,
            "clean_observations": len(df_clean),
            "quarantined_outliers": quarantined,
            "baselines_updated": saved_count,
            "model_version": self.model_version,
        }
