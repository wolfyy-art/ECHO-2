"""
detection/evaluation.py
=======================
ECHO — Controlled Model Evaluation Harness.

Executes:
1. Chronological 70:30 window-preserving dataset split.
2. Contamination sensitivity experiments (0.01, 0.05, 0.10).
3. Comparative analysis against Phase 4 MAD baseline anomaly scores.
4. Latency, training runtime, memory, and model footprint profiling.
5. Generalisation evaluation on persistent processes vs. unseen kernel tasks.
"""

import os
import sys
import time
import logging
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Tuple, Optional
from pathlib import Path
import numpy as np
import pandas as pd

from dashboard.database import DB_PATH, _get_connection
from detection.isolation_forest import ProcessIsolationForest, IsolationForestConfig
from detection.metrics import (
    compute_spearman_rank_correlation,
    compute_top_k_jaccard_overlap,
    compute_latency_percentiles,
)
from baseline.comparator import BaselineComparator

logger = logging.getLogger(__name__)


@dataclass
class ChronologicalSplit:
    """
    Representation of the strict window-preserving temporal split.
    """
    total_records: int
    train_records: int
    test_records: int
    train_window_count: int
    test_window_count: int
    train_earliest: str
    train_latest: str
    test_earliest: str
    test_latest: str
    overlapping_processes: List[str]
    unseen_test_processes: List[str]


class DetectionEvaluator:
    """
    Evaluator for unsupervised anomaly detection models and baselines.
    """

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = Path(db_path)
        self.comparator = BaselineComparator(db_path=self.db_path)

    def load_processed_features(self) -> pd.DataFrame:
        """Load full processed features from SQLite."""
        conn = _get_connection(self.db_path)
        try:
            df = pd.read_sql_query(
                "SELECT * FROM processed_features ORDER BY window_start ASC, id ASC",
                conn,
            )
            return df
        finally:
            conn.close()

    def get_chronological_split(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, ChronologicalSplit]:
        """
        Partition dataset along 5-second window boundaries (70:30 ratio).

        Returns
        -------
        Tuple[pd.DataFrame, pd.DataFrame, ChronologicalSplit]
            (df_train, df_test, split_metadata)
        """
        unique_windows = df["window_start"].unique()
        n_windows = len(unique_windows)
        if n_windows < 2:
            raise ValueError(f"Insufficient distinct windows to split ({n_windows} available).")

        split_idx = int(n_windows * 0.70)
        train_windows = unique_windows[:split_idx]
        test_windows = unique_windows[split_idx:]

        df_train = df[df["window_start"].isin(train_windows)].copy()
        df_test = df[df["window_start"].isin(test_windows)].copy()

        train_procs = set(df_train["process_name"])
        test_procs = set(df_test["process_name"])

        overlapping = sorted(list(train_procs.intersection(test_procs)))
        unseen = sorted(list(test_procs - train_procs))

        split_meta = ChronologicalSplit(
            total_records=len(df),
            train_records=len(df_train),
            test_records=len(df_test),
            train_window_count=len(train_windows),
            test_window_count=len(test_windows),
            train_earliest=str(train_windows[0]),
            train_latest=str(train_windows[-1]),
            test_earliest=str(test_windows[0]),
            test_latest=str(test_windows[-1]),
            overlapping_processes=overlapping,
            unseen_test_processes=unseen,
        )

        return df_train, df_test, split_meta

    def evaluate_contamination_sensitivity(
        self,
        df_train: pd.DataFrame,
        df_test: pd.DataFrame,
        contaminations: Sequence[float] = (0.01, 0.05, 0.10),
    ) -> List[Dict[str, Any]]:
        """
        Train Isolation Forest under varying contamination assumptions and evaluate test behavior.
        """
        results = []
        for cont in contaminations:
            cfg = IsolationForestConfig(n_estimators=100, contamination=cont, random_state=42)
            model = ProcessIsolationForest(cfg)

            t0 = time.perf_counter()
            model.fit(df_train)
            train_time_ms = (time.perf_counter() - t0) * 1000.0

            # Predict on test
            test_scores = model.score_samples(df_test)
            test_preds = model.predict_labels(df_test)

            outlier_count = int(np.sum(test_preds == -1))
            outlier_pct = round(outlier_count / len(test_preds) * 100.0, 2)

            results.append({
                "contamination": cont,
                "score_offset": round(model.score_offset_, 4),
                "train_time_ms": round(train_time_ms, 2),
                "test_outlier_count": outlier_count,
                "test_outlier_pct": outlier_pct,
                "mean_test_score": round(float(np.mean(test_scores)), 4),
                "median_test_score": round(float(np.median(test_scores)), 4),
            })
        return results

    def compare_with_mad(
        self,
        model: ProcessIsolationForest,
        df_test: pd.DataFrame,
    ) -> Dict[str, Any]:
        """
        Calculate statistical rank correlation and top-5% outlier agreement between IF and MAD.
        """
        if_scores = model.score_samples(df_test)

        # Compute MAD scores for each test row
        mad_scores = []
        for _, row in df_test.iterrows():
            eval_res = self.comparator.compare_window(row.to_dict())
            mad_scores.append(eval_res["combined_anomaly_score"])
        mad_scores = np.asarray(mad_scores, dtype=float)

        spearman_rho, pval = compute_spearman_rank_correlation(if_scores, mad_scores)
        top_k = compute_top_k_jaccard_overlap(if_scores, mad_scores, top_fraction=0.05)

        # Disagreement breakdown: cases where IF says anomalous (score > 0.5) but MAD says normal (score < 0.2), and vice versa
        if_anom_mad_norm = int(np.sum((if_scores >= 0.50) & (mad_scores < 0.20)))
        mad_anom_if_norm = int(np.sum((mad_scores >= 0.50) & (if_scores < 0.40)))

        return {
            "spearman_rho": spearman_rho,
            "spearman_pvalue": pval,
            "top_5pct_jaccard": top_k["jaccard_index"],
            "top_5pct_intersection": top_k["intersection_count"],
            "top_5pct_union": top_k["union_count"],
            "if_anomalous_mad_normal_count": if_anom_mad_norm,
            "mad_anomalous_if_normal_count": mad_anom_if_norm,
            "total_evaluated": len(df_test),
        }

    def measure_latency_and_resources(
        self,
        model: ProcessIsolationForest,
        df_test: pd.DataFrame,
        n_repeats: int = 50,
    ) -> Dict[str, Any]:
        """
        Measure inference latency per observation and per window.
        """
        latencies_per_row_ms = []

        # Benchmark single-observation inference
        sample_rows = [df_test.iloc[[i]] for i in range(min(50, len(df_test)))]

        for row_df in sample_rows:
            t0 = time.perf_counter()
            _ = model.score_samples(row_df)
            dt_ms = (time.perf_counter() - t0) * 1000.0
            latencies_per_row_ms.append(dt_ms)

        stats_latency = compute_latency_percentiles(latencies_per_row_ms)

        # Batch inference latency (full test set)
        t_batch_0 = time.perf_counter()
        _ = model.score_samples(df_test)
        batch_total_ms = (time.perf_counter() - t_batch_0) * 1000.0

        return {
            "per_record_latency": stats_latency,
            "full_test_batch_ms": round(batch_total_ms, 2),
            "test_record_count": len(df_test),
            "effective_throughput_records_per_sec": round(len(df_test) / (batch_total_ms / 1000.0), 1),
        }

    def evaluate_generalisation_groups(
        self,
        model: ProcessIsolationForest,
        df_test: pd.DataFrame,
        split_meta: ChronologicalSplit,
    ) -> Dict[str, Any]:
        """
        Evaluate score distributions on previously seen processes versus unseen kernel workers.
        """
        df_seen = df_test[df_test["process_name"].isin(split_meta.overlapping_processes)]
        df_unseen = df_test[df_test["process_name"].isin(split_meta.unseen_test_processes)]

        scores_seen = model.score_samples(df_seen)
        scores_unseen = model.score_samples(df_unseen)

        return {
            "seen_processes_count": len(split_meta.overlapping_processes),
            "seen_records_evaluated": len(scores_seen),
            "seen_mean_score": round(float(np.mean(scores_seen)), 4) if len(scores_seen) else 0.0,
            "seen_p95_score": round(float(np.percentile(scores_seen, 95)), 4) if len(scores_seen) else 0.0,
            "unseen_processes_count": len(split_meta.unseen_test_processes),
            "unseen_processes_list": split_meta.unseen_test_processes,
            "unseen_records_evaluated": len(scores_unseen),
            "unseen_mean_score": round(float(np.mean(scores_unseen)), 4) if len(scores_unseen) else 0.0,
            "unseen_p95_score": round(float(np.percentile(scores_unseen, 95)), 4) if len(scores_unseen) else 0.0,
        }
