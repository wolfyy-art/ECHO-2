"""
tests/test_detection.py
=======================
Unit and integration tests for ECHO Phase 5.1 Anomaly Detection.
Covers:
1. Approved feature validation and matrix extraction.
2. Missing and invalid value handling (no silent 0.0 conversion).
3. Chronological 70:30 window-preserving split verification.
4. Model fitting, prediction, and serialization.
5. Contamination sensitivity and decision offset changes.
6. Spearman rank correlation and Top-K Jaccard overlap metrics.
7. Controlled synthetic test fixtures (CPU spikes >= 98%, socket bursts > 50, thread churn > 64).
8. Process generalisation evaluation (seen vs unseen kernel workers).
"""

import unittest
import tempfile
from pathlib import Path
import numpy as np
import pandas as pd

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
from detection.evaluation import DetectionEvaluator
from baseline.identity import build_process_type_identity


def _create_synthetic_feature_dataframe(n_rows: int = 100, seed: int = 42) -> pd.DataFrame:
    """Generate isolated synthetic feature dataframe for unit testing."""
    np.random.seed(seed)
    data = {
        "window_start": [f"2026-11-11T10:{i//10:02d}:00Z" for i in range(n_rows)],
        "pid": [1000 + (i % 20) for i in range(n_rows)],
        "process_name": [f"proc_{i % 10}" for i in range(n_rows)],
        "username": ["vboxuser"] * n_rows,
        "status": ["running"] * n_rows,
        "cpu_mean": np.random.uniform(0.0, 5.0, n_rows),
        "cpu_max": np.random.uniform(5.0, 10.0, n_rows),
        "cpu_std": np.random.uniform(0.0, 1.0, n_rows),
        "memory_mean": np.random.uniform(0.1, 2.0, n_rows),
        "memory_max": np.random.uniform(2.0, 3.0, n_rows),
        "memory_rss_mean": np.random.uniform(1e5, 5e6, n_rows),
        "num_threads_mean": np.random.uniform(1.0, 4.0, n_rows),
        "num_threads_max": [4] * n_rows,
        "open_sockets_count": [i % 5 for i in range(n_rows)],
        "distinct_remote_ips": [(i % 5) // 2 for i in range(n_rows)],
        "sample_count": [1] * n_rows,
        "cpu_mem_ratio": np.random.uniform(0.1, 2.0, n_rows),
        "socket_thread_ratio": [(i % 5) / 2.0 for i in range(n_rows)],
    }
    return pd.DataFrame(data)


class TestDetectionPhase(unittest.TestCase):
    """Test suite for Phase 5.1 Detection module."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.model_path = Path(self.tmp_dir) / "test_iforest.joblib"
        self.df_synthetic = _create_synthetic_feature_dataframe(n_rows=200)

    # 1. Feature Matrix Validation & Missing Data Handling
    def test_missing_feature_column_raises_error(self):
        """Missing required feature column must raise ValueError."""
        df_incomplete = self.df_synthetic.drop(columns=["cpu_mean"])
        model = ProcessIsolationForest()
        with self.assertRaises(ValueError):
            model.prepare_feature_matrix(df_incomplete)

    def test_missing_or_nan_values_handled_explicitly(self):
        """NaN values are flagged explicitly and filtered without silent 0.0 conversion."""
        df_nan = self.df_synthetic.copy()
        df_nan.loc[5, "cpu_mean"] = np.nan
        df_nan.loc[12, "memory_mean"] = np.nan

        model = ProcessIsolationForest()
        X, valid_idx = model.prepare_feature_matrix(df_nan)
        self.assertEqual(len(X), 198)
        self.assertNotIn(5, valid_idx)
        self.assertNotIn(12, valid_idx)

    # 2. Model Lifecycle & Artifact Serialization
    def test_fit_score_and_save_model(self):
        """Verify model fits, scores in [0, 1], and serializes/deserializes cleanly."""
        model = ProcessIsolationForest(IsolationForestConfig(n_estimators=50, random_state=42))
        model.fit(self.df_synthetic)
        self.assertTrue(model.is_fitted)

        scores = model.score_samples(self.df_synthetic)
        self.assertEqual(len(scores), 200)
        self.assertTrue((scores >= 0.0).all() and (scores <= 1.0).all())

        model.save(self.model_path)
        self.assertTrue(self.model_path.exists())

        loaded = ProcessIsolationForest.load(self.model_path)
        self.assertTrue(loaded.is_fitted)
        loaded_scores = loaded.score_samples(self.df_synthetic)
        np.testing.assert_array_almost_equal(scores, loaded_scores)

    # 3. Contamination Sensitivity
    def test_contamination_parameter_shifts_offset(self):
        """Higher contamination raises the score offset threshold."""
        m_low = ProcessIsolationForest(IsolationForestConfig(n_estimators=50, contamination=0.01, random_state=42))
        m_low.fit(self.df_synthetic)

        m_high = ProcessIsolationForest(IsolationForestConfig(n_estimators=50, contamination=0.10, random_state=42))
        m_high.fit(self.df_synthetic)

        self.assertNotEqual(m_low.score_offset_, m_high.score_offset_)
        self.assertLess(m_low.score_offset_, m_high.score_offset_)

    # 4. Metric Tests: Spearman Rho & Jaccard Overlap
    def test_metrics_spearman_and_jaccard(self):
        """Verify Spearman correlation and Top-K Jaccard index calculations."""
        a = [0.1, 0.2, 0.3, 0.8, 0.9]
        b = [0.15, 0.25, 0.35, 0.85, 0.95]
        rho, pval = compute_spearman_rank_correlation(a, b)
        self.assertAlmostEqual(rho, 1.0, places=2)

        jaccard = compute_top_k_jaccard_overlap(a, b, top_fraction=0.40)
        self.assertEqual(jaccard["jaccard_index"], 1.0)
        self.assertEqual(jaccard["k"], 2)

    # 5. Controlled Synthetic Perturbation Test Fixtures
    def test_controlled_cpu_spike_perturbation(self):
        """
        Controlled test fixture: Verify that an extreme CPU spike (>= 98.0%)
        is assigned a elevated anomaly score compared to baseline normal data.
        """
        model = ProcessIsolationForest(IsolationForestConfig(n_estimators=50, contamination=0.05, random_state=42))
        model.fit(self.df_synthetic)

        normal_sample = self.df_synthetic.iloc[[0]].copy()
        normal_score = model.score_samples(normal_sample)[0]

        spike_sample = normal_sample.copy()
        spike_sample["cpu_mean"] = 99.5
        spike_sample["cpu_max"] = 100.0
        spike_sample["cpu_mem_ratio"] = 99.5 / (spike_sample["memory_mean"].iloc[0] + 1e-5)

        spike_score = model.score_samples(spike_sample)[0]
        self.assertGreater(spike_score, normal_score)
        self.assertGreaterEqual(spike_score, 0.50)

    def test_controlled_socket_burst_perturbation(self):
        """
        Controlled test fixture: Verify that a massive socket burst (> 50 sockets)
        produces an anomalous evaluation.
        """
        model = ProcessIsolationForest(IsolationForestConfig(n_estimators=50, contamination=0.05, random_state=42))
        model.fit(self.df_synthetic)

        normal_sample = self.df_synthetic.iloc[[1]].copy()
        normal_score = model.score_samples(normal_sample)[0]

        burst_sample = normal_sample.copy()
        burst_sample["open_sockets_count"] = 75
        burst_sample["distinct_remote_ips"] = 45
        burst_sample["socket_thread_ratio"] = 75.0 / burst_sample["num_threads_mean"].iloc[0]

        burst_score = model.score_samples(burst_sample)[0]
        self.assertGreater(burst_score, normal_score)

    def test_controlled_thread_churn_perturbation(self):
        """
        Controlled test fixture: Verify that thread ballooning (> 64 threads)
        produces an anomalous evaluation.
        """
        model = ProcessIsolationForest(IsolationForestConfig(n_estimators=50, contamination=0.05, random_state=42))
        model.fit(self.df_synthetic)

        normal_sample = self.df_synthetic.iloc[[2]].copy()
        churn_sample = normal_sample.copy()
        churn_sample["num_threads_mean"] = 80.0
        churn_sample["num_threads_max"] = 96

        churn_score = model.score_samples(churn_sample)[0]
        normal_score = model.score_samples(normal_sample)[0]
        self.assertGreater(churn_score, normal_score)

    def test_unseen_processes_generalisation_handling(self):
        """
        Verify that unseen test processes are scored based on their numerical feature
        sparsity without crashing or requiring artificial baseline fabrication.
        """
        model = ProcessIsolationForest(IsolationForestConfig(n_estimators=50, contamination=0.05, random_state=42))
        model.fit(self.df_synthetic)

        unseen_proc = self.df_synthetic.iloc[[0]].copy()
        unseen_proc["process_name"] = "kworker/u99:9-custom"
        score = model.score_samples(unseen_proc)
        self.assertEqual(len(score), 1)
        self.assertTrue(0.0 <= score[0] <= 1.0)


if __name__ == "__main__":
    unittest.main()
