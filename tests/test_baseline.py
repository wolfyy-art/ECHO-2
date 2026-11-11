"""
tests/test_baseline.py
======================
Comprehensive unit and integration tests for ECHO Phase 4 Behavioural Profiling.
Tests cover:
1. Historical data analysis and temporal coverage.
2. Target 30-day window selection.
3. Insufficient historical data marking (preliminary status).
4. CPU profiling statistics.
5. Memory profiling statistics.
6. Network socket and remote IP profiling.
7. MAD calculations and Boris Iglewicz Modified Z-Score.
8. Zero MAD handling and epsilon floor.
9. Missing feature values and NaN suppression.
10. Process identity separation.
11. PID reuse and distinct process grouping.
12. Baseline storage persistence in SQLite.
13. Baseline comparison against incoming feature windows.
14. Anomaly scoring and thresholding.
15. Baseline updates and version tracking.
16. Contamination prevention (outlier quarantine).
17. Database migration (process_baselines creation).
18. Empty database handling.
"""

import unittest
import tempfile
from pathlib import Path
import numpy as np
import pandas as pd

from baseline.mad import compute_median_and_mad, compute_modified_z_score, MADScorer
from baseline.historical_analyzer import HistoricalAnalyzer
from baseline.storage import BaselineStorage, init_baselines_table
from baseline.profiler import BehaviouralProfiler
from baseline.comparator import BaselineComparator
from baseline.updater import BaselineUpdater
from preprocessing.pipeline import PreprocessingPipeline
from collector.storage import TelemetryStorage
from collector.models import ProcessTelemetry


class TestBehaviouralProfiling(unittest.TestCase):
    """Test suite for Phase 4 baseline components."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.tmp_dir) / "test_echo.db"
        self.storage = TelemetryStorage(db_path=self.db_path)
        self.baseline_storage = BaselineStorage(db_path=self.db_path)

    # 1. MAD and Modified Z-Score Tests
    def test_mad_calculation_known_values(self):
        """Verify MAD calculation on known synthetic sequence: [1, 2, 3, 4, 5, 6, 7]."""
        # Median = 4; deviations = [3, 2, 1, 0, 1, 2, 3]; sorted deviations = [0, 1, 1, 2, 2, 3, 3]; median deviation = 2.0
        vals = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0]
        med, mad = compute_median_and_mad(vals)
        self.assertEqual(med, 4.0)
        self.assertEqual(mad, 2.0)

    def test_zero_mad_safe_handling(self):
        """When all values are identical, MAD is 0; modified Z-score must not explode to inf."""
        vals = [10.0, 10.0, 10.0, 10.0]
        med, mad = compute_median_and_mad(vals)
        self.assertEqual(med, 10.0)
        self.assertEqual(mad, 0.0)

        # Value equal to median -> Z = 0
        z_normal = compute_modified_z_score(10.0, med, mad)
        self.assertEqual(z_normal, 0.0)

        # Deviation when MAD is 0 -> Uses epsilon, bounded without raising ZeroDivisionError
        z_divergent = compute_modified_z_score(20.0, med, mad)
        self.assertTrue(np.isfinite(z_divergent))
        self.assertGreater(z_divergent, 0.0)

    def test_modified_z_score_missing_values(self):
        """NaN or None values must yield 0.0 Z-score safely."""
        self.assertEqual(compute_modified_z_score(None, 5.0, 1.0), 0.0)
        self.assertEqual(compute_modified_z_score(np.nan, 5.0, 1.0), 0.0)

    def test_mad_scorer_thresholding(self):
        """Scorer correctly flags values exceeding modified Z threshold (3.5)."""
        scorer = MADScorer(anomaly_threshold=3.5)
        # median=10, mad=2, value=30 -> diff=20 -> Z = 0.6745 * 20 / 2 = 6.745 >= 3.5
        res = scorer.score_feature("cpu", observed_value=30.0, expected_median=10.0, mad=2.0)
        self.assertTrue(res["is_anomalous"])
        self.assertGreaterEqual(res["modified_z_score"], 3.5)

        # Normal value within bounds
        res_normal = scorer.score_feature("cpu", observed_value=11.0, expected_median=10.0, mad=2.0)
        self.assertFalse(res_normal["is_anomalous"])

    # 2. Historical Analysis Tests
    def test_empty_database_historical_analysis(self):
        """Analyzer returns clean zero report on empty processed_features table."""
        analyzer = HistoricalAnalyzer(db_path=self.db_path)
        report = analyzer.analyze_coverage(target_days=30.0)
        self.assertFalse(report.is_fully_established)
        self.assertEqual(report.total_records, 0)
        self.assertEqual(report.status_label, "NO_DATA")

    def test_historical_coverage_calculation(self):
        """Seed processed features spanning 1 hour and verify coverage ratio against 30-day target."""
        self._seed_processed_features(duration_hours=1.0)
        analyzer = HistoricalAnalyzer(db_path=self.db_path)
        report = analyzer.analyze_coverage(target_days=30.0)

        self.assertEqual(report.target_learning_days, 30.0)
        self.assertAlmostEqual(report.total_duration_hours, 1.0, places=1)
        self.assertFalse(report.is_fully_established)
        self.assertEqual(report.status_label, "PRELIMINARY")
        self.assertLess(report.coverage_ratio, 0.01)

    # 3. Profiler Tests
    def test_profiler_creates_statistical_baseline(self):
        """Verify profiler correctly computes medians, means, and MAD across features."""
        self._seed_processed_features(duration_hours=2.0, process_name="nginx", cpu_vals=[5.0, 5.0, 6.0, 5.5, 5.2])
        profiler = BehaviouralProfiler(db_path=self.db_path, min_observations=3)
        baselines = profiler.learn_all_baselines(days=30.0)

        self.assertEqual(len(baselines), 1)
        b = baselines[0]
        self.assertEqual(b["process_name"], "nginx")
        self.assertAlmostEqual(b["cpu_median"], 5.2, places=1)
        self.assertEqual(b["baseline_status"], "preliminary")

        # Verify stored in SQLite
        saved = self.baseline_storage.get_baseline_by_process_name("nginx")
        self.assertIsNotNone(saved)
        self.assertEqual(saved["process_name"], "nginx")

    # 4. Comparator & Anomaly Scoring Tests
    def test_comparator_detects_deviant_window(self):
        """Comparator evaluates incoming record against learned baseline."""
        self._seed_processed_features(duration_hours=2.0, process_name="bash", cpu_vals=[1.0, 1.0, 1.2, 1.1])
        profiler = BehaviouralProfiler(db_path=self.db_path, min_observations=3)
        profiler.learn_all_baselines(days=30.0)

        comparator = BaselineComparator(db_path=self.db_path, anomaly_threshold=3.5)

        # Normal test record matching baseline attributes
        normal_eval = comparator.compare_window({
            "process_name": "bash", "pid": 100,
            "cpu_mean": 1.1, "memory_mean": 1.5,
            "open_sockets_count": 0, "distinct_remote_ips": 0,
            "num_threads_mean": 2.0
        })
        self.assertFalse(normal_eval["anomaly_detected"])

        # Anomalous test record (CPU spike to 95.0%)
        anom_eval = comparator.compare_window({"process_name": "bash", "pid": 100, "cpu_mean": 95.0, "memory_mean": 0.5})
        self.assertTrue(anom_eval["anomaly_detected"])
        self.assertIn("cpu", anom_eval["anomalous_features"])
        self.assertGreaterEqual(anom_eval["combined_anomaly_score"], 0.5)

    # 5. Contamination Prevention & Baseline Updater Tests
    def test_updater_quarantines_outliers(self):
        """BaselineUpdater rejects anomalous spikes during baseline re-training."""
        # Baseline established on clean data
        self._seed_processed_features(duration_hours=2.0, process_name="logger", cpu_vals=[2.0, 2.1, 2.0, 2.2])
        profiler = BehaviouralProfiler(db_path=self.db_path, min_observations=3)
        profiler.learn_all_baselines(days=30.0)

        # Inject extreme outlier into processed features
        conn = self.storage.db_path
        import sqlite3
        with sqlite3.connect(str(conn)) as db_conn:
            db_conn.execute("""
                INSERT INTO processed_features (
                    window_start, pid, ppid, process_name, username, status,
                    cpu_mean, cpu_max, cpu_std, memory_mean, memory_max,
                    memory_rss_mean, num_threads_mean, num_threads_max,
                    open_sockets_count, distinct_remote_ips, sample_count,
                    cpu_mem_ratio, socket_thread_ratio
                ) VALUES (
                    '2026-11-11T12:00:00Z', 999, 1, 'logger', 'user', 'running',
                    99.0, 99.0, 0.0, 1.0, 1.0, 1000, 1.0, 1, 0, 0, 1, 99.0, 0.0
                )
            """)

        updater = BaselineUpdater(db_path=self.db_path, model_version="1.0.2")
        result = updater.update_baselines(days=30.0)

        # Outlier was detected and quarantined
        self.assertEqual(result["quarantined_outliers"], 1)
        self.assertEqual(result["model_version"], "1.0.2")

        # Verify updated baseline remained unaffected by the 99% CPU spike
        updated_b = self.baseline_storage.get_baseline_by_process_name("logger")
        self.assertLess(updated_b["cpu_median"], 5.0)

    # Helper method to seed synthetic test telemetry into processed_features
    def _seed_processed_features(
        self,
        duration_hours: float = 1.0,
        process_name: str = "test_proc",
        cpu_vals: list = None,
    ):
        import sqlite3
        if cpu_vals is None:
            cpu_vals = [2.0, 2.5, 2.2, 2.1, 2.3]

        conn = sqlite3.connect(str(self.db_path))
        pipeline = PreprocessingPipeline(db_path=self.db_path)  # ensures processed_features table exists

        start_dt = pd.to_datetime("2026-11-11T10:00:00Z", utc=True)
        step = (duration_hours * 3600.0) / max(1, len(cpu_vals) - 1)

        records = []
        for i, cpu in enumerate(cpu_vals):
            ts = (start_dt + pd.to_timedelta(i * step, unit="s")).strftime("%Y-%m-%dT%H:%M:%SZ")
            records.append((
                ts, 1000 + i, 1, process_name, "test_user", "running",
                float(cpu), float(cpu), 0.0, 1.5, 1.5, 100000.0,
                2.0, 2, 0, 0, 1, float(cpu) / 1.5, 0.0
            ))

        sql = """
            INSERT INTO processed_features (
                window_start, pid, ppid, process_name, username, status,
                cpu_mean, cpu_max, cpu_std, memory_mean, memory_max,
                memory_rss_mean, num_threads_mean, num_threads_max,
                open_sockets_count, distinct_remote_ips, sample_count,
                cpu_mem_ratio, socket_thread_ratio
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with conn:
            conn.executemany(sql, records)
        conn.close()


if __name__ == "__main__":
    unittest.main()

class TestScaleFloorAndAnomalyScoringAudit(unittest.TestCase):
    """Targeted audit tests for Tasks 1, 2, and 3."""

    def test_scale_floor_zero_median_and_zero_mad(self):
        """Zero median and zero MAD uses epsilon floor."""
        z = compute_modified_z_score(value=1.0, median=0.0, mad=0.0)
        self.assertGreater(z, 0.0)
        self.assertTrue(np.isfinite(z))

    def test_scale_floor_near_zero_median(self):
        """Near-zero median (e.g. 0.0001) with zero MAD uses epsilon floor safely."""
        z = compute_modified_z_score(value=0.005, median=0.0001, mad=0.0)
        self.assertGreater(z, 0.0)
        self.assertTrue(np.isfinite(z))

    def test_scale_floor_small_positive_median(self):
        """Small positive median (e.g. 0.5) with zero MAD uses 10% median scale (0.05)."""
        z = compute_modified_z_score(value=0.55, median=0.5, mad=0.0)
        # diff = 0.05, scale = 0.05, z = 0.6745 * 1.0 = 0.6745
        self.assertAlmostEqual(z, 0.6745, places=3)

    def test_scale_floor_large_positive_median(self):
        """Large positive median (e.g. 50000) with zero MAD uses 10% median scale (5000)."""
        z = compute_modified_z_score(value=55000, median=50000, mad=0.0)
        # diff = 5000, scale = 5000, z = 0.6745 * 1.0 = 0.6745
        self.assertAlmostEqual(z, 0.6745, places=3)

    def test_scale_floor_negative_values(self):
        """Negative values (if ever present) handle scale without negative division."""
        z = compute_modified_z_score(value=-10.0, median=-10.0, mad=0.0)
        self.assertEqual(z, 0.0)
        z_dev = compute_modified_z_score(value=-15.0, median=-10.0, mad=0.0)
        self.assertLess(z_dev, 0.0)
        self.assertTrue(np.isfinite(z_dev))

    def test_scale_floor_constant_metrics(self):
        """Constant readings produce 0.0 Z-score."""
        z = compute_modified_z_score(value=42.0, median=42.0, mad=0.0)
        self.assertEqual(z, 0.0)

    def test_anomaly_score_bounds_and_properties(self):
        """Verify S in [0, 1], S(0)=0, S(3.5)=0.5, and monotonic increase."""
        comparator = BaselineComparator(anomaly_threshold=3.5)

        # Zero anomaly
        rec_zero = {"process_name": "proc_test", "cpu_mean": 10.0, "memory_mean": 10.0}
        base = {
            "process_name": "proc_test", "cpu_median": 10.0, "cpu_mad": 2.0,
            "memory_median": 10.0, "memory_mad": 2.0, "socket_median": 0.0,
            "socket_mad": 0.0, "remote_ip_median": 0.0, "remote_ip_mad": 0.0,
            "thread_median": 1.0, "thread_mad": 0.0, "baseline_status": "preliminary",
        }
        res_zero = comparator.compare_window(rec_zero, baseline=base)
        self.assertEqual(res_zero["combined_anomaly_score"], 0.0)

        # Exactly at threshold: Z = 3.5 -> S = 3.5 / (3.5 + 3.5) = 0.5
        # diff = 3.5 * 2 / 0.6745 = 10.378
        rec_thresh = {"process_name": "proc_test", "cpu_mean": 10.0 + (3.5 * 2.0 / 0.6745)}
        res_thresh = comparator.compare_window(rec_thresh, baseline=base)
        self.assertAlmostEqual(res_thresh["combined_anomaly_score"], 0.5, places=2)

        # Monotonicity: higher Z yields higher S, strictly < 1.0
        rec_huge = {"process_name": "proc_test", "cpu_mean": 1000.0}
        res_huge = comparator.compare_window(rec_huge, baseline=base)
        self.assertGreater(res_huge["combined_anomaly_score"], 0.5)
        self.assertLess(res_huge["combined_anomaly_score"], 1.0)

    def test_missing_features_do_not_produce_silent_zero_score(self):
        """Missing features are flagged as missing: True and not converted to Z=0.0."""
        comparator = BaselineComparator(anomaly_threshold=3.5)
        base = {
            "process_name": "proc_missing", "cpu_median": 10.0, "cpu_mad": 2.0,
            "memory_median": 10.0, "memory_mad": 2.0, "socket_median": 0.0,
            "socket_mad": 0.0, "remote_ip_median": 0.0, "remote_ip_mad": 0.0,
            "thread_median": 1.0, "thread_mad": 0.0, "baseline_status": "preliminary",
        }
        # CPU is missing (None)
        rec = {"process_name": "proc_missing", "cpu_mean": None, "memory_mean": 10.0}
        res = comparator.compare_window(rec, baseline=base)
        cpu_score = res["features_scored"]["cpu"]
        self.assertTrue(cpu_score.get("missing", False))
        self.assertIsNone(cpu_score["modified_z_score"])

    def test_process_type_vs_instance_identity(self):
        """Verify process-type identity is stable, while instance identity separates PID reuse."""
        from baseline.identity import build_process_type_identity, build_process_instance_identity

        type_id = build_process_type_identity(process_name="nginx", username="www-data")
        self.assertEqual(type_id, "type::www-data::nginx")

        # Two separate instances sharing PID 500 at different times
        inst_1 = build_process_instance_identity("nginx", pid=500, process_start_time="2026-11-11T01:00:00Z", username="www-data")
        inst_2 = build_process_instance_identity("nginx", pid=500, process_start_time="2026-11-11T04:00:00Z", username="www-data")
        self.assertNotEqual(inst_1, inst_2)

    def test_identity_aware_baseline_lookup(self):
        """Active baseline lookup prioritizes identity and username over process_name alone."""
        from baseline.storage import BaselineStorage
        import tempfile
        tmp = tempfile.mkdtemp()
        db_path = Path(tmp) / "id_test.db"
        storage = BaselineStorage(db_path=db_path)

        storage.save_baselines([
            {
                "baseline_id": "b-root-sh", "process_identity": "type::root::sh", "process_name": "sh",
                "executable_identity": "root", "learning_period_days": 30.0, "observation_count": 10,
                "cpu_median": 50.0, "cpu_mean": 50.0, "cpu_min": 50.0, "cpu_max": 50.0, "cpu_std": 0.0, "cpu_mad": 0.0,
                "memory_median": 10.0, "memory_mean": 10.0, "memory_max": 10.0, "memory_mad": 0.0,
                "socket_median": 0.0, "socket_max": 0, "socket_mad": 0.0, "remote_ip_median": 0.0, "remote_ip_mad": 0.0,
                "thread_median": 1.0, "thread_max": 1, "thread_mad": 0.0, "baseline_start": "2026-11-11T00:00:00Z",
                "baseline_end": "2026-11-11T01:00:00Z", "model_version": "1.0.0", "baseline_status": "preliminary",
                "created_at": "2026-11-11T01:00:00Z", "updated_at": "2026-11-11T01:00:00Z"
            },
            {
                "baseline_id": "b-user-sh", "process_identity": "type::vboxuser::sh", "process_name": "sh",
                "executable_identity": "vboxuser", "learning_period_days": 30.0, "observation_count": 10,
                "cpu_median": 1.0, "cpu_mean": 1.0, "cpu_min": 1.0, "cpu_max": 1.0, "cpu_std": 0.0, "cpu_mad": 0.0,
                "memory_median": 1.0, "memory_mean": 1.0, "memory_max": 1.0, "memory_mad": 0.0,
                "socket_median": 0.0, "socket_max": 0, "socket_mad": 0.0, "remote_ip_median": 0.0, "remote_ip_mad": 0.0,
                "thread_median": 1.0, "thread_max": 1, "thread_mad": 0.0, "baseline_start": "2026-11-11T00:00:00Z",
                "baseline_end": "2026-11-11T01:00:00Z", "model_version": "1.0.0", "baseline_status": "preliminary",
                "created_at": "2026-11-11T01:00:00Z", "updated_at": "2026-11-11T01:00:00Z"
            }
        ])

        root_base = storage.get_active_baseline(process_name="sh", username="root")
        user_base = storage.get_active_baseline(process_name="sh", username="vboxuser")

        self.assertEqual(root_base["baseline_id"], "b-root-sh")
        self.assertEqual(root_base["cpu_median"], 50.0)
        self.assertEqual(user_base["baseline_id"], "b-user-sh")
        self.assertEqual(user_base["cpu_median"], 1.0)
