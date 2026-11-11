"""
tests/test_preprocessing.py
===========================
Unit tests for ECHO Preprocessing Pipeline.
Verifies data cleaning, timestamp parsing, missing value handling, 5-second windowing,
derived feature calculations, and database / CSV persistence.
"""

import unittest
import tempfile
from pathlib import Path
import pandas as pd
import numpy as np

from preprocessing.cleaner import TelemetryCleaner
from preprocessing.windowing import WindowAggregator
from preprocessing.features import FeatureExtractor, NUMERICAL_FEATURE_COLUMNS
from preprocessing.pipeline import PreprocessingPipeline
from collector.models import ProcessTelemetry, NetworkTelemetry
from collector.storage import TelemetryStorage


class TestPreprocessing(unittest.TestCase):
    """Test suite for preprocessing components."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.tmp_dir) / "test_echo.db"
        self.csv_path = Path(self.tmp_dir) / "test_features.csv"
        self.storage = TelemetryStorage(db_path=self.db_path)

    def test_clean_process_telemetry(self):
        """Verify cleaning fills missing categoricals and clips negative values."""
        df_raw = pd.DataFrame([
            {
                "timestamp": "2026-11-11T10:00:00Z",
                "pid": "100",
                "ppid": "1",
                "process_name": "worker",
                "username": None,
                "exe": None,
                "cmdline": None,
                "cpu_percent": -5.0,
                "memory_percent": 12.5,
                "memory_rss": 1000,
                "num_threads": 2,
                "status": None,
            }
        ])

        df_clean = TelemetryCleaner.clean_process_telemetry(df_raw)
        self.assertEqual(len(df_clean), 1)
        row = df_clean.iloc[0]
        self.assertEqual(row["pid"], 100)
        self.assertEqual(row["ppid"], 1)
        self.assertEqual(row["username"], "unknown")
        self.assertEqual(row["exe"], "unknown")
        self.assertEqual(row["cmdline"], "")
        self.assertEqual(row["status"], "unknown")
        self.assertEqual(row["cpu_percent"], 0.0)  # Clipped from -5.0

    def test_window_aggregator_5_second_intervals(self):
        """Verify multi-point observations within 5s are properly aggregated."""
        df_proc = pd.DataFrame([
            {
                "timestamp": pd.to_datetime("2026-11-11T10:00:01Z", utc=True),
                "pid": 500,
                "ppid": 1,
                "process_name": "app",
                "username": "user",
                "status": "running",
                "cpu_percent": 10.0,
                "memory_percent": 5.0,
                "memory_rss": 5000,
                "num_threads": 2,
            },
            {
                "timestamp": pd.to_datetime("2026-11-11T10:00:03Z", utc=True),
                "pid": 500,
                "ppid": 1,
                "process_name": "app",
                "username": "user",
                "status": "running",
                "cpu_percent": 30.0,
                "memory_percent": 5.0,
                "memory_rss": 5000,
                "num_threads": 4,
            },
        ])

        df_net = pd.DataFrame([
            {
                "timestamp": pd.to_datetime("2026-11-11T10:00:02Z", utc=True),
                "pid": 500,
                "local_address": "127.0.0.1",
                "remote_address": "1.1.1.1",
            }
        ])

        aggregator = WindowAggregator(window_size_seconds=5)
        df_win = aggregator.generate_windows(df_proc, df_net)

        self.assertEqual(len(df_win), 1)
        row = df_win.iloc[0]
        self.assertEqual(row["pid"], 500)
        self.assertEqual(row["sample_count"], 2)
        self.assertEqual(row["cpu_mean"], 20.0)  # (10 + 30)/2
        self.assertEqual(row["cpu_max"], 30.0)
        self.assertEqual(row["num_threads_max"], 4)
        self.assertEqual(row["open_sockets_count"], 1)
        self.assertEqual(row["distinct_remote_ips"], 1)

    def test_feature_extractor_ratios(self):
        """Verify feature extractor calculates ratios and feature matrix correctly."""
        df_win = pd.DataFrame([
            {
                "window_start": pd.to_datetime("2026-11-11T10:00:00Z", utc=True),
                "pid": 200,
                "process_name": "miner",
                "cpu_mean": 80.0,
                "cpu_max": 90.0,
                "cpu_std": 5.0,
                "memory_mean": 20.0,
                "memory_max": 20.0,
                "memory_rss_mean": 1000000.0,
                "num_threads_mean": 4.0,
                "num_threads_max": 4,
                "open_sockets_count": 2,
                "distinct_remote_ips": 1,
                "sample_count": 1,
            }
        ])

        df_feat = FeatureExtractor.extract_features(df_win)
        self.assertIn("cpu_mem_ratio", df_feat.columns)
        self.assertIn("socket_thread_ratio", df_feat.columns)
        self.assertAlmostEqual(df_feat.iloc[0]["cpu_mem_ratio"], 4.0, places=2)

        X, cols = FeatureExtractor.get_feature_matrix(df_feat)
        self.assertEqual(X.shape[0], 1)
        self.assertEqual(X.shape[1], len(cols))

    def test_pipeline_end_to_end_with_database(self):
        """Seed raw records, execute pipeline, verify CSV and SQLite outputs."""
        # Insert 2 raw records
        self.storage.save_process_telemetry_batch([
            ProcessTelemetry(
                pid=999,
                ppid=1,
                process_name="test_proc",
                username="vboxuser",
                exe="/bin/test_proc",
                cmdline="/bin/test_proc",
                cpu_percent=15.0,
                memory_percent=2.5,
                memory_rss=204800,
                num_threads=2,
                process_start_time="2026-11-11T09:00:00Z",
                status="running",
                timestamp="2026-11-11T10:00:01Z",
            )
        ])
        self.storage.save_network_telemetry_batch([
            NetworkTelemetry(
                pid=999,
                local_address="127.0.0.1",
                local_port=8080,
                remote_address=None,
                remote_port=None,
                status="LISTEN",
                protocol="TCP4",
                timestamp="2026-11-11T10:00:01Z",
            )
        ])

        pipeline = PreprocessingPipeline(
            db_path=self.db_path,
            output_csv_path=self.csv_path,
            window_size_seconds=5,
        )
        df_out = pipeline.run()

        self.assertEqual(len(df_out), 1)
        self.assertTrue(self.csv_path.exists())

        # Check SQLite table using standard sqlite3 connection
        import sqlite3
        with sqlite3.connect(str(self.storage.db_path)) as conn:
            df_sqlite = pd.read_sql_query("SELECT * FROM processed_features WHERE pid=999", conn)
        self.assertEqual(len(df_sqlite), 1)
        self.assertEqual(df_sqlite.iloc[0]["process_name"], "test_proc")


if __name__ == "__main__":
    unittest.main()
