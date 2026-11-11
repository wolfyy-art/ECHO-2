"""
preprocessing/pipeline.py
=========================
ECHO — End-to-End Preprocessing Pipeline.

Orchestrates raw telemetry extraction from SQLite, cleaning, 5-second windowing,
feature extraction, and persistence to CSV and SQLite.
"""

import sqlite3
import logging
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
import pandas as pd

from dashboard.database import DB_PATH, _get_connection
from preprocessing.cleaner import TelemetryCleaner
from preprocessing.windowing import WindowAggregator
from preprocessing.features import FeatureExtractor

logger = logging.getLogger(__name__)

# Non-destructive schema extension for processed features with unique constraint for idempotency
_CREATE_PROCESSED_FEATURES_TABLE = """
CREATE TABLE IF NOT EXISTS processed_features (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    window_start            TEXT    NOT NULL,
    pid                     INTEGER NOT NULL,
    ppid                    INTEGER NOT NULL,
    process_name            TEXT    NOT NULL,
    username                TEXT,
    status                  TEXT,
    cpu_mean                REAL    NOT NULL DEFAULT 0.0,
    cpu_max                 REAL    NOT NULL DEFAULT 0.0,
    cpu_std                 REAL    NOT NULL DEFAULT 0.0,
    memory_mean             REAL    NOT NULL DEFAULT 0.0,
    memory_max              REAL    NOT NULL DEFAULT 0.0,
    memory_rss_mean         REAL    NOT NULL DEFAULT 0.0,
    num_threads_mean        REAL    NOT NULL DEFAULT 1.0,
    num_threads_max         INTEGER NOT NULL DEFAULT 1,
    open_sockets_count      INTEGER NOT NULL DEFAULT 0,
    distinct_remote_ips     INTEGER NOT NULL DEFAULT 0,
    sample_count            INTEGER NOT NULL DEFAULT 1,
    cpu_mem_ratio           REAL    NOT NULL DEFAULT 0.0,
    socket_thread_ratio     REAL    NOT NULL DEFAULT 0.0,
    CONSTRAINT uq_window_pid_pname UNIQUE (window_start, pid, process_name)
);
"""

_CREATE_PROCESSED_INDEXES = [
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_pf_unique ON processed_features(window_start, pid, process_name);",
    "CREATE INDEX IF NOT EXISTS idx_pf_window_pid   ON processed_features(window_start, pid);",
    "CREATE INDEX IF NOT EXISTS idx_pf_pname        ON processed_features(process_name);",
]


class PreprocessingPipeline:
    """
    Coordinates reading raw telemetry, cleaning, 5-second windowing, and persistence.
    """

    def __init__(
        self,
        db_path: Path = DB_PATH,
        output_csv_path: Optional[Path] = None,
        window_size_seconds: int = 5,
    ):
        self.db_path = Path(db_path)
        self.output_csv_path = (
            Path(output_csv_path)
            if output_csv_path
            else self.db_path.parent / "processed" / "process_features.csv"
        )
        self.window_size_seconds = window_size_seconds
        self.cleaner = TelemetryCleaner()
        self.aggregator = WindowAggregator(window_size_seconds=self.window_size_seconds)
        self.extractor = FeatureExtractor()

        # Ensure processed table exists
        self._init_processed_table()

    def _init_processed_table(self) -> None:
        """Create processed_features table if it does not exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = _get_connection(self.db_path)
        try:
            with conn:
                conn.execute(_CREATE_PROCESSED_FEATURES_TABLE)
                for idx in _CREATE_PROCESSED_INDEXES:
                    conn.execute(idx)
        finally:
            conn.close()

    def load_raw_data(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Load raw process and network telemetry tables from SQLite."""
        conn = _get_connection(self.db_path)
        try:
            df_proc = pd.read_sql_query("SELECT * FROM raw_process_telemetry", conn)
            df_net = pd.read_sql_query("SELECT * FROM raw_network_telemetry", conn)
            return df_proc, df_net
        finally:
            conn.close()

    def run(self) -> pd.DataFrame:
        """
        Execute full pipeline: Load -> Clean -> Window (5s) -> Extract Features -> Save.

        Returns
        -------
        pd.DataFrame
            Final processed features DataFrame.
        """
        logger.info("Executing PreprocessingPipeline (window=%ds)...", self.window_size_seconds)

        # 1. Load raw
        df_proc_raw, df_net_raw = self.load_raw_data()
        logger.info("Loaded %d raw process records, %d raw network records.", len(df_proc_raw), len(df_net_raw))

        if df_proc_raw.empty:
            logger.warning("No raw process telemetry found in %s.", self.db_path)
            return pd.DataFrame()

        # 2. Clean
        df_proc_clean = self.cleaner.clean_process_telemetry(df_proc_raw)
        df_net_clean = self.cleaner.clean_network_telemetry(df_net_raw)

        # 3. Time Windows (5 seconds)
        df_windows = self.aggregator.generate_windows(df_proc_clean, df_net_clean)
        logger.info("Generated %d windowed records.", len(df_windows))

        # 4. Feature Extraction
        df_features = self.extractor.extract_features(df_windows)

        # 5. Save to CSV and SQLite
        self.save_features(df_features)

        logger.info("Preprocessing complete. Output saved to %s and SQLite.", self.output_csv_path)
        return df_features

    def save_features(self, df_features: pd.DataFrame) -> None:
        """
        Save features to CSV and insert into SQLite processed_features idempotently.
        Uses INSERT OR REPLACE to prevent duplicate records on re-runs.
        """
        if df_features.empty:
            return

        # Ensure output directory exists
        self.output_csv_path.parent.mkdir(parents=True, exist_ok=True)
        df_features.to_csv(self.output_csv_path, index=False)

        # Format dataframe for SQLite table insertion
        db_cols = [
            "window_start", "pid", "ppid", "process_name", "username", "status",
            "cpu_mean", "cpu_max", "cpu_std", "memory_mean", "memory_max",
            "memory_rss_mean", "num_threads_mean", "num_threads_max",
            "open_sockets_count", "distinct_remote_ips", "sample_count",
            "cpu_mem_ratio", "socket_thread_ratio",
        ]

        df_db = df_features.copy()
        if "window_start_str" in df_db.columns:
            df_db["window_start"] = df_db["window_start_str"]
        else:
            df_db["window_start"] = df_db["window_start"].astype(str)

        existing_cols = [c for c in db_cols if c in df_db.columns]

        conn = _get_connection(self.db_path)
        try:
            with conn:
                placeholders = ", ".join(["?"] * len(existing_cols))
                col_names = ", ".join(existing_cols)
                sql = f"INSERT OR REPLACE INTO processed_features ({col_names}) VALUES ({placeholders})"
                records = [tuple(row) for row in df_db[existing_cols].to_numpy()]
                conn.executemany(sql, records)
        finally:
            conn.close()


def main():
    """Command-line runner for preprocessing pipeline."""
    import argparse
    parser = argparse.ArgumentParser(description="ECHO — Telemetry Preprocessing Pipeline")
    parser.add_argument("--db-path", type=str, default=None, help="Path to SQLite database")
    parser.add_argument("--output-csv", type=str, default=None, help="Path to output CSV")
    parser.add_argument("--window", type=int, default=5, help="Time window size in seconds (default: 5)")

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    db_path = Path(args.db_path) if args.db_path else DB_PATH
    output_csv = Path(args.output_csv) if args.output_csv else None

    pipeline = PreprocessingPipeline(
        db_path=db_path,
        output_csv_path=output_csv,
        window_size_seconds=args.window,
    )
    df = pipeline.run()
    print(f"\nSuccessfully generated {len(df)} processed feature records across 5-second windows.")


if __name__ == "__main__":
    main()
