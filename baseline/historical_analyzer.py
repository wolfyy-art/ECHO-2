"""
baseline/historical_analyzer.py
===============================
ECHO — Historical Data Coverage & Telemetry Analysis.

Analyzes stored process telemetry and windowed feature records in SQLite,
determines time bounds, calculates real historical coverage against target
learning periods (24h, 7d, 14d, 30d), and identifies processes with
insufficient observations. Never claims artificial data coverage.
"""

import sys
import logging
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List
import pandas as pd
import sqlite3

from dashboard.database import DB_PATH, _get_connection

logger = logging.getLogger(__name__)


@dataclass
class HistoricalCoverageReport:
    """
    Summary of historical telemetry coverage in the database.
    """
    earliest_timestamp: Optional[str]
    latest_timestamp: Optional[str]
    total_duration_seconds: float
    total_duration_hours: float
    total_duration_days: float
    target_learning_days: float
    coverage_ratio: float
    is_fully_established: bool
    status_label: str
    total_records: int
    unique_processes: int
    unique_process_instances: int
    processes_with_sufficient_data: int
    processes_with_insufficient_data: int
    min_observations_threshold: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class HistoricalAnalyzer:
    """
    Inspects historical processed features and raw telemetry to measure actual temporal depth.
    """

    def __init__(
        self,
        db_path: Path = DB_PATH,
        min_observations_threshold: int = 10,
    ):
        self.db_path = Path(db_path)
        self.min_observations_threshold = min_observations_threshold

    def analyze_coverage(self, target_days: float = 30.0) -> HistoricalCoverageReport:
        """
        Evaluate actual data coverage against a target learning horizon.

        Parameters
        ----------
        target_days : float
            Desired historical learning window in days (e.g. 1.0, 7.0, 14.0, 30.0).

        Returns
        -------
        HistoricalCoverageReport
        """
        conn = _get_connection(self.db_path)
        try:
            # Check if processed_features table exists
            table_check = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='processed_features'"
            ).fetchone()
            if not table_check:
                df_proc = pd.DataFrame()
            else:
                # Query processed_features
                df_proc = pd.read_sql_query(
                    "SELECT window_start, pid, process_name FROM processed_features",
                    conn,
                )
        finally:
            conn.close()

        if df_proc.empty:
            return HistoricalCoverageReport(
                earliest_timestamp=None,
                latest_timestamp=None,
                total_duration_seconds=0.0,
                total_duration_hours=0.0,
                total_duration_days=0.0,
                target_learning_days=target_days,
                coverage_ratio=0.0,
                is_fully_established=False,
                status_label="NO_DATA",
                total_records=0,
                unique_processes=0,
                unique_process_instances=0,
                processes_with_sufficient_data=0,
                processes_with_insufficient_data=0,
                min_observations_threshold=self.min_observations_threshold,
            )

        df_proc["dt"] = pd.to_datetime(df_proc["window_start"], utc=True, errors="coerce")
        df_proc = df_proc.dropna(subset=["dt"]).sort_values("dt")

        min_dt = df_proc["dt"].min()
        max_dt = df_proc["dt"].max()

        delta = max_dt - min_dt
        duration_sec = delta.total_seconds()
        duration_hours = round(duration_sec / 3600.0, 4)
        duration_days = round(duration_sec / 86400.0, 4)

        target_sec = max(1.0, target_days * 86400.0)
        coverage_ratio = min(1.0, round(duration_sec / target_sec, 6))

        # A baseline is only marked 'established' when actual coverage spans >= 90% of target
        is_established = coverage_ratio >= 0.90
        status_label = "ESTABLISHED" if is_established else "PRELIMINARY"

        # Count observations per process name
        counts_per_pname = df_proc.groupby("process_name")["dt"].count()
        sufficient = int((counts_per_pname >= self.min_observations_threshold).sum())
        insufficient = int((counts_per_pname < self.min_observations_threshold).sum())

        unique_procs = int(df_proc["process_name"].nunique())
        unique_instances = int(df_proc.groupby(["pid", "process_name"]).ngroups)

        return HistoricalCoverageReport(
            earliest_timestamp=min_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            latest_timestamp=max_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            total_duration_seconds=round(duration_sec, 2),
            total_duration_hours=duration_hours,
            total_duration_days=duration_days,
            target_learning_days=target_days,
            coverage_ratio=coverage_ratio,
            is_fully_established=is_established,
            status_label=status_label,
            total_records=len(df_proc),
            unique_processes=unique_procs,
            unique_process_instances=unique_instances,
            processes_with_sufficient_data=sufficient,
            processes_with_insufficient_data=insufficient,
            min_observations_threshold=self.min_observations_threshold,
        )

    def get_process_observation_counts(self) -> pd.DataFrame:
        """Return table of observation counts per process."""
        conn = _get_connection(self.db_path)
        try:
            sql = """
                SELECT process_name, count(*) as observation_count,
                       min(window_start) as first_seen,
                       max(window_start) as last_seen,
                       count(DISTINCT pid) as distinct_pids
                FROM processed_features
                GROUP BY process_name
                ORDER BY observation_count DESC
            """
            return pd.read_sql_query(sql, conn)
        finally:
            conn.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="ECHO — Historical Telemetry Coverage Analyzer")
    parser.add_argument("--days", type=float, default=30.0, help="Target learning window in days (default: 30)")
    parser.add_argument("--db-path", type=str, default=None, help="SQLite database path")
    args = parser.parse_args()

    db_path = Path(args.db_path) if args.db_path else DB_PATH
    analyzer = HistoricalAnalyzer(db_path=db_path)
    report = analyzer.analyze_coverage(target_days=args.days)

    print("=" * 70)
    print(" ECHO HISTORICAL COVERAGE REPORT")
    print("=" * 70)
    print(f" Target Period       : {report.target_learning_days:.1f} days ({report.target_learning_days * 24:.1f} hours)")
    print(f" Earliest Timestamp  : {report.earliest_timestamp or 'N/A'}")
    print(f" Latest Timestamp    : {report.latest_timestamp or 'N/A'}")
    print(f" Actual Duration     : {report.total_duration_hours:.2f} hours ({report.total_duration_days:.4f} days)")
    print(f" Historical Coverage : {report.coverage_ratio * 100:.4f}% of target")
    print(f" Baseline Status     : {report.status_label} (Preliminary profiles applied until full depth reached)")
    print(f" Total Records       : {report.total_records}")
    print(f" Unique Processes    : {report.unique_processes} (Instances: {report.unique_process_instances})")
    print(f" Sufficient Data     : {report.processes_with_sufficient_data} processes (>= {report.min_observations_threshold} obs)")
    print(f" Insufficient Data   : {report.processes_with_insufficient_data} processes (< {report.min_observations_threshold} obs)")
    print("=" * 70)


if __name__ == "__main__":
    main()
