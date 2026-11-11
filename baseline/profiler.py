"""
baseline/profiler.py
====================
ECHO — Behavioural Profiler & Baseline Learner.

Builds statistical behavioural profiles for processes using historical telemetry.
Calculates medians, means, min, max, variance, and MAD across CPU, RAM,
network sockets, remote IPs, and thread counts.
"""

import uuid
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone, timedelta
from pathlib import Path
import numpy as np
import pandas as pd

from dashboard.database import DB_PATH, _get_connection
from baseline.mad import compute_median_and_mad
from baseline.historical_analyzer import HistoricalAnalyzer
from baseline.storage import BaselineStorage
from baseline.identity import build_process_type_identity, build_process_instance_identity

logger = logging.getLogger(__name__)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


class BehaviouralProfiler:
    """
    Computes per-process statistical baselines with MAD dispersion metrics.
    """

    def __init__(
        self,
        db_path: Path = DB_PATH,
        min_observations: int = 3,
        model_version: str = "1.0.0",
    ):
        self.db_path = Path(db_path)
        self.min_observations = min_observations
        self.model_version = model_version
        self.storage = BaselineStorage(self.db_path)
        self.analyzer = HistoricalAnalyzer(self.db_path, min_observations_threshold=min_observations)

    def load_historical_data(self, days: float = 30.0) -> pd.DataFrame:
        """
        Load processed features within the specified rolling day window.
        """
        conn = _get_connection(self.db_path)
        try:
            # Query all processed features
            df = pd.read_sql_query("SELECT * FROM processed_features", conn)
            if df.empty:
                return df

            df["dt"] = pd.to_datetime(df["window_start"], utc=True, errors="coerce")
            df = df.dropna(subset=["dt"]).sort_values("dt")

            max_dt = df["dt"].max()
            cutoff = max_dt - timedelta(days=days)
            df_filtered = df[df["dt"] >= cutoff].copy()
            return df_filtered
        finally:
            conn.close()

    def profile_process_group(
        self,
        process_name: str,
        df_group: pd.DataFrame,
        target_days: float = 30.0,
    ) -> Dict[str, Any]:
        """
        Compute MAD and parametric statistics for a grouped process dataset.
        """
        obs_count = len(df_group)
        first_seen = df_group["dt"].min().strftime("%Y-%m-%dT%H:%M:%SZ")
        last_seen = df_group["dt"].max().strftime("%Y-%m-%dT%H:%M:%SZ")

        # Identity resolution: construct canonical process-type identity
        distinct_pids = df_group["pid"].unique()
        pid_ref = int(distinct_pids[0]) if len(distinct_pids) == 1 else None
        username = str(df_group["username"].iloc[0]) if "username" in df_group.columns else "unknown"
        proc_identity = build_process_type_identity(process_name=process_name, username=username)

        # 1. CPU Metrics
        cpu_vals = df_group["cpu_mean"].to_numpy()
        cpu_med, cpu_mad = compute_median_and_mad(cpu_vals)
        cpu_mean = float(np.mean(cpu_vals))
        cpu_min = float(np.min(cpu_vals))
        cpu_max = float(np.max(cpu_vals))
        cpu_std = float(np.std(cpu_vals))

        # 2. Memory Metrics
        mem_vals = df_group["memory_mean"].to_numpy()
        mem_med, mem_mad = compute_median_and_mad(mem_vals)
        mem_mean = float(np.mean(mem_vals))
        mem_max = float(np.max(mem_vals))

        # 3. Socket Metrics
        sock_vals = df_group["open_sockets_count"].to_numpy()
        sock_med, sock_mad = compute_median_and_mad(sock_vals)
        sock_max = int(np.max(sock_vals)) if len(sock_vals) > 0 else 0

        # 4. Remote IP Metrics
        rip_vals = df_group["distinct_remote_ips"].to_numpy()
        rip_med, rip_mad = compute_median_and_mad(rip_vals)

        # 5. Thread Metrics
        th_vals = df_group["num_threads_mean"].to_numpy()
        th_med, th_mad = compute_median_and_mad(th_vals)
        th_max = int(df_group["num_threads_max"].max()) if "num_threads_max" in df_group.columns else int(np.max(th_vals))

        # Coverage assessment
        duration_days = (df_group["dt"].max() - df_group["dt"].min()).total_seconds() / 86400.0
        is_established = (duration_days >= (0.90 * target_days)) and (obs_count >= 100)
        baseline_status = "established" if is_established else "preliminary"

        baseline_id = f"base-{uuid.uuid4().hex[:12]}"
        now = _utc_now()

        return {
            "baseline_id": baseline_id,
            "process_identity": proc_identity,
            "pid_reference": pid_ref,
            "process_name": process_name,
            "executable_identity": str(df_group["username"].iloc[0]) if "username" in df_group.columns else "unknown",
            "learning_period_days": round(target_days, 2),
            "observation_count": obs_count,
            "cpu_median": cpu_med,
            "cpu_mean": round(cpu_mean, 4),
            "cpu_min": round(cpu_min, 4),
            "cpu_max": round(cpu_max, 4),
            "cpu_std": round(cpu_std, 4),
            "cpu_mad": cpu_mad,
            "memory_median": mem_med,
            "memory_mean": round(mem_mean, 4),
            "memory_max": round(mem_max, 4),
            "memory_mad": mem_mad,
            "socket_median": sock_med,
            "socket_max": sock_max,
            "socket_mad": sock_mad,
            "remote_ip_median": rip_med,
            "remote_ip_mad": rip_mad,
            "thread_median": th_med,
            "thread_max": th_max,
            "thread_mad": th_mad,
            "baseline_start": first_seen,
            "baseline_end": last_seen,
            "model_version": self.model_version,
            "baseline_status": baseline_status,
            "created_at": now,
            "updated_at": now,
        }

    def learn_all_baselines(self, days: float = 30.0) -> List[Dict[str, Any]]:
        """
        Analyze processed historical features and learn individual profiles for all observed processes.
        """
        df = self.load_historical_data(days=days)
        if df.empty:
            logger.warning("No historical telemetry available to learn baselines.")
            return []

        baselines: List[Dict[str, Any]] = []

        # Group by process_name
        grouped = df.groupby("process_name")
        for pname, group in grouped:
            if len(group) >= self.min_observations:
                profile = self.profile_process_group(pname, group, target_days=days)
                baselines.append(profile)

        # Persist to database
        self.storage.save_baselines(baselines)
        logger.info("Learned and saved %d behavioural baselines.", len(baselines))
        return baselines


def main():
    import argparse
    parser = argparse.ArgumentParser(description="ECHO — Behavioural Baseline Profiler")
    parser.add_argument("--days", type=float, default=30.0, help="Target learning window in days (default: 30)")
    parser.add_argument("--db-path", type=str, default=None, help="SQLite database path")
    args = parser.parse_args()

    db_path = Path(args.db_path) if args.db_path else DB_PATH
    profiler = BehaviouralProfiler(db_path=db_path)
    baselines = profiler.learn_all_baselines(days=args.days)

    print("=" * 70)
    print(" ECHO BEHAVIOURAL PROFILING SUMMARY")
    print("=" * 70)
    print(f" Total Baselines Learned : {len(baselines)}")
    preliminary = sum(1 for b in baselines if b["baseline_status"] == "preliminary")
    established = sum(1 for b in baselines if b["baseline_status"] == "established")
    print(f" Preliminary Baselines   : {preliminary} (Flagged because actual depth < {args.days}d)")
    print(f" Established Baselines   : {established}")
    if baselines:
        print("\nSample Baseline Profiles:")
        for b in baselines[:5]:
            print(f"  • {b['process_name']:<25} (Obs: {b['observation_count']:>3}) | "
                  f"CPU med={b['cpu_median']:.2f}% (MAD={b['cpu_mad']:.2f}) | "
                  f"RAM med={b['memory_median']:.2f}% (MAD={b['memory_mad']:.2f}) | "
                  f"Status: {b['baseline_status'].upper()}")
    print("=" * 70)


if __name__ == "__main__":
    main()
