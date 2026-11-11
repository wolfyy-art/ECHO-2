"""
preprocessing/windowing.py
==========================
ECHO — Time-Window Aggregator.

Slices cleaned continuous telemetry into configurable time windows
(default: 5 seconds) per process to compute temporal behavioral dynamics.
"""

import logging
from typing import Optional
import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)


class WindowAggregator:
    """
    Partitions process and socket telemetry into fixed time intervals
    and generates windowed feature summaries.
    """

    def __init__(self, window_size_seconds: int = 5):
        if window_size_seconds <= 0:
            raise ValueError(f"window_size_seconds must be positive (> 0), got {window_size_seconds}")
        self.window_size_seconds = window_size_seconds

    def generate_windows(
        self,
        df_proc: pd.DataFrame,
        df_net: Optional[pd.DataFrame] = None,
    ) -> pd.DataFrame:
        """
        Group process telemetry into fixed time windows and join network socket density.

        Parameters
        ----------
        df_proc : pd.DataFrame
            Cleaned process telemetry with datetime timestamp.
        df_net : Optional[pd.DataFrame]
            Cleaned network socket telemetry.

        Returns
        -------
        pd.DataFrame
            Aggregated time-window feature dataset.
        """
        if df_proc.empty:
            return pd.DataFrame()

        df = df_proc.copy()

        # Floor timestamps to the nearest window boundary (e.g., 5s slots)
        freq_str = f"{self.window_size_seconds}s"
        df["window_start"] = df["timestamp"].dt.floor(freq_str)

        # Calculate network connection counts per PID within each window
        net_counts = {}
        if df_net is not None and not df_net.empty:
            df_n = df_net.copy()
            df_n["window_start"] = df_n["timestamp"].dt.floor(freq_str)
            # Count connections and count distinct remote endpoints
            grouped_net = df_n.groupby(["window_start", "pid"]).agg(
                open_sockets_count=("local_address", "count"),
                distinct_remote_ips=("remote_address", lambda x: len(set(filter(None, x)))),
            ).reset_index()
        else:
            grouped_net = pd.DataFrame(columns=["window_start", "pid", "open_sockets_count", "distinct_remote_ips"])

        # Aggregate process telemetry per (window_start, pid, process_name)
        grouped = df.groupby(["window_start", "pid", "process_name"]).agg(
            ppid=("ppid", "first"),
            username=("username", "first"),
            status=("status", "first"),
            cpu_mean=("cpu_percent", "mean"),
            cpu_max=("cpu_percent", "max"),
            cpu_std=("cpu_percent", lambda x: float(np.std(x)) if len(x) > 1 else 0.0),
            memory_mean=("memory_percent", "mean"),
            memory_max=("memory_percent", "max"),
            memory_rss_mean=("memory_rss", "mean"),
            num_threads_mean=("num_threads", "mean"),
            num_threads_max=("num_threads", "max"),
            sample_count=("timestamp", "count"),
        ).reset_index()

        # Merge network statistics
        if not grouped_net.empty:
            merged = pd.merge(grouped, grouped_net, on=["window_start", "pid"], how="left")
            merged["open_sockets_count"] = merged["open_sockets_count"].fillna(0).astype(int)
            merged["distinct_remote_ips"] = merged["distinct_remote_ips"].fillna(0).astype(int)
        else:
            merged = grouped
            merged["open_sockets_count"] = 0
            merged["distinct_remote_ips"] = 0

        # Sort cleanly
        merged["window_start_str"] = merged["window_start"].dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        merged = merged.sort_values(by=["window_start", "pid"]).reset_index(drop=True)
        return merged
