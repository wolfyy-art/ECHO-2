"""
preprocessing/cleaner.py
========================
ECHO — Telemetry Data Validation and Cleaning.

Validates raw process and network telemetry, handles missing values,
and ensures proper data types for downstream windowing and ML feature extraction.
"""

import logging
from typing import Optional
import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)


class TelemetryCleaner:
    """
    Cleans and standardizes raw telemetry DataFrames.
    """

    @staticmethod
    def clean_process_telemetry(df: pd.DataFrame) -> pd.DataFrame:
        """
        Validate and sanitize raw process telemetry records.

        Steps:
        1. Ensure required columns are present.
        2. Parse timestamps to UTC datetime.
        3. Fill missing categorical fields (username, exe, cmdline).
        4. Validate numeric boundaries (cpu_percent >= 0, memory_percent >= 0).
        5. Deduplicate exact duplicate readings.

        Parameters
        ----------
        df : pd.DataFrame
            Raw process telemetry data.

        Returns
        -------
        pd.DataFrame
            Cleaned and validated DataFrame.
        """
        if df.empty:
            return pd.DataFrame()

        df_clean = df.copy()

        # Parse timestamp to UTC datetime
        if "timestamp" in df_clean.columns:
            df_clean["timestamp"] = pd.to_datetime(df_clean["timestamp"], utc=True, errors="coerce")
            df_clean = df_clean.dropna(subset=["timestamp"])

        if "process_start_time" in df_clean.columns:
            df_clean["process_start_time"] = pd.to_datetime(df_clean["process_start_time"], utc=True, errors="coerce")

        # Fill missing string/categorical metadata
        if "username" in df_clean.columns:
            df_clean["username"] = df_clean["username"].fillna("unknown")
        if "exe" in df_clean.columns:
            df_clean["exe"] = df_clean["exe"].fillna("unknown")
        if "cmdline" in df_clean.columns:
            df_clean["cmdline"] = df_clean["cmdline"].fillna("")
        if "status" in df_clean.columns:
            df_clean["status"] = df_clean["status"].fillna("unknown")
        if "process_name" in df_clean.columns:
            df_clean["process_name"] = df_clean["process_name"].fillna("unknown")

        # Enforce non-negative numeric constraints
        numeric_cols = ["cpu_percent", "memory_percent", "memory_rss", "num_threads"]
        for col in numeric_cols:
            if col in df_clean.columns:
                df_clean[col] = pd.to_numeric(df_clean[col], errors="coerce").fillna(0.0)
                df_clean[col] = df_clean[col].clip(lower=0.0)

        # Ensure PID & PPID are integer
        if "pid" in df_clean.columns:
            df_clean["pid"] = df_clean["pid"].astype(int)
        if "ppid" in df_clean.columns:
            df_clean["ppid"] = df_clean["ppid"].astype(int)

        # Sort chronologically
        df_clean = df_clean.sort_values(by=["timestamp", "pid"]).reset_index(drop=True)
        return df_clean

    @staticmethod
    def clean_network_telemetry(df: pd.DataFrame) -> pd.DataFrame:
        """
        Validate and sanitize raw network telemetry records.

        Parameters
        ----------
        df : pd.DataFrame
            Raw network telemetry data.

        Returns
        -------
        pd.DataFrame
            Cleaned and validated network DataFrame.
        """
        if df.empty:
            return pd.DataFrame()

        df_net = df.copy()

        if "timestamp" in df_net.columns:
            df_net["timestamp"] = pd.to_datetime(df_net["timestamp"], utc=True, errors="coerce")
            df_net = df_net.dropna(subset=["timestamp"])

        if "pid" in df_net.columns:
            df_net["pid"] = df_net["pid"].astype(int)

        if "local_address" in df_net.columns:
            df_net["local_address"] = df_net["local_address"].fillna("")
        if "remote_address" in df_net.columns:
            df_net["remote_address"] = df_net["remote_address"].fillna("")
        if "status" in df_net.columns:
            df_net["status"] = df_net["status"].fillna("UNKNOWN")
        if "protocol" in df_net.columns:
            df_net["protocol"] = df_net["protocol"].fillna("UNKNOWN")

        return df_net.reset_index(drop=True)
