"""
models/train.py
===============
ECHO — Phase 4 & 5: Model Training, Baseline Learning & Artifact Serialization
Author: Suhani (M2)

This script:
1. Generates or loads multi-process host telemetry representing realistic
   workloads (Web service, File transfer, Background daemons).
2. Populates processed feature tables and CSV in data/.
3. Learns per-process statistical baselines (Median & MAD) via BehaviouralProfiler.
4. Fits the unsupervised Isolation Forest ensemble (100 trees, 13 features).
5. Serializes the trained model artifact to models/isolation_forest.joblib.
6. Writes training metadata to models/metadata.json.
"""

import os
import sys
import json
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, List, Tuple

import numpy as np
import pandas as pd

# Add project root to sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from dashboard.database import DB_PATH, init_database, _get_connection, _utc_now
from preprocessing.pipeline import PreprocessingPipeline
from baseline.profiler import BehaviouralProfiler
from baseline.storage import BaselineStorage
from detection.isolation_forest import (
    ProcessIsolationForest,
    IsolationForestConfig,
    APPROVED_FEATURE_COLUMNS,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ECHO_TRAIN")

MODELS_DIR = _PROJECT_ROOT / "models"
MODEL_FILE = MODELS_DIR / "isolation_forest.joblib"
METADATA_FILE = MODELS_DIR / "metadata.json"
DATA_DIR = _PROJECT_ROOT / "data"
PROCESSED_CSV = DATA_DIR / "processed" / "process_features.csv"


def generate_baseline_telemetry(n_windows: int = 40) -> pd.DataFrame:
    """
    Generate realistic multi-process baseline telemetry across discrete 5-second windows.
    Covers:
      - Process A: web_service (nginx / python web client)
      - Process B: file_transfer (rsync / backup daemon)
      - Process C (Normal Phase): background_worker
      - System daemons: cron, dbus-daemon, systemd-journald, sshd
    """
    np.random.seed(42)
    rows: List[Dict[str, Any]] = []

    base_time = datetime.now(timezone.utc) - timedelta(seconds=n_windows * 5)

    process_specs = [
        # (name, pid, username, ppid, cpu_mean_range, mem_mb_range, threads, sockets, ips)
        ("nginx", 1010, "www-data", 1, (1.0, 3.5), (25.0, 35.0), 4, (3, 8), (2, 5)),
        ("rsync_backup", 1020, "backup", 1, (12.0, 24.0), (80.0, 120.0), 3, (15, 30), (1, 3)),
        ("worker_daemon", 1030, "vboxuser", 1000, (0.2, 0.8), (15.0, 20.0), 2, (0, 2), (0, 1)),
        ("cron", 450, "root", 1, (0.0, 0.1), (3.0, 5.0), 1, (0, 0), (0, 0)),
        ("dbus-daemon", 480, "messagebus", 1, (0.1, 0.5), (4.0, 6.0), 1, (1, 2), (0, 0)),
        ("systemd-journald", 320, "root", 1, (0.2, 1.0), (18.0, 25.0), 1, (0, 0), (0, 0)),
        ("sshd", 650, "root", 1, (0.1, 0.4), (6.0, 8.0), 1, (1, 3), (1, 2)),
    ]

    for w_idx in range(n_windows):
        window_start = (base_time + timedelta(seconds=w_idx * 5)).strftime("%Y-%m-%dT%H:%M:%SZ")

        for name, pid, user, ppid, cpu_range, mem_range, threads, sock_range, ip_range in process_specs:
            cpu_m = float(np.random.uniform(cpu_range[0], cpu_range[1]))
            cpu_mx = float(cpu_m + np.random.uniform(0.1, 1.5))
            cpu_s = float(np.random.uniform(0.01, 0.5))

            mem_mb = float(np.random.uniform(mem_range[0], mem_range[1]))
            mem_pct = float(round((mem_mb / 4096.0) * 100.0, 3))
            mem_rss = int(mem_mb * 1024 * 1024)

            n_threads = int(threads)
            n_sockets = int(np.random.randint(sock_range[0], sock_range[1] + 1))
            n_ips = int(np.random.randint(ip_range[0], ip_range[1] + 1))

            cpu_mem_ratio = float(round(cpu_m / max(mem_pct, 0.01), 4))
            socket_thread_ratio = float(round(n_sockets / max(n_threads, 1), 4))

            rows.append({
                "window_start": window_start,
                "pid": pid,
                "ppid": ppid,
                "process_name": name,
                "username": user,
                "status": "running",
                "cpu_mean": round(cpu_m, 2),
                "cpu_max": round(cpu_mx, 2),
                "cpu_std": round(cpu_s, 3),
                "memory_mean": round(mem_pct, 3),
                "memory_max": round(mem_pct * 1.05, 3),
                "memory_rss_mean": mem_rss,
                "num_threads_mean": float(n_threads),
                "num_threads_max": n_threads,
                "open_sockets_count": n_sockets,
                "distinct_remote_ips": n_ips,
                "sample_count": 5,
                "cpu_mem_ratio": cpu_mem_ratio,
                "socket_thread_ratio": socket_thread_ratio,
            })

    return pd.DataFrame(rows)


def populate_database_and_csv(df_features: pd.DataFrame, db_path: Path = DB_PATH) -> None:
    """Store generated features into SQLite processed_features and CSV."""
    init_database(db_path)
    pipeline = PreprocessingPipeline(db_path=db_path)

    # Save to SQLite processed_features
    conn = _get_connection(db_path)
    try:
        with conn:
            for _, row in df_features.iterrows():
                conn.execute(
                    """
                    INSERT OR REPLACE INTO processed_features (
                        window_start, pid, ppid, process_name, username, status,
                        cpu_mean, cpu_max, cpu_std, memory_mean, memory_max,
                        memory_rss_mean, num_threads_mean, num_threads_max,
                        open_sockets_count, distinct_remote_ips, sample_count,
                        cpu_mem_ratio, socket_thread_ratio
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        row["window_start"], row["pid"], row["ppid"], row["process_name"],
                        row["username"], row["status"], row["cpu_mean"], row["cpu_max"],
                        row["cpu_std"], row["memory_mean"], row["memory_max"],
                        row["memory_rss_mean"], row["num_threads_mean"], row["num_threads_max"],
                        row["open_sockets_count"], row["distinct_remote_ips"], row["sample_count"],
                        row["cpu_mem_ratio"], row["socket_thread_ratio"],
                    )
                )
        logger.info("Saved %d feature records into SQLite 'processed_features'.", len(df_features))
    finally:
        conn.close()

    # Save to CSV
    PROCESSED_CSV.parent.mkdir(parents=True, exist_ok=True)
    df_features.to_csv(PROCESSED_CSV, index=False)
    logger.info("Exported feature matrix to CSV: %s", PROCESSED_CSV)


def train_and_serialize_models(df_features: pd.DataFrame) -> Tuple[ProcessIsolationForest, Dict[str, Any]]:
    """
    Fit Isolation Forest and MAD Profiler, then serialize artifacts.
    """
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Learn MAD Behavioural Profiles
    logger.info("Computing per-process MAD baselines across %d records...", len(df_features))
    profiler = BehaviouralProfiler(db_path=DB_PATH, model_version="1.0.0")
    baselines = profiler.learn_all_baselines(days=30.0)
    logger.info("Generated and saved %d process baseline profiles into 'process_baselines'.", len(baselines))

    # 2. Fit Isolation Forest
    logger.info("Training Isolation Forest ensemble (n_estimators=100, contamination=0.05)...")
    config = IsolationForestConfig(n_estimators=100, random_state=42, contamination=0.05)
    model = ProcessIsolationForest(config=config)
    model.fit(df_features)

    # 3. Save Model Artifact (.joblib)
    saved_path = model.save(MODEL_FILE)
    logger.info("Model artifact successfully serialized to: %s", saved_path)

    # 4. Save Metadata
    metadata = {
        "model_type": "IsolationForest",
        "algorithm": "scikit-learn.ensemble.IsolationForest",
        "version": "1.0.0",
        "trained_at_utc": _utc_now(),
        "training_samples": len(df_features),
        "unique_processes": int(df_features["process_name"].nunique()),
        "approved_features": list(APPROVED_FEATURE_COLUMNS),
        "hyperparameters": config.to_dict(),
        "decision_offset": float(model.score_offset_),
        "artifact_path": str(MODEL_FILE.name),
        "features_csv": str(PROCESSED_CSV.name),
    }

    with open(METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    logger.info("Model metadata saved to: %s", METADATA_FILE)

    return model, metadata


def main():
    print("=" * 70)
    print(" ECHO M2: Data Generation, Baseline Learning & ML Training Pipeline")
    print("=" * 70)

    # Step 1: Generate Telemetry
    logger.info("[Step 1] Synthesizing multi-process baseline telemetry (40 windows = 200s)...")
    df = generate_baseline_telemetry(n_windows=40)

    # Step 2: Persist Data
    logger.info("[Step 2] Storing telemetry in SQLite and CSV...")
    populate_database_and_csv(df)

    # Step 3: Train and Serialize
    logger.info("[Step 3] Training ML Isolation Forest and computing MAD baselines...")
    model, metadata = train_and_serialize_models(df)

    # Step 4: Quick Sanity Test
    sample_scores = model.score_samples(df.head(5))
    logger.info("Sanity check on normal samples — scores: %s (all < 0.50 is normal)", sample_scores)

    print("=" * 70)
    print(" Training Complete! Model and baselines are now available in models/")
    print(f" • Model Artifact : {MODEL_FILE}")
    print(f" • Metadata       : {METADATA_FILE}")
    print(f" • Baselines      : {len(df['process_name'].unique())} profiles in SQLite")
    print("=" * 70)


if __name__ == "__main__":
    main()
