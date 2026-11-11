"""
baseline/comparator.py
======================
ECHO — Baseline Deviation & Anomaly Comparator.

Compares incoming processed feature windows against established process baselines.
Computes feature-level modified Z-scores and generates structured behavioral
anomaly assessments without performing automated termination.
"""

import logging
from typing import Dict, Any, Optional, List
from pathlib import Path
import pandas as pd

from dashboard.database import DB_PATH, _get_connection
from baseline.mad import MADScorer
from baseline.storage import BaselineStorage

logger = logging.getLogger(__name__)


class BaselineComparator:
    """
    Evaluates live or batch feature windows against process behavioural baselines.
    """

    def __init__(
        self,
        db_path: Path = DB_PATH,
        anomaly_threshold: float = 3.5,
    ):
        self.db_path = Path(db_path)
        self.anomaly_threshold = anomaly_threshold
        self.storage = BaselineStorage(self.db_path)
        self.scorer = MADScorer(anomaly_threshold=anomaly_threshold)

    def compare_window(
        self,
        record: Dict[str, Any],
        baseline: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Compare an individual process observation against its learned baseline.

        Parameters
        ----------
        record : Dict[str, Any]
            Window feature record (e.g. from processed_features).
        baseline : Optional[Dict[str, Any]]
            Baseline record. If None, fetched automatically by process_name.

        Returns
        -------
        Dict[str, Any]
            Comprehensive evaluation including per-feature scores, combined score,
            anomaly flag, and explanatory breakdown.
        """
        pname = record.get("process_name", "unknown")
        pid = record.get("pid", 0)
        username = record.get("username")
        process_identity = record.get("process_identity")

        if baseline is None:
            baseline = self.storage.get_active_baseline(
                process_name=pname,
                username=username,
                process_identity=process_identity,
            )

        if not baseline:
            return {
                "process_name": pname,
                "pid": pid,
                "baseline_available": False,
                "anomaly_detected": False,
                "combined_anomaly_score": 0.0,
                "features_scored": {},
                "explanation": f"No baseline profile exists for process '{pname}'. Cannot compute MAD deviation.",
            }

        features_to_evaluate = [
            ("cpu", record.get("cpu_mean"), float(baseline.get("cpu_median", 0.0)), float(baseline.get("cpu_mad", 0.0))),
            ("memory", record.get("memory_mean"), float(baseline.get("memory_median", 0.0)), float(baseline.get("memory_mad", 0.0))),
            ("sockets", record.get("open_sockets_count"), float(baseline.get("socket_median", 0.0)), float(baseline.get("socket_mad", 0.0))),
            ("remote_ips", record.get("distinct_remote_ips"), float(baseline.get("remote_ip_median", 0.0)), float(baseline.get("remote_ip_mad", 0.0))),
            ("threads", record.get("num_threads_mean"), float(baseline.get("thread_median", 1.0)), float(baseline.get("thread_mad", 0.0))),
        ]

        feature_scores: Dict[str, Any] = {}
        anomalous_features: List[str] = []
        abs_z_scores: List[float] = []

        for feat_name, raw_obs, exp_med, mad_val in features_to_evaluate:
            if raw_obs is None or (isinstance(raw_obs, float) and pd.isna(raw_obs)):
                # Do NOT silently score missing features as normal 0.0
                feature_scores[feat_name] = {
                    "feature_name": feat_name,
                    "observed_value": None,
                    "expected_median": round(float(exp_med), 4),
                    "mad": round(float(mad_val), 4),
                    "modified_z_score": None,
                    "is_anomalous": False,
                    "missing": True,
                    "explanation": f"Feature '{feat_name}' is missing or invalid in window record.",
                }
                continue

            obs_val = float(raw_obs)
            score_data = self.scorer.score_feature(feat_name, obs_val, exp_med, mad_val)
            feature_scores[feat_name] = score_data
            abs_z_scores.append(abs(score_data["modified_z_score"]))
            if score_data["is_anomalous"]:
                anomalous_features.append(feat_name)

        # Combined score: normalized maximum modified Z-score scaled to [0.0, 1.0]
        # (Where 0.0 indicates exactly on baseline median, and 1.0 represents a severe deviation)
        max_z = max(abs_z_scores) if abs_z_scores else 0.0
        # Sigmoid-like soft saturation: combined = max_z / (max_z + threshold)
        combined_score = round(float(max_z / (max_z + self.anomaly_threshold)), 4) if max_z > 0 else 0.0

        is_overall_anomalous = len(anomalous_features) > 0 and combined_score >= 0.50

        if is_overall_anomalous:
            explanation = (
                f"Process '{pname}' (PID {pid}) exhibited statistical anomalies in {len(anomalous_features)} "
                f"dimension(s): {', '.join(anomalous_features)}. Maximum Modified Z-Score: {max_z:.2f}. "
                f"Note: Statistical deviation does not prove malicious intent."
            )
        else:
            explanation = f"Process '{pname}' (PID {pid}) operates within normal baseline boundaries."

        return {
            "process_name": pname,
            "pid": pid,
            "baseline_available": True,
            "baseline_status": baseline.get("baseline_status", "unknown"),
            "anomaly_detected": is_overall_anomalous,
            "combined_anomaly_score": combined_score,
            "max_modified_z_score": round(max_z, 4),
            "anomalous_features": anomalous_features,
            "features_scored": feature_scores,
            "explanation": explanation,
        }

    def compare_recent_features(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Evaluate the latest windowed features against existing baselines.
        """
        conn = _get_connection(self.db_path)
        try:
            sql = f"SELECT * FROM processed_features ORDER BY id DESC LIMIT {limit}"
            df = pd.read_sql_query(sql, conn)
        finally:
            conn.close()

        results = []
        for _, row in df.iterrows():
            eval_res = self.compare_window(row.to_dict())
            results.append(eval_res)
        return results


def main():
    import argparse
    parser = argparse.ArgumentParser(description="ECHO — Baseline Deviation Comparator")
    parser.add_argument("--threshold", type=float, default=3.5, help="Modified Z-score threshold (default: 3.5)")
    parser.add_argument("--limit", type=int, default=10, help="Number of recent records to evaluate (default: 10)")
    parser.add_argument("--db-path", type=str, default=None, help="SQLite database path")
    args = parser.parse_args()

    db_path = Path(args.db_path) if args.db_path else DB_PATH
    comparator = BaselineComparator(db_path=db_path, anomaly_threshold=args.threshold)
    evaluations = comparator.compare_recent_features(limit=args.limit)

    print("=" * 70)
    print(" ECHO BASELINE COMPARISON & ANOMALY EVALUATION")
    print("=" * 70)
    print(f" Evaluated Records  : {len(evaluations)}")
    anomalies = [e for e in evaluations if e["anomaly_detected"]]
    print(f" Anomalies Detected : {len(anomalies)}")
    print("-" * 70)
    for res in evaluations[:5]:
        flag = "[ANOMALOUS]" if res["anomaly_detected"] else "[NORMAL]"
        print(f" {flag:<12} {res['process_name']} (PID {res['pid']}): Score={res['combined_anomaly_score']:.3f} | {res['explanation']}")
    print("=" * 70)


if __name__ == "__main__":
    main()
