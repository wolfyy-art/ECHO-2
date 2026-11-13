"""
correlation/adapters.py
=======================
ECHO — M3: Telemetry & Detection Data Adapters.

Converts existing synthetic records and demo datasets into the standard M3 input format:
1. Converts demo events from dashboard/seed_demo.py
2. Converts pipeline test scenarios from dashboard/run_demo_pipeline.py
3. Converts synthetic feature records from tests/test_detection.py

Guarantees:
- Preserves the distinction between simulated demo values and live ML models.
- Does not modify any existing demo scripts.
- Safely fills optional missing fields with standard simulated defaults.
"""

from typing import Dict, Any, Tuple, Optional
from correlation.models import ProcessTelemetryInput, DetectionSignalInput


class DemoDataAdapter:
    """
    Adapter converting external/demo records into standard M3 schemas.
    """

    @staticmethod
    def from_seed_demo_event(record: Dict[str, Any]) -> Tuple[ProcessTelemetryInput, DetectionSignalInput]:
        """
        Convert a record from dashboard/seed_demo.py into (ProcessTelemetryInput, DetectionSignalInput).
        """
        pid = int(record["pid"])
        pname = str(record["process_name"])
        cpu = float(record.get("cpu_percent", 0.0))
        mem = float(record.get("memory_percent", 0.0))
        event_id = record.get("event_id")
        ts = record.get("timestamp")
        start_time = record.get("process_start_time", ts)

        # In seed_demo.py, anomaly_score is in [0.0, 1.0]
        raw_anomaly = record.get("anomaly_score")
        
        # Contextual socket/thread estimation for demo data
        # High-risk demo miner has active sockets
        sockets = 3 if "miner" in pname.lower() else (1 if "firefox" in pname.lower() else 0)
        remote_ips = 2 if "miner" in pname.lower() else (1 if "firefox" in pname.lower() else 0)
        threads = 8 if "miner" in pname.lower() else 2

        telemetry = ProcessTelemetryInput(
            pid=pid,
            process_name=pname,
            process_start_time=start_time,
            cpu_percent=cpu,
            memory_percent=mem,
            open_sockets_count=sockets,
            distinct_remote_ips=remote_ips,
            num_threads=threads,
            timestamp=ts,
            event_id=event_id,
            username="vboxuser",
        )

        detection = DetectionSignalInput(
            ml_anomaly_score=raw_anomaly,
            ml_label="anomaly" if (raw_anomaly or 0.0) >= 0.5 else "normal",
            behavioural_score=raw_anomaly, # Mirrored for demo completeness
            resource_anomaly_score=None,    # Let RiskEngine calculate contextual resource score
            is_simulated=True,
            model_metadata={"source": "seed_demo.py", "simulated": True},
            detection_timestamp=ts,
        )

        return telemetry, detection

    @staticmethod
    def from_pipeline_event(
        event_id: str,
        pid: int,
        process_name: str,
        cpu_percent: float,
        memory_percent: float,
        anomaly_score: float,
        process_start_time: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> Tuple[ProcessTelemetryInput, DetectionSignalInput]:
        """
        Convert an end-to-end pipeline demo event (from dashboard/run_demo_pipeline.py).
        """
        telemetry = ProcessTelemetryInput(
            pid=pid,
            process_name=process_name,
            process_start_time=process_start_time or timestamp,
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            open_sockets_count=4 if "miner" in process_name.lower() else 0,
            distinct_remote_ips=2 if "miner" in process_name.lower() else 0,
            num_threads=16 if "miner" in process_name.lower() else 1,
            timestamp=timestamp,
            event_id=event_id,
            username="vboxuser",
        )

        detection = DetectionSignalInput(
            ml_anomaly_score=anomaly_score,
            ml_label="anomaly" if anomaly_score >= 0.5 else "normal",
            behavioural_score=anomaly_score,
            resource_anomaly_score=None,
            is_simulated=True,
            model_metadata={"source": "run_demo_pipeline.py", "simulated": True},
            detection_timestamp=timestamp,
        )

        return telemetry, detection

    @staticmethod
    def from_feature_fixture(fixture: Dict[str, Any]) -> Tuple[ProcessTelemetryInput, DetectionSignalInput]:
        """
        Convert a synthetic feature record from tests/test_detection.py fixtures.
        """
        pid = int(fixture.get("pid", 1000))
        pname = str(fixture.get("process_name", "fixture_proc"))
        cpu = float(fixture.get("cpu_mean", fixture.get("cpu_percent", 0.0)))
        mem = float(fixture.get("memory_mean", fixture.get("memory_percent", 0.0)))
        sockets = int(fixture.get("open_sockets_count", 0))
        ips = int(fixture.get("distinct_remote_ips", 0))
        threads = int(fixture.get("num_threads_mean", fixture.get("num_threads", 1)))
        ts = fixture.get("window_start") or fixture.get("timestamp")

        telemetry = ProcessTelemetryInput(
            pid=pid,
            process_name=pname,
            process_start_time=ts,
            cpu_percent=cpu,
            memory_percent=mem,
            open_sockets_count=sockets,
            distinct_remote_ips=ips,
            num_threads=threads,
            timestamp=ts,
            username=fixture.get("username", "vboxuser"),
        )

        return telemetry, detection


class M2ModelAdapter:
    """
    Adapter converting real M2 Isolation Forest inference outputs and 13-feature vectors
    into standard M3 input schemas (ProcessTelemetryInput, DetectionSignalInput).
    """

    APPROVED_FEATURES = [
        "cpu_mean",
        "cpu_max",
        "cpu_std",
        "memory_mean",
        "memory_max",
        "memory_rss_mean",
        "num_threads_mean",
        "num_threads_max",
        "open_sockets_count",
        "distinct_remote_ips",
        "sample_count",
        "cpu_mem_ratio",
        "socket_thread_ratio",
    ]

    @classmethod
    def validate_and_extract_features(cls, record: Dict[str, Any]):
        """
        Extract and validate the exact 13 approved features for ML inference.
        
        Checks:
        - All 13 approved features must be present.
        - Preserves strict feature order matching models/metadata.json.
        - Rejects None, NaN, and Infinite values.
        - Returns a 1-row DataFrame ready for model.score_samples().
        """
        import pandas as pd
        import numpy as np

        missing = [col for col in cls.APPROVED_FEATURES if col not in record]
        if missing:
            raise ValueError(f"Feature vector validation failed: missing required features: {missing}")

        row_dict = {}
        for col in cls.APPROVED_FEATURES:
            val = record[col]
            if val is None:
                raise ValueError(f"Feature vector validation failed: column '{col}' has null value.")
            val_float = float(val)
            if np.isnan(val_float) or np.isinf(val_float):
                raise ValueError(f"Feature vector validation failed: column '{col}' has NaN or Infinite value.")
            row_dict[col] = [val_float]

        df_row = pd.DataFrame(row_dict)[cls.APPROVED_FEATURES]
        return df_row

    @classmethod
    def from_m2_inference(
        cls,
        record: Dict[str, Any],
        model,
        event_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> Tuple[ProcessTelemetryInput, DetectionSignalInput]:
        """
        Execute actual Isolation Forest model inference on the 13 approved features,
        standardizing scores into M3's scale [0.0, 100.0].

        Parameters
        ----------
        record : Dict[str, Any]
            Dictionary containing process metadata and the 13 approved features.
        model : ProcessIsolationForest
            Fitted M2 Isolation Forest model.
        event_id : Optional[str]
            Optional event ID.
        timestamp : Optional[str]
            Optional observation timestamp.

        Returns
        -------
        Tuple[ProcessTelemetryInput, DetectionSignalInput]
            Validated telemetry and real ML detection signal.
        """
        if not hasattr(model, "is_fitted") or not model.is_fitted:
            raise RuntimeError("Cannot perform M2 inference: Isolation Forest model is not fitted.")

        # 1. Validate and extract exact 13-feature matrix row
        df_row = cls.validate_and_extract_features(record)

        # 2. Execute Model Inference
        # score_samples returns S in [0.0, 1.0] where < 0.50 is normal and > 0.50 is anomalous
        raw_scores = model.score_samples(df_row)
        raw_labels = model.predict_labels(df_row)

        if len(raw_scores) == 0:
            raise RuntimeError("Model inference returned empty score vector.")

        score_unit = float(raw_scores[0])
        label_int = int(raw_labels[0])

        # 3. Standardize score into M3's 0-100 range:
        # Monotonic linear scale: 0.0 -> 0.0, 0.50 (threshold) -> 50.0, 1.0 -> 100.0
        standardized_ml_score = round(score_unit * 100.0, 2)
        ml_label = "anomaly" if label_int == -1 else "normal"

        # 4. Construct Telemetry
        pid = int(record["pid"])
        pname = str(record["process_name"])
        telemetry = ProcessTelemetryInput(
            event_id=event_id,
            pid=pid,
            process_name=pname,
            ppid=record.get("ppid"),
            process_start_time=record.get("process_start_time") or timestamp,
            cpu_percent=float(record.get("cpu_mean", 0.0)),
            memory_percent=float(record.get("memory_mean", 0.0)),
            memory_rss=int(record.get("memory_rss_mean", 0)),
            open_sockets_count=int(record.get("open_sockets_count", 0)),
            distinct_remote_ips=int(record.get("distinct_remote_ips", 0)),
            num_threads=int(record.get("num_threads_max", 1)),
            username=record.get("username", "vboxuser"),
            timestamp=timestamp,
            exe_path=record.get("exe_path"),
            parent_name=record.get("parent_name"),
        )

        # 5. Construct Detection Signal
        detection = DetectionSignalInput(
            ml_anomaly_score=standardized_ml_score,
            ml_label=ml_label,
            behavioural_score=None,
            resource_anomaly_score=None,
            is_simulated=False, # REAL ML INFERENCE
            model_metadata={
                "model_type": "IsolationForest",
                "version": "1.0.0",
                "raw_unit_score": score_unit,
                "prediction_label": label_int,
                "score_offset": float(model.score_offset_),
                "features_validated": cls.APPROVED_FEATURES,
                "is_simulated": False,
            },
            detection_timestamp=timestamp,
        )

        return telemetry, detection

