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

        ml_score = fixture.get("ml_anomaly_score")
        beh_score = fixture.get("behavioural_score")
        res_score = fixture.get("resource_anomaly_score")

        detection = DetectionSignalInput(
            ml_anomaly_score=ml_score,
            behavioural_score=beh_score,
            resource_anomaly_score=res_score,
            is_simulated=True,
            model_metadata={"source": "test_detection.py_fixture", "simulated": True},
            detection_timestamp=ts,
        )

        return telemetry, detection

