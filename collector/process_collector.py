"""
collector/process_collector.py
==============================
ECHO — Linux Process Telemetry Collector.

Continuously captures process-level telemetry snapshots across the Linux host.
Handles process exits, access denials, zombie states, and system boundaries
gracefully.
"""

import os
import sys
import time
import signal
import logging
import argparse
from typing import List, Tuple, Optional
from datetime import datetime, timezone
import psutil

from collector.config import CollectorConfig
from collector.models import ProcessTelemetry, NetworkTelemetry, CollectionStats
from collector.network_collector import NetworkCollector
from collector.storage import TelemetryStorage

logger = logging.getLogger(__name__)


def _utc_now() -> str:
    """Return ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _format_start_time(create_time: float) -> str:
    """Convert POSIX epoch start time to ISO-8601 UTC string."""
    try:
        dt = datetime.fromtimestamp(create_time, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    except Exception:
        return _utc_now()


class ProcessCollector:
    """
    Collects comprehensive Linux process telemetry and optional network sockets.
    """

    def __init__(
        self,
        config: Optional[CollectorConfig] = None,
        storage: Optional[TelemetryStorage] = None,
    ):
        self.config = config or CollectorConfig()
        self.storage = storage or TelemetryStorage(self.config.db_path)
        self.network_collector = NetworkCollector()
        self._running = False

    def collect_single_process(
        self,
        proc: psutil.Process,
        timestamp: Optional[str] = None,
    ) -> Tuple[Optional[ProcessTelemetry], List[NetworkTelemetry]]:
        """
        Extract telemetry for a single process with defensive error handling.

        Handles:
        - psutil.NoSuchProcess (process exited during query)
        - psutil.AccessDenied (insufficient permissions for specific attributes)
        - psutil.ZombieProcess (defunct process state)
        - PermissionError / OSError

        Returns
        -------
        Tuple[Optional[ProcessTelemetry], List[NetworkTelemetry]]
        """
        if timestamp is None:
            timestamp = _utc_now()

        try:
            # Gather basic identity
            pid = proc.pid
            ppid = proc.ppid()
            name = proc.name() or "unknown"

            # Optional / privileged fields with graceful fallbacks
            try:
                username = proc.username()
            except (psutil.AccessDenied, KeyError):
                username = None

            try:
                exe = proc.exe()
            except (psutil.AccessDenied, FileNotFoundError):
                exe = None

            try:
                cmd_list = proc.cmdline()
                cmdline = " ".join(cmd_list) if cmd_list else None
            except (psutil.AccessDenied, FileNotFoundError):
                cmdline = None

            # Resource metrics
            # cpu_percent with interval=None gives non-blocking CPU since last call
            cpu_percent = float(proc.cpu_percent(interval=None) or 0.0)
            mem_percent = float(proc.memory_percent() or 0.0)

            try:
                mem_info = proc.memory_info()
                memory_rss = int(mem_info.rss) if mem_info else 0
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                memory_rss = 0

            try:
                num_threads = int(proc.num_threads())
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                num_threads = 1

            try:
                create_time = proc.create_time()
                process_start_time = _format_start_time(create_time)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                process_start_time = timestamp

            try:
                status = str(proc.status())
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                status = "unknown"

            proc_record = ProcessTelemetry(
                pid=pid,
                ppid=ppid,
                process_name=name,
                username=username,
                exe=exe,
                cmdline=cmdline,
                cpu_percent=round(cpu_percent, 2),
                memory_percent=round(mem_percent, 2),
                memory_rss=memory_rss,
                num_threads=num_threads,
                process_start_time=process_start_time,
                status=status,
                timestamp=timestamp,
            )

            # Optional network collection
            net_records: List[NetworkTelemetry] = []
            if self.config.collect_network:
                net_records = self.network_collector.collect_for_process(proc, timestamp=timestamp)

            return proc_record, net_records

        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return None, []
        except psutil.AccessDenied:
            logger.debug("Access denied accessing PID %d", proc.pid)
            return None, []
        except Exception as exc:
            logger.debug("Error inspecting PID %d: %s", getattr(proc, "pid", -1), exc)
            return None, []

    def collect_cycle(self) -> CollectionStats:
        """
        Execute one full collection sweep across all currently active host processes.

        Returns
        -------
        CollectionStats
            Summary counts of observed processes, saved records, and errors.
        """
        cycle_start = time.time()
        timestamp = _utc_now()

        proc_records: List[ProcessTelemetry] = []
        net_records: List[NetworkTelemetry] = []
        observed_count = 0
        error_count = 0

        # Prime cpu_percent counters for accurate process-level telemetry
        for proc in psutil.process_iter():
            observed_count += 1
            try:
                record, net_list = self.collect_single_process(proc, timestamp=timestamp)
                if record:
                    proc_records.append(record)
                if net_list:
                    net_records.extend(net_list)
            except Exception:
                error_count += 1

        # Batch insert into database
        if proc_records:
            self.storage.save_process_telemetry_batch(proc_records)
        if net_records:
            self.storage.save_network_telemetry_batch(net_records)

        duration = time.time() - cycle_start
        stats = CollectionStats(
            cycle_index=0,
            processes_observed=observed_count,
            records_collected=len(proc_records),
            network_records_collected=len(net_records),
            errors_encountered=error_count,
            cycle_duration_seconds=round(duration, 4),
        )
        return stats

    def run(self, duration: Optional[float] = None) -> None:
        """
        Continuously collect telemetry with configurable interval and graceful shutdown.

        Parameters
        ----------
        duration : Optional[float]
            Total runtime in seconds. If 0 or None, runs indefinitely until interrupted.
        """
        self._running = True
        interval = self.config.sampling_interval
        max_duration = duration if duration is not None else self.config.default_duration

        start_time = time.time()
        cycle = 0

        # Register signal handlers for clean SIGINT / SIGTERM handling
        def _sig_handler(signum, frame):
            logger.info("Shutdown signal (%d) received. Gracefully exiting collector...", signum)
            self._running = False

        original_sigint = signal.signal(signal.SIGINT, _sig_handler)
        original_sigterm = signal.signal(signal.SIGTERM, _sig_handler)

        logger.info(
            "Starting ProcessCollector (Interval=%.1fs, Max Duration=%.1fs, Network=%s, DB=%s)",
            interval, max_duration, self.config.collect_network, self.config.db_path,
        )

        try:
            while self._running:
                cycle += 1
                stats = self.collect_cycle()
                stats.cycle_index = cycle

                logger.info(
                    "[Cycle %d] Observed: %d | Saved Procs: %d | Saved Nets: %d | Errors: %d | Time: %.2fs",
                    cycle,
                    stats.processes_observed,
                    stats.records_collected,
                    stats.network_records_collected,
                    stats.errors_encountered,
                    stats.cycle_duration_seconds,
                )

                if max_duration > 0 and (time.time() - start_time) >= max_duration:
                    logger.info("Reached target collection duration (%.1fs). Stopping.", max_duration)
                    break

                # Sleep interval accounting for execution duration to avoid drift
                sleep_time = max(0.0, interval - stats.cycle_duration_seconds)
                # Sleep in short increments to respond promptly to shutdown signals
                slept = 0.0
                while self._running and slept < sleep_time:
                    chunk = min(0.5, sleep_time - slept)
                    time.sleep(chunk)
                    slept += chunk

                    if max_duration > 0 and (time.time() - start_time) >= max_duration:
                        break
        finally:
            self._running = False
            signal.signal(signal.SIGINT, original_sigint)
            signal.signal(signal.SIGTERM, original_sigterm)
            logger.info("ProcessCollector stopped cleanly.")


def main():
    """Command-line interface for the process telemetry collector."""
    parser = argparse.ArgumentParser(description="ECHO — Linux Process Telemetry Collector")
    parser.add_argument(
        "--interval",
        type=float,
        default=5.0,
        help="Sampling interval in seconds (default: 5.0)",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=0.0,
        help="Total duration to run in seconds (default: 0 = run indefinitely)",
    )
    parser.add_argument(
        "--no-network",
        action="store_true",
        help="Disable process network socket collection",
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=None,
        help="Custom SQLite database file path",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    db_path = Path(args.db_path) if args.db_path else None
    config = CollectorConfig(
        sampling_interval=args.interval,
        default_duration=args.duration,
        collect_network=not args.no_network,
        db_path=db_path or CollectorConfig().db_path,
    )

    collector = ProcessCollector(config=config)
    collector.run(duration=args.duration)


if __name__ == "__main__":
    main()
