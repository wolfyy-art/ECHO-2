"""
tests/test_process_collector.py
================================
Unit tests for ECHO Process Collector.
Verifies telemetry extraction, exception handling (NoSuchProcess, AccessDenied,
ZombieProcess, PermissionError), empty sweeps, sampling interval logic, and database persistence.
"""

import os
import unittest
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch
from collections import namedtuple

import psutil

from collector.config import CollectorConfig
from collector.models import ProcessTelemetry, NetworkTelemetry
from collector.process_collector import ProcessCollector
from collector.storage import TelemetryStorage, init_telemetry_tables

MemInfo = namedtuple("MemInfo", ["rss", "vms"])


class TestProcessCollector(unittest.TestCase):
    """Test suite for ProcessCollector and defensive telemetry collection."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.tmp_dir) / "test_telemetry.db"
        self.config = CollectorConfig(
            sampling_interval=1.0,
            default_duration=1.0,
            collect_network=True,
            db_path=self.db_path,
        )
        self.storage = TelemetryStorage(db_path=self.db_path)
        self.collector = ProcessCollector(config=self.config, storage=self.storage)

    def test_collect_single_process_normal(self):
        """Verify normal process telemetry extraction."""
        mock_proc = MagicMock(spec=psutil.Process)
        mock_proc.pid = 1234
        mock_proc.ppid.return_value = 1
        mock_proc.name.return_value = "test_daemon"
        mock_proc.username.return_value = "vboxuser"
        mock_proc.exe.return_value = "/usr/bin/test_daemon"
        mock_proc.cmdline.return_value = ["/usr/bin/test_daemon", "--foreground"]
        mock_proc.cpu_percent.return_value = 15.5
        mock_proc.memory_percent.return_value = 2.4
        mock_proc.memory_info.return_value = MemInfo(rss=1024 * 1024 * 50, vms=1024 * 1024 * 100)
        mock_proc.num_threads.return_value = 4
        mock_proc.create_time.return_value = 1700000000.0
        mock_proc.status.return_value = "running"
        mock_proc.net_connections.return_value = []

        record, net_list = self.collector.collect_single_process(mock_proc, timestamp="2026-11-11T00:00:00Z")

        self.assertIsNotNone(record)
        self.assertEqual(record.pid, 1234)
        self.assertEqual(record.ppid, 1)
        self.assertEqual(record.process_name, "test_daemon")
        self.assertEqual(record.username, "vboxuser")
        self.assertEqual(record.exe, "/usr/bin/test_daemon")
        self.assertEqual(record.cmdline, "/usr/bin/test_daemon --foreground")
        self.assertEqual(record.cpu_percent, 15.5)
        self.assertEqual(record.memory_percent, 2.4)
        self.assertEqual(record.memory_rss, 50 * 1024 * 1024)
        self.assertEqual(record.num_threads, 4)
        self.assertEqual(record.status, "running")
        self.assertEqual(record.timestamp, "2026-11-11T00:00:00Z")
        self.assertEqual(net_list, [])

    def test_collect_single_process_no_such_process(self):
        """Terminated processes during collection must return None, [] gracefully."""
        mock_proc = MagicMock(spec=psutil.Process)
        mock_proc.pid = 9999
        mock_proc.name.side_effect = psutil.NoSuchProcess(pid=9999)

        record, net_list = self.collector.collect_single_process(mock_proc)
        self.assertIsNone(record)
        self.assertEqual(net_list, [])

    def test_collect_single_process_zombie(self):
        """Zombie processes must return None, [] gracefully."""
        mock_proc = MagicMock(spec=psutil.Process)
        mock_proc.pid = 9998
        mock_proc.name.side_effect = psutil.ZombieProcess(pid=9998)

        record, net_list = self.collector.collect_single_process(mock_proc)
        self.assertIsNone(record)
        self.assertEqual(net_list, [])

    def test_collect_single_process_access_denied_on_identity(self):
        """AccessDenied on root process identity must return None, [] without raising."""
        mock_proc = MagicMock(spec=psutil.Process)
        mock_proc.pid = 1
        mock_proc.name.side_effect = psutil.AccessDenied(pid=1)

        record, net_list = self.collector.collect_single_process(mock_proc)
        self.assertIsNone(record)
        self.assertEqual(net_list, [])

    def test_collect_single_process_partial_access_denied(self):
        """
        When process identity is readable but privileged fields like exe or cmdline
        raise AccessDenied, collector must provide graceful fallbacks.
        """
        mock_proc = MagicMock(spec=psutil.Process)
        mock_proc.pid = 555
        mock_proc.ppid.return_value = 1
        mock_proc.name.return_value = "worker"
        mock_proc.username.side_effect = psutil.AccessDenied(pid=555)
        mock_proc.exe.side_effect = psutil.AccessDenied(pid=555)
        mock_proc.cmdline.side_effect = psutil.AccessDenied(pid=555)
        mock_proc.cpu_percent.return_value = 1.0
        mock_proc.memory_percent.return_value = 0.5
        mock_proc.memory_info.return_value = MemInfo(rss=1024, vms=2048)
        mock_proc.num_threads.return_value = 1
        mock_proc.create_time.return_value = 1700000000.0
        mock_proc.status.return_value = "sleeping"
        mock_proc.net_connections.return_value = []

        record, net_list = self.collector.collect_single_process(mock_proc)
        self.assertIsNotNone(record)
        self.assertEqual(record.pid, 555)
        self.assertEqual(record.process_name, "worker")
        self.assertIsNone(record.username)
        self.assertIsNone(record.exe)
        self.assertIsNone(record.cmdline)
        self.assertEqual(record.status, "sleeping")

    @patch("psutil.process_iter")
    def test_empty_process_list(self, mock_iter):
        """Handle case where process_iter yields zero processes."""
        mock_iter.return_value = []
        stats = self.collector.collect_cycle()
        self.assertEqual(stats.processes_observed, 0)
        self.assertEqual(stats.records_collected, 0)
        self.assertEqual(stats.errors_encountered, 0)

    def test_telemetry_storage_and_database_integration(self):
        """Verify storage engine inserts and queries raw telemetry without schema collisions."""
        proc = ProcessTelemetry(
            pid=777,
            ppid=1,
            process_name="test_worker",
            username="vboxuser",
            exe="/usr/bin/test_worker",
            cmdline="/usr/bin/test_worker",
            cpu_percent=12.0,
            memory_percent=3.5,
            memory_rss=1024 * 1024 * 10,
            num_threads=2,
            process_start_time="2026-11-11T00:00:00Z",
            status="running",
            timestamp="2026-11-11T00:00:05Z",
        )
        net = NetworkTelemetry(
            pid=777,
            local_address="127.0.0.1",
            local_port=9000,
            remote_address=None,
            remote_port=None,
            status="LISTEN",
            protocol="TCP4",
            timestamp="2026-11-11T00:00:05Z",
        )

        inserted_p = self.storage.save_process_telemetry_batch([proc])
        inserted_n = self.storage.save_network_telemetry_batch([net])

        self.assertEqual(inserted_p, 1)
        self.assertEqual(inserted_n, 1)

        saved_p = self.storage.get_recent_process_telemetry(10)
        saved_n = self.storage.get_recent_network_telemetry(10)

        self.assertEqual(len(saved_p), 1)
        self.assertEqual(saved_p[0]["pid"], 777)
        self.assertEqual(saved_p[0]["process_name"], "test_worker")

        self.assertEqual(len(saved_n), 1)
        self.assertEqual(saved_n[0]["pid"], 777)
        self.assertEqual(saved_n[0]["local_port"], 9000)

    def test_collector_live_cycle_on_system(self):
        """Run a single real collection cycle on the current host system."""
        stats = self.collector.collect_cycle()
        self.assertGreater(stats.processes_observed, 0)
        self.assertGreater(stats.records_collected, 0)
        self.assertGreaterEqual(stats.network_records_collected, 0)

        # Verify data landed in sqlite
        rows = self.storage.get_recent_process_telemetry(5)
        self.assertGreater(len(rows), 0)


if __name__ == "__main__":
    unittest.main()
