"""
tests/test_network_collector.py
================================
Unit tests for ECHO Network Collector.
Verifies socket inspection, address formatting, error suppression, and protocol parsing.
"""

import socket
import unittest
from unittest.mock import MagicMock
from collections import namedtuple

import psutil

from collector.network_collector import NetworkCollector, _format_protocol
from collector.models import NetworkTelemetry

Addr = namedtuple("Addr", ["ip", "port"])
MockConn = namedtuple("MockConn", ["fd", "family", "type", "laddr", "raddr", "status"])


class TestNetworkCollector(unittest.TestCase):
    """Tests for NetworkCollector."""

    def setUp(self):
        self.collector = NetworkCollector()

    def test_protocol_formatting(self):
        """Verify protocol resolution for IPv4 and IPv6 TCP/UDP."""
        self.assertEqual(_format_protocol(socket.AF_INET, socket.SOCK_STREAM), "TCP4")
        self.assertEqual(_format_protocol(socket.AF_INET, socket.SOCK_DGRAM), "UDP4")
        self.assertEqual(_format_protocol(socket.AF_INET6, socket.SOCK_STREAM), "TCP6")
        self.assertEqual(_format_protocol(socket.AF_INET6, socket.SOCK_DGRAM), "UDP6")
        self.assertEqual(_format_protocol(999, 999), "UNKNOWN")

    def test_collect_for_process_success(self):
        """Verify parsing of valid network connections."""
        mock_proc = MagicMock(spec=psutil.Process)
        mock_proc.pid = 4321
        mock_conn = MockConn(
            fd=3,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
            laddr=Addr(ip="127.0.0.1", port=8000),
            raddr=Addr(ip="10.0.0.5", port=443),
            status="ESTABLISHED",
        )
        mock_proc.net_connections.return_value = [mock_conn]

        conns = self.collector.collect_for_process(mock_proc, timestamp="2026-11-11T00:00:00Z")
        self.assertEqual(len(conns), 1)
        record = conns[0]
        self.assertEqual(record.pid, 4321)
        self.assertEqual(record.local_address, "127.0.0.1")
        self.assertEqual(record.local_port, 8000)
        self.assertEqual(record.remote_address, "10.0.0.5")
        self.assertEqual(record.remote_port, 443)
        self.assertEqual(record.status, "ESTABLISHED")
        self.assertEqual(record.protocol, "TCP4")
        self.assertEqual(record.timestamp, "2026-11-11T00:00:00Z")

    def test_access_denied_handled_gracefully(self):
        """Verify AccessDenied returns an empty list without raising exceptions."""
        mock_proc = MagicMock(spec=psutil.Process)
        mock_proc.pid = 1
        mock_proc.net_connections.side_effect = psutil.AccessDenied(pid=1)

        conns = self.collector.collect_for_process(mock_proc)
        self.assertEqual(conns, [])

    def test_no_such_process_handled_gracefully(self):
        """Verify NoSuchProcess returns an empty list without crashing."""
        mock_proc = MagicMock(spec=psutil.Process)
        mock_proc.pid = 9999
        mock_proc.net_connections.side_effect = psutil.NoSuchProcess(pid=9999)

        conns = self.collector.collect_for_process(mock_proc)
        self.assertEqual(conns, [])

    def test_zombie_process_handled_gracefully(self):
        """Verify ZombieProcess returns an empty list."""
        mock_proc = MagicMock(spec=psutil.Process)
        mock_proc.pid = 8888
        mock_proc.net_connections.side_effect = psutil.ZombieProcess(pid=8888)

        conns = self.collector.collect_for_process(mock_proc)
        self.assertEqual(conns, [])


if __name__ == "__main__":
    unittest.main()
