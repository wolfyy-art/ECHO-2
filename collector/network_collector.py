"""
collector/network_collector.py
==============================
ECHO — Network Socket and Process-to-Socket Attribution Collector.

Gathers network connection details attributed to processes where accessible.

Technical Limitations & Attribution Challenges in Linux
-------------------------------------------------------
1. AccessDenied / Privileges:
   Unprivileged users cannot inspect sockets belonging to root or other users'
   processes. `psutil.AccessDenied` is normal and expected for system daemons.
2. Short-Lived Processes & Ephemeral Connections:
   A process establishing a short burst connection (e.g. DNS lookup, curl) may
   terminate before the collector samples it, causing a socket race condition.
3. Socket Races & Port Reuse:
   File descriptors and ephemeral ports are reused rapidly. Attribution reflects
   a point-in-time snapshot, not an atomic transaction.
4. Shared / Inherited Sockets:
   Forks, UNIX domain sockets, or file descriptor passing across IPC can result
   in sockets associated with multiple or unexpected PIDs.
5. Dual-Stack IPv4 / IPv6:
   Listening sockets binding to `::` may accept IPv4-mapped connections, requiring
   flexible address representation.
"""

import socket
import logging
from typing import List, Optional
from datetime import datetime, timezone
import psutil

from collector.models import NetworkTelemetry

logger = logging.getLogger(__name__)


def _utc_now() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _format_protocol(family: int, sock_type: int) -> str:
    """Determine protocol name from socket family and type."""
    proto = "UNKNOWN"
    if sock_type == socket.SOCK_STREAM:
        proto = "TCP"
    elif sock_type == socket.SOCK_DGRAM:
        proto = "UDP"

    if family == socket.AF_INET6:
        proto += "6"
    elif family == socket.AF_INET:
        proto += "4"

    return proto


class NetworkCollector:
    """
    Collects socket telemetry attributed to individual processes where permitted.
    """

    def collect_for_process(self, proc: psutil.Process, timestamp: Optional[str] = None) -> List[NetworkTelemetry]:
        """
        Collect active network connections for a specific psutil.Process instance.

        Parameters
        ----------
        proc : psutil.Process
            Process object to inspect.
        timestamp : Optional[str]
            ISO-8601 UTC timestamp; generated if omitted.

        Returns
        -------
        List[NetworkTelemetry]
            List of connection records successfully attributed to this process.
        """
        if timestamp is None:
            timestamp = _utc_now()

        connections: List[NetworkTelemetry] = []
        try:
            net_conns = proc.net_connections(kind="inet")
            for conn in net_conns:
                laddr = conn.laddr.ip if conn.laddr else ""
                lport = conn.laddr.port if conn.laddr else None
                raddr = conn.raddr.ip if conn.raddr else None
                rport = conn.raddr.port if conn.raddr else None
                status = conn.status if conn.status else "NONE"
                protocol = _format_protocol(conn.family, conn.type)

                connections.append(
                    NetworkTelemetry(
                        pid=proc.pid,
                        local_address=laddr,
                        local_port=lport,
                        remote_address=raddr,
                        remote_port=rport,
                        status=status,
                        protocol=protocol,
                        timestamp=timestamp,
                    )
                )
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            # Gracefully ignore expected security and lifecycle boundaries
            pass
        except Exception as exc:
            logger.debug("Unexpected error collecting network info for PID %d: %s", proc.pid, exc)

        return connections
