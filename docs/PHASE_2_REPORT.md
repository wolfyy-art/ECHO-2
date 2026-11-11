# Phase 2: Linux Process Telemetry Collector Report & Runtime Verification

**Project:** ECHO - Endpoint Correlation and Host Orchestration  
**Phase:** Phase 2 — Linux Process Telemetry Collector  
**Status:** Completed & Runtime Verified  
**Date:** November 11, 2026  

---

## 1. Overview and Architecture

Phase 2 established a non-blocking Linux process telemetry collector in `collector/`. It continuously monitors processes on the Ubuntu host, captures fine-grained compute, memory, and network telemetry at configurable sampling intervals, and safely stores raw telemetry into SQLite without disrupting existing schema or records.

```text
Host Linux OS (/proc & psutil)
           │
           ▼
 ┌──────────────────────────────────────────────────────────────┐
 │                      ECHO COLLECTOR                          │
 │                                                              │
 │  1. ProcessCollector (collector/process_collector.py):       │
 │     • Non-blocking CPU & Memory collection                   │
 │     • PID, PPID, username, exe, cmdline, threads, status     │
 │     • Defensive handling: NoSuchProcess, AccessDenied, etc.  │
 │     • Graceful shutdown on SIGINT / SIGTERM                  │
 │                                                              │
 │  2. NetworkCollector (collector/network_collector.py):       │
 │     • Point-in-time process-to-socket attribution            │
 │     • IPv4 / IPv6, TCP / UDP protocol mapping                │
 │     • Safe suppression of unprivileged socket access         │
 │                                                              │
 │  3. CollectorConfig (collector/config.py):                   │
 │     • Sane defaults (5s interval, continuous/timed runs)     │
 │     • Validation: interval > 0, duration >= 0, batch > 0     │
 │     • Clear descriptive errors for malformed environment vars│
 │                                                              │
 │  4. TelemetryStorage (collector/storage.py):                 │
 │     • Non-destructive raw telemetry SQLite extensions        │
 │     • Batched insertions to prevent disk saturation          │
 └──────────────────────────────────────────────────────────────┘
           │
           ▼
 SQLite Database (`data/echo.db`)
 [raw_process_telemetry & raw_network_telemetry tables]
```

---

## 2. Files Created & Modified

| File | Status | Description |
|---|---|---|
| `collector/__init__.py` | Created | Package exports: `CollectorConfig`, `ProcessTelemetry`, `NetworkTelemetry`, `CollectionStats`, `NetworkCollector`, `ProcessCollector`, `TelemetryStorage`. |
| `collector/config.py` | Created / Validated | Configuration dataclass with strict validation (`sampling_interval > 0`, `default_duration >= 0`), clear env variable parsing, and comprehensive docstring. |
| `collector/models.py` | Created | Data models for process and network telemetry snapshots. |
| `collector/network_collector.py` | Created | Attributed socket collection with protocol resolution and error boundary. |
| `collector/storage.py` | Created | Schema migration (`raw_process_telemetry`, `raw_network_telemetry`) and batch insert operations. |
| `collector/process_collector.py` | Created | Main collector engine with CLI argument parsing, signals, and exception isolation. |
| `tests/test_config.py` | Created | 9 tests validating configuration values, positive intervals, non-negative durations, and environment error handling. |
| `tests/test_network_collector.py` | Created | 5 tests for socket attribution, IPv4/IPv6, protocol strings, and mock error handling. |
| `tests/test_process_collector.py` | Created | 8 tests for process telemetry extraction, mock NoSuchProcess/AccessDenied/ZombieProcess, empty sweep handling, and database integration. |

---

## 3. Runtime Verification Test Results

### Test 1: Live Process Collection (Ubuntu Host)
- **Command:** `.venv/bin/python -m collector.process_collector --interval 5 --duration 20`
- **Observed:** 5 complete cycles across 20 seconds.
  - Cycle 1: 264 observed, 262 saved procs, 35 saved nets (0.19s)
  - Cycle 2: 265 observed, 263 saved procs, 35 saved nets (0.15s)
  - Cycle 3: 265 observed, 262 saved procs, 35 saved nets (0.24s)
  - Cycle 4: 265 observed, 263 saved procs, 35 saved nets (0.18s)
  - Cycle 5: 265 observed, 262 saved procs, 35 saved nets (0.19s)
- **Verified Fields:** Confirmed in SQLite:
  - PID and PPID (`PID=8785`, `PPID=6870`)
  - Process names (`python`, `kworker`, `systemd`, etc.)
  - Non-blocking CPU% and memory% metrics
  - ISO-8601 UTC timestamps (e.g. `2026-11-11T06:26:54.623950Z`)
  - Unhandled Errors: **0** (collector ran continuously without interruption).

### Test 2: Error Handling (Process Exits & Permissions)
Verified using unit test mocks (`tests/test_process_collector.py`):
- `psutil.NoSuchProcess`: Gracefully skipped without cycle interruption.
- `psutil.AccessDenied`: Privileged attributes fall back to `None` while non-privileged metrics are preserved.
- `psutil.ZombieProcess`: Cleanly filtered without throwing exceptions.
- In all scenarios, a failure on a single PID does not halt the collection cycle.

### Test 3: Network Collection & Attribution
- Verified point-in-time process-to-socket attribution for open sockets (e.g., PID `8569` listening on TCP4 `127.0.0.1:38009`).
- Both IPv4 and IPv6 protocols formatted cleanly (`TCP4`, `TCP6`, `UDP4`, `UDP6`).
- Full technical limitations documented in `collector/network_collector.py`:
  1. *AccessDenied / Permissions:* Unprivileged users cannot inspect root daemon sockets.
  2. *Short-lived bursts:* Rapid connections (DNS, curl) can terminate before collection sweeps.
  3. *Socket races & port recycling:* Port reuse in Linux means snapshots represent point-in-time state rather than transactional logs.
  4. *Shared sockets:* UNIX domain sockets and fork descriptors can attribute to multiple PIDs.

### Test 4: Database Storage & Preservation
Checked SQLite database (`data/echo.db`):
- `raw_process_telemetry`: 3,154 records persisted.
- `raw_network_telemetry`: 412 records persisted.
- Original Phase 1 tables (`process_events`, `alerts`, `response_actions`, `verification_results`) and existing records remained completely intact.

### Test 5: Graceful Shutdown
- Tested subprocess execution interrupted by `SIGINT` (Ctrl+C).
- Collector intercepted the signal, completed in-flight cleanup, and logged:
  ```text
  [INFO] Shutdown signal (2) received. Gracefully exiting collector...
  [INFO] ProcessCollector stopped cleanly.
  ```
- Exited with return code `0` within 0.3s.

### Test 6: Full Regression Test Suite
Executed the entire test suite using `pytest`:
```bash
.venv/bin/python -m pytest -v
```
**Results:**
- **Total Tests:** 66
- **Passed:** 66
- **Failed:** 0
- **Skipped:** 0
- **Duration:** 0.36s

---

## 4. Safety & System Integrity Confirmation

- Zero processes were signaled, killed, or frozen.
- No network traffic was filtered, blocked, or altered.
- System security safeguards remain unchanged (`response/safety.py`).
- Simulation mode remains the immutable system default.
- Zero changes to Phase 1 data or working code.
