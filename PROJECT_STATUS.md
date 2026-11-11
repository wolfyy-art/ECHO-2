# ECHO Project Status & Inspection Report

**Date of Inspection:** November 11, 2026  
**System Environment:** Ubuntu 26.04.1 LTS (Codename: resolute), Linux Kernel 6.17  
**Python Runtime:** Python 3.14.4  
**Database:** SQLite 3 (Built-in standard library)  
**Project Objective:** Linux-based process-aware anomaly detection and response system (ECHO - Endpoint Correlation and Host Orchestration)

---

## 1. Executive Summary

An in-depth structural, code, and environment inspection of the existing `ECHO` repository was performed. The repository contains an operational **Database Foundation**, **Safe Response Engine (Simulation-Mode)**, **Closed-Loop Verification Subsystem**, and **Prometheus/Grafana exporter and configurations** (previously developed as module `M4`).

All 44 existing automated unit tests pass with zero failures. Critical pipeline workflows execute seamlessly. However, the upstream pipeline stages—specifically **Telemetry Collection (M1)**, **Data Preprocessing**, **ML Detection Engine (M2)**, **Per-Process Behavioral Profiling (MAD)**, **Correlation Engine (M3)**, and the **Streamlit Web Dashboard**—are currently empty directories awaiting implementation.

---

## 2. Inventory of Existing Implementation

### 2.1 Working Modules

1. **Database Layer (`dashboard/database.py`):**
   - SQLite file database at `data/echo.db`.
   - 4 normalized relational tables:
     - `process_events`: Records process telemetry snapshots, start time, CPU/memory, anomaly score, and risk level (`low`, `medium`, `high`, `unknown`).
     - `alerts`: Tracks security alerts linked to events with severities (`low`, `medium`, `high`) and statuses (`open`, `acknowledged`, `resolved`).
     - `response_actions`: Captures containment and investigative actions (`alert`, `investigate`, `simulate_restriction`, `log_only`, `notify_operator`), execution modes (`simulation`, `live`), approval states, and execution results.
     - `verification_results`: Records closed-loop validation outcomes, verification details, and collateral impact assessments (`none`, `detected`, `unknown`).
   - Foreign key integrity (`PRAGMA foreign_keys = ON;`) enabled on every connection.
   - ISO-8601 UTC timestamp format compliance.
   - Comprehensive CRUD functions with parameterised queries.

2. **Safety Guards (`response/safety.py`):**
   - Hardcoded protection for root/kernel PIDs (`PID 0`, `PID 1`) and the active ECHO process itself (`os.getpid()`).
   - Extensive system binary allowlist safeguarding critical system daemons (`systemd`, `init`, `kthreadd`, `kworker`, `sshd`, `cron`, `auditd`, etc.) and development runtimes (`python`, `python3`, `code`, `antigravity`).
   - Pre-execution validation enforcing simulation vs live constraints and operator approvals.

3. **Response Engine (`response/engine.py`):**
   - Implements `ResponseEngine` adhering to zero-harm principles.
   - Defaults strictly to `execution_mode="simulation"`.
   - Persists all simulated/executed actions to `response_actions` in SQLite.

4. **Closed-Loop Verification (`verification/verifier.py`):**
   - Implements `ClosedLoopVerifier`.
   - Validates post-response outcomes and checks for collateral impact on neighboring processes.
   - Persists audit trails in `verification_results`.

5. **Metrics Exporter & Dashboards (`dashboard/prometheus/`, `dashboard/grafana/`):**
   - Zero-dependency Prometheus metrics HTTP server (`dashboard/prometheus/exporter.py`) exposing standard OpenMetrics on port 9108.
   - Pre-configured Grafana dashboards (`dashboard/grafana/dashboards/echo_overview.json`) and data source provisioning files.

6. **Demos & Seed Scripts (`dashboard/seed_demo.py`, `dashboard/run_demo_pipeline.py`):**
   - Synthetic event and alert seeder for local demonstration.
   - End-to-end executable test pipeline demonstrating event ingestion -> alert trigger -> simulation containment -> closed-loop verification -> Prometheus metrics export.

---

## 3. Missing Modules (To Be Developed)

The following core functional modules specified in the architecture currently exist only as empty directories:

| Component / Phase | Directory | Current Status | Required Implementation |
|---|---|---|---|
| **Phase 2: Telemetry Collection** | `collector/` | Empty (`.gitkeep` only) | Continuous process telemetry collection (PID, PPID, process name, CPU/RAM, network sockets/connections) in 5-second intervals via `psutil` and `/proc`. |
| **Phase 3: Data Preprocessing** | `preprocessing/` | Empty (`.gitkeep` only) | Telemetry cleaning, missing value handling, feature engineering, normalization, and window aggregation. |
| **Phase 4: ML Detection Engine** | `detection/` | Empty (`.gitkeep` only) | Scikit-learn Random Forest baseline classifier for process anomaly detection; training/evaluation pipelines; metric reporting (Precision, Recall, F1, Confusion Matrix). |
| **Phase 4 Persistence** | `models/` | Empty (`.gitkeep` only) | Serialized model artifacts (`.joblib` or `.pkl`) and feature vector definitions. |
| **Phase 5: Behavioral Profiling** | `detection/` or `profiling/` | Missing | Per-process baseline creation using Median Absolute Deviation (MAD) to detect statistical resource anomalies without false-positive penalization. |
| **Phase 6: Correlation & Risk** | `correlation/` | Empty (`.gitkeep` only) | Multi-factor risk scoring engine implementing $R = w_m M + w_a A + w_r Q$. |
| **Phase 7: Policy Engine** | `policy/` or `correlation/` | Missing | Context-aware decision engine mapping risk scores and process identity to defensive policy recommendations. |
| **Phase 8-9: Host Response Extensions** | `response/`, `verification/` | Basic Simulation Only | Real Linux containment drivers (cgroups v2 controller for CPU/memory throttling, network namespace isolation) with strict simulation-mode defaults. |
| **Phase 10: Streamlit Dashboard** | `dashboard/` | Missing Streamlit App | Interactive UI (`app.py`) for system status, live process telemetry, anomaly risk gauges, alert management, and response audit trails. |
| **Phase 11: MLflow Tracking** | `models/` / pipeline | Missing | MLflow experiment tracking for model parameters, training metrics, and artifact logging. |

---

## 4. Test Suite Execution Results

Ran standard unit test discovery:
```bash
python3 -m unittest discover tests -v
```

**Results:**
- **Ran:** 44 tests in 0.077s
- **Status:** OK (44 passed, 0 failures, 0 errors, 0 skipped)
- **Breakdown:**
  - `tests/test_database.py`: 33 tests passing (Schema verification, CRUD operations, foreign key integrity, ISO timestamp verification, duplicate rejection).
  - `tests/test_response.py`: 7 tests passing (Safety allowlist rejection, PID 0/1 protection, operator approval skip logic, simulation execution).
  - `tests/test_verification.py`: 3 tests passing (Closed-loop verification success, collateral damage detection, unrecorded action rejection).
  - `tests/test_prometheus.py`: 1 test passing (OpenMetrics format generation).

---

## 5. Dependency & Environment Analysis

### 5.1 Operating System & Python
- **OS:** Ubuntu 26.04.1 LTS x86_64
- **Kernel:** Linux 6.17 (Supports cgroups v2 at `/sys/fs/cgroup`)
- **Python:** Python 3.14.4

### 5.2 Python Package Status
- `psutil`: **INSTALLED** (version 7.1.0 via system package)
- `sqlite3`: **INSTALLED** (Python standard library)
- `unittest`: **INSTALLED** (Python standard library)
- `pandas`: **MISSING** (Candidate available in Ubuntu repository: `python3-pandas` 2.3.3)
- `numpy`: **MISSING** (Candidate available via `python3-numpy` or pip)
- `scikit-learn`: **MISSING** (Candidate available in Ubuntu repository: `python3-sklearn` 1.7.2)
- `streamlit`: **MISSING** (Requires pip/venv installation)
- `mlflow`: **MISSING** (Requires pip/venv installation)
- `pytest`: **MISSING** (Tests currently run smoothly using standard `unittest`)

### 5.3 Hardware / Kernel Capabilities
- **cgroups v2:** Mounted and active at `/sys/fs/cgroup` (`cgroup2 on /sys/fs/cgroup type cgroup2`).
- **Network Namespaces:** Kernel supports `ip netns` and network namespaces.
- **Root Privileges:** User is `vboxuser`. Sudo commands require password prompt or specific privileges. Simulation mode must remain the primary default to guarantee safety and unprivileged execution.

---

## 6. Implementation Risks & Mitigation Strategies

1. **Python 3.14 Compatibility with Modern ML Libraries:**
   - *Risk:* Python 3.14 is very new; some pre-compiled binary wheels for packages like MLflow or specific scikit-learn/pandas versions may require compilation tools or specific wheel versions.
   - *Mitigation:* In Phase 1, we will set up a dedicated virtual environment or utilize Ubuntu 26.04's native system packages (`python3-pandas`, `python3-sklearn`, `python3-numpy`) which are pre-compiled and tested for Python 3.14 on this distro.

2. **Process Socket Attribution Overhead & Race Conditions:**
   - *Risk:* Inspecting open network connections with `psutil.net_connections()` or `/proc/net` can fail with `AccessDenied` or `NoSuchProcess` when short-lived processes exit during the 5-second sampling loop.
   - *Mitigation:* Wrap telemetry reads in per-PID try-except blocks handling `psutil.NoSuchProcess`, `psutil.AccessDenied`, and `psutil.ZombieProcess`. Explicitly document socket attribution limits in the telemetry module.

3. **False Positives in Baseline Profiling:**
   - *Risk:* Legitimate compute-heavy processes (e.g., builds, video rendering, compilers) triggering high anomaly scores based on raw CPU/RAM alone.
   - *Mitigation:* Implement Median Absolute Deviation (MAD) on a per-process name basis, coupled with contextual process tree features (parent process, user, binary path) rather than isolated CPU usage.

4. **Accidental OS Disruption During Response:**
   - *Risk:* Automated response logic terminating or throttling crucial OS services.
   - *Mitigation:* Strict preservation of the existing `response/safety.py` allowlist, strict default of `execution_mode="simulation"`, and requiring explicit operator approval for any containment actions.

---

## 7. Recommended Phase-by-Phase Roadmap

1. **Phase 1: Environment & Dependency Foundation**
   - Configure Python virtual environment or package dependencies (`pandas`, `numpy`, `scikit-learn`, `pytest`).
   - Validate imports and extend unit test harness without modifying existing working database/response code.
2. **Phase 2: Telemetry Collector (`collector/`)**
   - Implement process-level metrics collector with 5-second sampling window.
   - Graceful termination handling and socket mapping documentation.
3. **Phase 3: Data Preprocessing (`preprocessing/`)**
   - Telemetry validation, rolling 5-second window aggregation, and CSV/database feature store.
4. **Phase 4: ML Detection Engine (`detection/`)**
   - Random Forest model training, evaluation pipeline, and metric validation.
5. **Phase 5: Behavioral Profiling (MAD)**
   - Robust median-based per-process deviation profiling.
6. **Phase 6: Correlation & Risk Scoring (`correlation/`)**
   - Composite risk engine calculating $R = w_m M + w_a A + w_r Q$.
7. **Phase 7: Policy Engine**
   - Decision rules mapping composite risk to recommended actions.
8. **Phase 8-9: Safe Response & Verification Integration**
   - Connect policy outputs to `response/engine.py` and `verification/verifier.py`.
9. **Phase 10: Streamlit Dashboard (`dashboard/app.py`)**
   - Interactive UI providing live monitoring, risk breakdown, and audit histories.
10. **Phases 11-14: MLflow, VM Containment Testing & Final Presentation**.

---

*Inspection report compiled and verified against live codebase.*
