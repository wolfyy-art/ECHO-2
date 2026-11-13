# ECHO — Endpoint Correlation and Host Orchestration (ECHO-2)

[![Test Suite](https://img.shields.io/badge/Unit%20%26%20Integration%20Tests-217%20Passed-brightgreen.svg)](#testing-and-verification)
[![Python Version](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](requirements.txt)
[![Execution Mode](https://img.shields.io/badge/Safety%20Mode-Simulation%20Default-orange.svg)](#safety-invariants)

ECHO is a Linux-based endpoint security monitoring, process-level anomaly detection, multi-signal risk correlation, and closed-loop orchestration platform. It is engineered to distinguish legitimate heavy workloads from genuine adversarial behaviour with zero collateral damage.

---

## 1. Architectural Blueprint & Subsystems

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │                     HOST OS: LINUX KERNEL / TELEMETRY                  │
 └───────────────────────────────────┬────────────────────────────────────┘
                                     │ psutil /proc inspection
                                     ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                   M1: TELEMETRY COLLECTOR (collector/)                 │
 │ • Process attributes (PID, PPID, Start Time, RSS, Threads)            │
 │ • Socket topology (Local/Remote IPs, Connection states)                │
 │ • Storage: raw telemetry SQLite tables (processes, sockets)           │
 └───────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │               M2: PREPROCESSING & ML DETECTION (preprocessing/, detection/) │
 │ • 5-Second Discrete Window Aggregation & Feature Extraction            │
 │ • 13 Approved Feature Matrix (CPU/Mem ratios, Thread/Socket ratios)    │
 │ • Per-Process Behavioural Baseline Profiling via Median/MAD            │
 │ • Unsupervised Anomaly Detection via Isolation Forest (models/)       │
 └───────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │            M3: MULTI-SIGNAL CORRELATION & POLICY (correlation/, policy/)    │
 │ • Signal Normalization: ML (M), Behavioural MAD (A), Context Rules (Q) │
 │ • Mathematical Composite Risk Scoring: R = 0.40*M + 0.40*A + 0.20*Q    │
 │ • Graduated Enforcement Decisions (log_only, investigate, restrict)    │
 │ • Policy Rules & Action Mapping to M4 Bridge                           │
 └───────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │           M4: ENFORCEMENT, VERIFICATION & DASHBOARD (response/, dashboard/) │
 │ • Safe Response Engine (Simulation-Mode Default, Zero OS Harm)         │
 │ • System Safety Allowlist (PID 0, PID 1, system daemons protected)    │
 │ • Closed-Loop Verification: Collateral Damage & Containment Asserts   │
 │ • Central SQLite Audit Ledger (data/echo.db)                          │
 │ • Streamlit Security Operations Dashboard (dashboard/app.py)          │
 │ • OpenMetrics Prometheus Exporter (port 9108)                         │
 └────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Team Subsystem Boundaries

- **M1 — Telemetry Collection (Kshitij):** `collector/`
  Gathers raw process snapshots and socket connections from the host, with graceful handling of exited processes and zombie states.
- **M2 — Preprocessing & Detection (Suhani):** `preprocessing/`, `baseline/`, `detection/`, `models/`
  Transforms raw time-series into 5-second feature windows, manages per-process statistical baselines (MAD), and serializes/infers with the Isolation Forest ensemble.
- **M3 — Correlation & Policy Engine (Rishit):** `correlation/`, `policy/`
  Correlates multi-source anomaly signals into a normalized composite risk score $R \in [0.0, 1.0]$, checks process hierarchy, and issues actionable policy decisions.
- **M4 — Enforcement & Observability (Mayank):** `response/`, `verification/`, `dashboard/`
  Enforces zero-harm simulation responses, asserts post-action verification without false claims, hosts the central SQLite database, exports Prometheus metrics, and delivers the Streamlit dashboard.

---

## 3. Installation & Setup

### Prerequisites
- Linux (Ubuntu 22.04 LTS recommended) or WSL2 / VMware Ubuntu.
- Python 3.11+.

### Clone & Environment Setup
```bash
git clone https://github.com/wolfyy-art/ECHO-2.git
cd ECHO-2
git checkout integration/final-completion

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install all verified dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 4. Execution & Demonstration Commands

### A. Run Automated Unit & Integration Tests (217 Tests)
Run the entire regression test suite across all 4 modules:
```bash
python3 -m unittest discover -s tests -v
```

### B. Train the Isolation Forest Model (Isolated Database)
To train or retrain the ML model without contaminating the production database:
```bash
python3 models/train.py --db-path /tmp/echo_train.db --force
```
*Artifacts saved to `models/isolation_forest.joblib` and `models/metadata.json`.*

### C. Run the 3-Process Multi-Workload Demonstration Pipeline
Demonstrates ECHO distinguishing normal traffic, heavy backups, and unauthorized miners running concurrently:
```bash
python3 run_echo.py
```

### D. Run the M3 End-to-End Correlation & Policy Scenarios
Demonstrates the 4 security scenarios (Normal, Suspicious, High-Threat Miner, and Missing Signals):
```bash
python3 scripts/run_m3_demo.py
```

### E. Launch the Interactive Streamlit Dashboard
Start the real-time security operations console:
```bash
streamlit run dashboard/app.py
```
Open your browser at `http://localhost:8501`.

### F. Start the Prometheus Metrics Exporter
Expose OpenMetrics on port 9108:
```bash
python3 dashboard/prometheus/exporter.py
```
Scrape metrics at `http://localhost:9108/metrics`.

---

## 5. Safety Invariants & Policies

1. **Simulation Mode by Default:** All containment actions (`simulate_restriction`, `network_bandwidth_throttling`, etc.) run strictly in software simulation mode. No host signals (SIGKILL, SIGSTOP) or firewall (iptables/nftables) modifications are applied.
2. **Protected Process Allowlist:** PID 0, PID 1 (`init`/`systemd`), the monitoring agent itself, and core daemons (`sshd`, `dbus-daemon`, `python3`) can never be targeted or restricted.
3. **Operator Approval Gates:** High-impact containment actions require explicit operator approval; missing or pending approval defaults to safe `skipped` outcomes.
4. **Verification Integrity:** Post-action verification strictly distinguishes `success`, `failure`, and `inconclusive`. Missing telemetry evidence is never falsely reported as successful containment.
5. **Database Isolation:** Synthetic training telemetry is strictly forbidden from writing to `data/echo.db`.
