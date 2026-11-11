# ECHO M4 — Enforcement, Verification & Monitoring Dashboard

**Module:** M4 — Enforcement, Verification & Monitoring Dashboard  
**Author:** Mayank  
**Scope Completed:** Phase 1 (Database Foundation) -> Phase 2 (Safe Response & Closed-Loop Verification) -> Phase 3 (Prometheus Exporter & Grafana Dashboard)

---

## 1. Overview & Architecture

ECHO (Endpoint Correlation and Host Orchestration) is a Linux-based security monitoring system.  
Module 4 (M4) provides the data backbone, policy enforcement, closed-loop verification, and real-time observability:

```text
[M1: Telemetry Collector]
       │
[M2: ML Anomaly Detector]
       │
[M3: Risk & Policy Engine]
       │
       ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                      ECHO M4: MAYANK'S MODULE                          │
 │                                                                        │
 │  1. Database Foundation: data/echo.db (SQLite, 4 normalized tables)    │
 │  2. Safe Response Engine: response/ (allowlists, simulation mode)      │
 │  3. Closed-Loop Verification: verification/ (collateral impact checks) │
 │  4. Metrics Exporter: dashboard/prometheus/ (OpenMetrics on /metrics)  │
 │  5. Visualisation: dashboard/grafana/ (custom dashboards & datasources)│
 └────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Directory Layout

```text
echo-project/
├── dashboard/
│   ├── database.py                 # SQLite schema, validation, parameterised CRUD
│   ├── seed_demo.py                # Synthetic realistic sample data seeder
│   ├── run_demo_pipeline.py        # End-to-end closed loop workflow demonstrator
│   ├── prometheus/
│   │   ├── exporter.py             # Zero-dependency Prometheus HTTP metrics exporter
│   │   └── prometheus.yml          # Prometheus scrape target configuration
│   └── grafana/
│       ├── dashboards/
│       │   └── echo_overview.json  # Full 8-panel Grafana dashboard configuration
│       └── provisioning/
│           ├── dashboards/         # Automated Grafana dashboard provider
│           └── datasources/        # Automated Prometheus datasource provider
├── data/
│   └── echo.db                     # Active SQLite database file
├── response/
│   ├── safety.py                   # System PID & critical binary allowlist guards
│   └── engine.py                   # Safe simulation-mode response executor
├── verification/
│   └── verifier.py                 # Closed-loop verifier & collateral impact detector
└── tests/
    ├── test_database.py            # 33 unit tests for database layer
    ├── test_response.py            # 7 unit tests for response safety & engine
    ├── test_verification.py        # 3 unit tests for closed-loop verification
    └── test_prometheus.py          # 1 unit test for Prometheus exposition format
```

---

## 3. Database Schema (Phase 1)

All timestamps are stored in UTC ISO-8601 (`...Z`). Foreign keys are strictly enforced on every connection (`PRAGMA foreign_keys = ON;`).

1. **`process_events`**: Stores Linux process snapshots and ML scores (`low`, `medium`, `high`, `unknown`).
2. **`alerts`**: Security alerts linked via `event_id` foreign key.
3. **`response_actions`**: Automated or operator response actions linked via `event_id`.
4. **`verification_results`**: Post-action validations linked via `action_id`.

---

## 4. Safe Response Execution (Phase 2)

The Response Engine (`response/`) handles containment recommendations from M3:
- **Strict Simulation Guarantee:** Defaults to `execution_mode="simulation"`. It models network throttling, process snapshots, and firewall rules in software without modifying host OS state.
- **Safety Allowlist:** Intercepts any action targeting core system processes (PID 0, PID 1, the monitoring agent itself, `systemd`, `init`, `sshd`, `login`, etc.) and immediately rejects the action with a safety violation.
- **Approval Workflow:** Restrictive actions require operator approval; rejected actions are marked `skipped`.

---

## 5. Closed-Loop Verification (Phase 2)

The Verification Engine (`verification/`):
- Verifies that containment or restriction achieved the desired state.
- Assesses **collateral impact** (`none`, `detected`, `unknown`): confirms whether adjacent or non-malicious processes were degraded by the response.
- Records all findings into `verification_results` for dashboard visualization and audit compliance.

---

## 6. Prometheus & Grafana Monitoring (Phase 3)

### Prometheus Exporter (`dashboard/prometheus/exporter.py`)
Runs a lightweight, zero-dependency HTTP server (built with Python standard library `http.server`) exposing metrics on port `9108` at `/metrics`:

- `echo_process_events_total{risk_level="..."}` (Counter)
- `echo_active_alerts{severity="..."}` (Gauge)
- `echo_alerts_total{severity="...",status="..."}` (Counter)
- `echo_response_actions_total{action_type="...",result="...",execution_mode="..."}` (Counter)
- `echo_verification_results_total{success="...",collateral_impact="..."}` (Counter)
- `echo_verification_success_rate` (Gauge 0.0 - 1.0)

### Grafana Dashboard (`dashboard/grafana/dashboards/echo_overview.json`)
Pre-configured dashboard with dark-mode visualization:
1. **Total Active Alerts** (Stat panel with color thresholds)
2. **Verification Success Rate** (Percent gauge)
3. **Total Response Actions** (Stat counter)
4. **Monitored Process Events** (Stat counter)
5. **Process Events by Risk Level** (Time-series smooth graph)
6. **Active Alerts Distribution by Severity** (Donut / Pie chart)
7. **Response Actions Breakdown** (Stacked bar time-series)
8. **Verification Results & Collateral Impact** (Stacked bar time-series)

---

## 7. Execution Commands

### Run Full Test Suite (44 Tests)
```bash
python -m unittest discover -s tests -v
```

### Run Full Closed-Loop Pipeline Demo
```bash
python dashboard/run_demo_pipeline.py
```

### Start Prometheus Exporter
```bash
python dashboard/prometheus/exporter.py
```
View metrics in browser or curl:
```bash
curl http://localhost:9108/metrics
```

### Start Prometheus with ECHO Scraper
```bash
prometheus --config.file=dashboard/prometheus/prometheus.yml
```
