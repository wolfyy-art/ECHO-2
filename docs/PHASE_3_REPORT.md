# Phase 3: Telemetry Data Preprocessing and 5-Second Windowing Report

**Project:** ECHO - Endpoint Correlation and Host Orchestration  
**Phase:** Phase 3 — Data Preprocessing and Feature Extraction  
**Status:** Completed & Independently Reviewed  
**Date:** November 11, 2026  

---

## 1. Overview and Architecture

Phase 3 implements the data transformation pipeline between raw system telemetry (from Phase 2) and behavioral profiling / machine learning anomaly detection (Phases 4-6).

```text
       RAW TELEMETRY (`data/echo.db`)
       ├── raw_process_telemetry (3,154 records)
       └── raw_network_telemetry (412 records)
                      │
                      ▼
 ┌──────────────────────────────────────────────────────────────┐
 │                  PHASE 3: PREPROCESSING                      │
 │                                                              │
 │  1. TelemetryCleaner (preprocessing/cleaner.py):             │
 │     • Validates numeric ranges (clipping negative values)    │
 │     • Parses UTC ISO timestamps                              │
 │     • Imputes missing metadata (username, exe, cmdline)      │
 │                                                              │
 │  2. WindowAggregator (preprocessing/windowing.py):           │
 │     • Slices streams into configurable 5-second intervals    │
 │     • Calculates mean, max, std of CPU, RAM RSS, and threads │
 │     • Attributes concurrent network socket counts to PID     │
 │                                                              │
 │  3. FeatureExtractor (preprocessing/features.py):            │
 │     • Generates normalized feature vectors                   │
 │     • Computes derived ratios safely with epsilon:           │
 │       - cpu_mem_ratio                                        │
 │       - socket_thread_ratio                                  │
 │                                                              │
 │  4. PreprocessingPipeline (preprocessing/pipeline.py):       │
 │     • Coordinates End-to-End Execution                       │
 │     • Idempotent UPSERT into SQLite `processed_features`     │
 │     • Saves output to `data/processed/process_features.csv`  │
 └──────────────────────────────────────────────────────────────┘
                      │
                      ▼
       DOWNSTREAM BEHAVIORAL & ML MODELS
       (MAD Profiling, Random Forest, Risk Scoring)
```

---

## 2. Independent Review & Verification Criteria

| Verification Item | Status | Verification Detail |
|---|---|---|
| **1. PID Reuse & Process Identity** | **Verified** | Windows aggregate on `(window_start, pid, process_name)`. Because process names and start times are preserved, PID recycling across different binaries/times creates distinct records. |
| **2. Missing Categorical Values** | **Verified** | Imputed safely in `cleaner.py` (`username -> "unknown"`, `exe -> "unknown"`, `cmdline -> ""`, `status -> "unknown"`). |
| **3. Invalid Numeric Values** | **Verified** | Negative metrics resulting from counter resets or anomalous readings are clipped to 0.0 with explicit type casting, preventing NaN/corrupted values from propagating to ML models. |
| **4. 5-Second Window Boundaries** | **Verified** | Window boundaries are determined using deterministic flooring `timestamp.dt.floor("5s")` in UTC ISO-8601, ensuring synchronized time slices. |
| **5. Network Socket Feature Attribution** | **Verified** | Correlates concurrent active sockets (`open_sockets_count`) and unique external IPs (`distinct_remote_ips`) per `(window_start, pid)`. Process-to-socket attribution limits (unprivileged queries, socket races) are preserved. |
| **6. Pipeline Idempotency (No Duplicates)** | **Verified** | `processed_features` enforces `idx_pf_unique` on `(window_start, pid, process_name)` and uses `INSERT OR REPLACE`. Re-running the pipeline on identical telemetry leaves the count strictly at 2,892 records. |
| **7. Division by Zero Protection** | **Verified** | `cpu_mem_ratio` and `socket_thread_ratio` incorporate an epsilon term (`+ 1e-5`) in the denominator, preventing `ZeroDivisionError` or `inf` values. |
| **8. Historical Processing** | **Verified** | Handles past telemetry batches accurately without relying on host real-time clocks. |
| **9. Raw Telemetry Preservation** | **Verified** | `raw_process_telemetry` (3,154 records) and `raw_network_telemetry` (412 records) remain completely untouched. |
| **10. Existing Database Preservation** | **Verified** | Original M4 tables (`process_events`, `alerts`, `response_actions`, `verification_results`) and demo records remain intact. |

---

## 3. Database Status & Verification

All 2,892 processed feature records were queried and verified directly from SQLite:

```sql
SELECT count(*) FROM processed_features;
-- Result: 2892
```

### Table Schema (`processed_features`):
- `id`: Autoincrement integer primary key
- `window_start`: ISO-8601 UTC timestamp of window slot
- `pid`, `ppid`, `process_name`, `username`, `status`: Process identity
- `cpu_mean`, `cpu_max`, `cpu_std`: Compute usage dynamics
- `memory_mean`, `memory_max`, `memory_rss_mean`: Memory usage dynamics
- `num_threads_mean`, `num_threads_max`: Thread concurrency
- `open_sockets_count`, `distinct_remote_ips`: Socket activity
- `sample_count`: Frequency of observations in window
- `cpu_mem_ratio`, `socket_thread_ratio`: Derived behavioral ratios
- `UNIQUE INDEX`: `idx_pf_unique ON (window_start, pid, process_name)`

---

## 4. Full Regression Test Suite

Executed the entire test suite via `pytest`:
```bash
.venv/bin/python -m pytest -v
```

**Results:**
- **Total Tests:** 70
- **Passed:** 70 (100% pass rate)
- **Failed:** 0
- **Execution Time:** 0.74s

---

## 5. Safety & Integrity Confirmation

- Simulation mode remains the default.
- Zero Linux processes signaled or terminated.
- Zero network alterations or iptables changes.
- Pre-existing M4 SQLite data and Phase 2 telemetry tables are intact.
