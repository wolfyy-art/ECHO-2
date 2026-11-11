# ECHO — Endpoint Correlation and Host Orchestration

## Description

ECHO is a Linux-based process-level anomaly detection and security monitoring system.
It collects real-time system telemetry (processes, network connections, resource usage),
applies machine learning to detect anomalies, correlates suspicious events across host
endpoints, and presents findings through an interactive dashboard — all designed as a
college minor project demonstrating applied ML in a cybersecurity context.

---

## Folder Structure

| Folder | Purpose |
|---|---|
| `collector/` | Gathers raw telemetry from the host — process lists, CPU/memory usage, network connections — using libraries like `psutil`. |
| `data/raw/` | Stores unprocessed telemetry data as collected from the system (CSV or JSON snapshots). |
| `data/processed/` | Stores cleaned, normalized, and feature-engineered data ready for model training or inference. |
| `preprocessing/` | Contains scripts for data cleaning, normalization, feature extraction, and transformation pipelines. |
| `detection/` | Houses the anomaly detection logic — model training, inference, and scoring of process-level events. |
| `correlation/` | Correlates related anomalous events across time and process trees to identify attack patterns or suspicious sequences. |
| `response/` | Implements automated or semi-automated response actions (e.g., alerting, logging, process flagging) triggered by detections. |
| `verification/` | Provides utilities to validate detections — reducing false positives by cross-checking alerts against known baselines. |
| `dashboard/` | Streamlit-based interactive web dashboard for visualizing real-time and historical alerts, metrics, and system state. |
| `models/` | Persists trained ML model artifacts (serialized with `joblib`) for use during live inference. |
| `tests/` | Unit and integration tests for all modules to ensure correctness and regression safety. |

---

## Tech Stack

- **Language:** Python 3
- **Data collection:** psutil
- **Data processing:** pandas
- **Machine learning:** scikit-learn
- **Model persistence:** joblib
- **Dashboard:** Streamlit
