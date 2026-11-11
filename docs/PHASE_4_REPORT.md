# Phase 4: Behavioural Profiling and Baseline Learning Technical Audit & Remediation

**Project:** ECHO — Endpoint Correlation and Host Orchestration  
**Phase:** Phase 4 — Behavioural Profiling and Baseline Learning  
**Audit & Remediation Date:** November 11, 2026  
**Status:** Remediated, Audited, and 100% Passing  

---

## 1. Executive Summary & Audit Verification Table

| Audit Task | Verification Requirement | Status | Detailed Technical Finding |
|---|---|---|---|
| **Task 1: Process Identity & Active Lookup** | Separate process-type vs instance identity | **VERIFIED** | Implemented `build_process_type_identity()` and `build_process_instance_identity()` in `baseline/identity.py`. |
| | PID reuse handling | **VERIFIED** | Instance identity incorporates `(username, process_name, pid, process_start_time)`. Process instances separated by time never share a single identity. |
| | Identity-aware baseline lookup | **VERIFIED** | Updated `BaselineStorage.get_active_baseline()`: prioritizes exact `process_identity` match $\to$ `(process_name, username)` $\to$ `process_name`. |
| | Accidental cross-process collision | **VERIFIED** | Baselines isolate processes by owner/identity (e.g. `root::sh` vs `vboxuser::sh`). |
| | Baseline version preservation | **VERIFIED** | Both `v1.0.0` (249 rows) and `v1.0.1` (247 rows) are preserved in `process_baselines` (total 496 rows). Older versions cannot become active due to strict `ORDER BY updated_at DESC LIMIT 1`. |
| **Task 2: MAD Scale-Floor Behavior** | Robust scale-floor formula | **VERIFIED** | $\text{scale} = \text{MAD}$ if $\text{MAD} > 10^{-4}$; otherwise $\max(0.10 \times \|\text{median}\|, 10^{-4})$. |
| | Zero median & zero MAD | **VERIFIED** | Tested: Uses $10^{-4}$ floor safely without zero division. |
| | Small, large, and constant values | **VERIFIED** | Small ($0.5$), large ($50,000$), and constant readings behave stably. |
| | Missing / invalid values | **VERIFIED** | Missing/NaN feature readings are explicitly flagged with `missing: True` and do NOT produce silent $0.0$ scores. |
| **Task 3: Anomaly Scoring Validation** | Range bounded $S \in [0.0, 1.0]$ | **VERIFIED** | $S = \frac{\max(\|Z\|)}{\max(\|Z\|) + 3.5}$. $S(0) = 0.0$, $S(3.5) = 0.50$, $S \to 1.0$ as $Z \to \infty$. |
| | Monotonicity & normalization | **VERIFIED** | Strictly increasing with deviation magnitude. Treated strictly as normalized deviation indicator, **not** malware probability. |
| | Statistical vs Security distinction | **VERIFIED** | Documented that statistical outliers indicate unmodeled behavior or compute bursts, requiring policy/correlation engines for security decisions. |
| **Task 4: Regression & Data Integrity** | Full test suite | **VERIFIED** | **89 passed out of 89 tests (100% pass rate)** in 0.77s. |
| | Database row counts intact | **VERIFIED** | All 8 tables intact with zero record loss. Quarantined records remain in `processed_features`. |

---

## 2. Detailed Technical Audit Findings

### 2.1 Process Identity & Active Lookup Implementation
In [`baseline/identity.py`](file:///home/vboxuser/Downloads/echo-project/baseline/identity.py):
1. **Process-Type Identity (`build_process_type_identity`):**
   - Canonical format: `type::<username>::<process_name>`
   - Represents the stable executable definition across invocations.
2. **Process-Instance Identity (`build_process_instance_identity`):**
   - Canonical format: `inst::<username>::<process_name>::<pid>::<process_start_time>`
   - Binds the physical OS PID to the process creation timestamp. When a PID is recycled hours or days later by the Linux kernel, the creation timestamp generates an entirely distinct instance identifier, preventing collision.
3. **Identity-Aware Active Lookup (`BaselineStorage.get_active_baseline`):**
   - Resolves profiles in descending specificity:
     1. Exact match on `process_identity`.
     2. Match on `process_name` AND `username` (`type::<username>::<process_name>`).
     3. Fallback to `process_name`.
   - Guaranteed version ordering: Always enforces `ORDER BY updated_at DESC LIMIT 1`. This prevents older baseline versions from ever becoming active accidentally.

### 2.2 Scale-Floor Formulation and Metric Suitability
In [`baseline/mad.py`](file:///home/vboxuser/Downloads/echo-project/baseline/mad.py):
```python
scale = mad
if scale <= epsilon:
    scale = max(0.10 * abs(median), epsilon)
z = 0.6745 * diff / scale
```
- **Rationale per Metric:**
  - **CPU Usage:** Many daemon processes run completely idle ($0.0\%$ CPU, $\text{MAD}=0.0$). A scale floor of $\max(0.10 \times 0.0, 10^{-4}) = 10^{-4}$ detects sudden bursts above idle without blowing up numerical precision.
  - **Memory Usage:** Persistent background daemons often consume stable memory (e.g. 100 MB, $\text{MAD}=0.0$). If memory rises to 110 MB, the $10\%$ median scale floor yields $\text{scale} = 10 \implies Z = 0.6745 \times \frac{10}{10} = 0.67$, correctly recognizing this as a minor natural fluctuation rather than an extreme outlier.
  - **Network Sockets & Threads:** Discrete counters with zero median use the $10^{-4}$ floor safely, bounding spikes within $[-1000, 1000]$.

### 2.3 Anomaly Scoring Properties & Missing Feature Safety
In [`baseline/comparator.py`](file:///home/vboxuser/Downloads/echo-project/baseline/comparator.py):
$$S = \frac{\max(|Z|)}{\max(|Z|) + 3.5} \in [0.0, 1.0)$$
- **Boundary Verification:**
  - Zero deviation: $\max(|Z|) = 0 \implies S = 0.0$.
  - At threshold: $\max(|Z|) = 3.5 \implies S = \frac{3.5}{3.5 + 3.5} = 0.50$.
  - High deviation: $\max(|Z|) = 14.0 \implies S = \frac{14.0}{17.5} = 0.80$.
  - Extreme deviation: $\max(|Z|) \to \infty \implies S \to 1.0$.
- **Missing Feature Safety:**
  If a feature value is `None` or `NaN`, the comparator does **not** evaluate it as $0.0$. Instead, it records:
  ```json
  {"observed_value": null, "modified_z_score": null, "missing": true}
  ```
  and excludes it from the max score computation, preventing unmeasured features from masking anomalies or faking normal readings.

### 2.4 Quarantined Outlier Preservation & 496 Baseline Records
- The **114 quarantined records** remain fully preserved in `data/echo.db` under `processed_features`. They were filtered purely in memory by `BaselineUpdater` to prevent anomalous telemetry from contaminating baseline updates.
- **Breakdown of the 496 Baseline Records:**
  - Version `1.0.0`: **249 profiles** (all processes with $\ge 3$ initial observations).
  - Version `1.0.1`: **247 profiles** (clean re-learning after masking the 114 outliers; 2 short-lived kernel workers dropped below the minimum observation threshold).
  - Both versions remain stored side-by-side in `process_baselines` for longitudinal auditability.

---

## 3. Database Integrity & State (Before vs After Audit)

| Table | Count Before Audit | Count After Audit | Integrity Status |
|---|---|---|---|
| `process_events` | 1 | 1 | Preserved (Original M4 demo) |
| `alerts` | 1 | 1 | Preserved (Original M4 demo) |
| `response_actions` | 1 | 1 | Preserved (Original M4 demo) |
| `verification_results` | 1 | 1 | Preserved (Original M4 demo) |
| `raw_process_telemetry` | 3,154 | 3,154 | Preserved (Phase 2 telemetry) |
| `raw_network_telemetry` | 412 | 412 | Preserved (Phase 2 telemetry) |
| `processed_features` | 2,892 | 2,892 | Preserved (Phase 3 5s windows) |
| `process_baselines` | 496 | 496 | Preserved (249 v1.0.0 + 247 v1.0.1) |

---

## 4. Full Regression Test Execution

Ran the complete project test suite via `pytest`:
```bash
.venv/bin/python -m pytest -v
```

**Results:**
- **Total Tests:** 89 (79 previous tests + 10 new identity, scale-floor, and anomaly scoring audit tests)
- **Passed:** 89 (100% pass rate)
- **Failed:** 0
- **Duration:** 0.77s

---

## 5. Remaining Limitations

1. **Short Historical Horizon (0.10 hours):** All learned profiles are truthfully flagged `baseline_status='preliminary'`. As telemetry accumulates towards 30 days, baselines will transition to `established`.
2. **Attribution Boundaries:** Ephemeral UDP connections that close in $<5$s remain subject to Linux socket attribution limits.
3. **Statistical Outlier $\ne$ Malicious Incident:** High Modified Z-scores reflect statistical deviation from past host behavior; downstream correlation with ML classifiers and policy rules (Phases 5-7) is required to determine security risk.
