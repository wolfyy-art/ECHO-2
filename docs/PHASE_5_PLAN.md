# Phase 5: Anomaly Detection Model Evaluation Methodology & Technical Plan

**Project:** ECHO — Endpoint Correlation and Host Orchestration  
**Phase:** Phase 5 — Anomaly Detection Model Evaluation  
**Status:** Approved Planning Specification (Pre-Implementation)  
**Date:** November 11, 2026  

---

## 1. Executive Summary & Purpose

Phase 5 evaluates unsupervised anomaly detection models to detect multivariate process deviations across the Linux host. The primary candidate is **Isolation Forest**, evaluated comparatively against our existing **Phase 4 non-parametric MAD baselines**.

This document details the exact evaluation methodology, temporal partitioning, mathematical formulation, metric definitions, and inherent experimental limitations.

**Integrity Constraints & Confirmation:**
- **No models have been trained or implemented.**
- **No changes have been made to Phase 1–4 modules or SQLite schemas.**
- **No synthetic data has been mixed into live telemetry.**
- **Simulation mode remains the immutable system default.**

---

## 2. Chronological Train/Test Partitioning

Standard random cross-validation randomly shuffles observations across time, causing severe **future-to-past data leakage** and falsely deflating error rates due to auto-correlated time series. Phase 5 enforces a strict, global timestamp-based **70:30 chronological split**.

### 2.1 Window-Preserving Split Boundaries
To prevent intra-window leakage, the split is applied at the level of distinct 5-second `window_start` boundaries rather than arbitrary individual rows:
- **Total Distinct 5-Second Windows:** 11 discrete windows
- **Training Window Set (First 70% of Windows, ~63.6% of records):**
  - **Window Count:** 7 windows
  - **Timestamp Span:** `2026-11-11T06:21:15Z` to `2026-11-11T06:26:40Z`
  - **Record Count:** 1,838 observations
- **Testing Window Set (Final 30% of Windows, ~36.4% of records):**
  - **Window Count:** 4 windows
  - **Timestamp Span:** `2026-11-11T06:26:45Z` to `2026-11-11T06:27:10Z`
  - **Record Count:** 1,054 observations
- **Split Rule:** All process observations captured during a given 5-second interval reside strictly on one side of the split boundary.

### 2.2 Process Overlap & Generalisation Dynamics
- **Processes in Training Set:** 259 unique process names
- **Processes in Testing Set:** 247 unique process names
- **Overlapping Processes (Seen in both):** 241 processes (~97.6% of test processes)
- **Unseen Processes in Testing Set:** Exactly 6 short-lived kernel workers:
  - `kworker/u20:0-writeback`
  - `kworker/u18:5-ext4-rsv-conversion`
  - `kworker/3:3-events`
  - `kworker/u17:2-events_unbound`
  - `kworker/u18:5-events_unbound`
  - `kworker/u17:3-flush-8:0`
- **Adjacent-Window Autocorrelation Effect:** Because background Linux daemons maintain stable resident memory and state over consecutive 5-second windows, observations from adjacent intervals exhibit strong serial correlation. The evaluation will report generalisation on persistent processes vs. unseen short-lived kernel tasks separately.

---

## 3. Isolation Forest Architecture & Sensitivity Experiments

### 3.1 Model Formulation
Isolation Forest explicitly isolates anomalies instead of profiling normal points. It constructs an ensemble of Isolation Trees ($iTrees$), where anomalies are isolated closer to the root of the tree:
$$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$
where $h(x)$ is the path length of observation $x$, $E(h(x))$ is the average path length across all trees, and $c(n)$ is the average path length of unsuccessful searches in a Binary Search Tree (BST) of $n$ samples.

### 3.2 Baseline Model Hyperparameters
- `n_estimators`: `100` trees (standard convergence for tabular ensembles)
- `random_state`: `42` (ensures bit-for-bit experimental reproducibility)
- `max_samples`: `'auto'` ($\min(256, N)$ to prevent tree masking and swamping)
- `contamination`: `0.05` (initial nominal operating point)

### 3.3 Contamination Sensitivity Experiments
The `contamination` parameter defines the threshold quantile on decision function scores:
$$\text{Decision Boundary: } \text{score} < \tau_{\text{contamination}}$$
- **Crucial Clarification:** `contamination` represents an **assumed outlier proportion** in the training distribution, **never** an estimate of malware prevalence.
- **Sensitivity Grid:** The model will be evaluated across three distinct contamination assumptions:
  1. `contamination = 0.01` (Conservative / Low Alert Rate)
  2. `contamination = 0.05` (Nominal Baseline)
  3. `contamination = 0.10` (Permissive / High Sensitivity)
- **Evaluation:** Measure how shifting contamination changes threshold sensitivity, detection stability, and false-positive rates on known normal daemons.

---

## 4. Multi-Dimensional MAD Comparative Analysis

Phase 4 provided univariate statistical baselines via Median Absolute Deviation. In Phase 5, Isolation Forest will be systematically compared against MAD to understand model alignment and divergence:

1. **Spearman Rank Correlation:**
   Measure the non-parametric monotonic rank correlation between the continuous Isolation Forest anomaly score $S_{\text{IF}} \in [0, 1]$ and the composite MAD score $S_{\text{MAD}} \in [0, 1]$.
2. **Top-K Anomaly Overlap (Jaccard Index):**
   Calculate the intersection-over-union of the top 5% most anomalous observations identified by Isolation Forest versus those identified by MAD:
   $$J(A_{\text{IF}}, A_{\text{MAD}}) = \frac{|A_{\text{IF}} \cap A_{\text{MAD}}|}{|A_{\text{IF}} \cup A_{\text{MAD}}|}$$
3. **Per-Feature Disagreement Analysis:**
   Inspect cases where MAD flags a single univariate outlier (e.g., CPU burst with zero socket activity) while Isolation Forest considers it normal, or vice versa (multivariate correlation shift where individual features remain within median bounds).
4. **Epistemic Limitation:**
   **High agreement between Isolation Forest and MAD does NOT establish security correctness.** Both are purely statistical measures of distribution rarity. If a benign process exhibits a rare memory spike, both models may flag it; conversely, stealthy malware operating within ordinary compute thresholds may be missed by both.

---

## 5. Comprehensive Evaluation Metrics

Because natural host telemetry contains zero ground-truth security labels, **Precision, Recall, and F1-score will NOT be reported as real-world security metrics.** Reporting pseudo-precision against unlabeled telemetry is scientifically invalid.

Instead, the evaluation will measure:

### 5.1 Computational Performance & Resource Overhead
- **Model Training Time:** Clock time in milliseconds to fit the ensemble on the training split.
- **Inference Latency Profile:**
  - Average inference latency per window ($\mu\text{s}$)
  - Median inference latency per window ($\mu\text{s}$)
  - 95th Percentile ($p_{95}$) latency ($\mu\text{s}$)
- **Memory Consumption:** Peak resident set size (RSS) differential during inference and serialized model footprint on disk (`.joblib` artifact size).

### 5.2 Stability & False-Positive Behavior on Ordinary Workloads
- **Per-Process-Type Score Stability:** Variance ($\sigma^2$) of anomaly scores across stable core daemons (`systemd`, `systemd-journald`, `dbus-daemon`, `chrony`). Core system daemons should exhibit consistent, low anomaly scores over time.
- **Ordinary Workload False-Positive Rate:** Proportion of normal background process windows assigned anomaly scores exceeding the threshold.

---

## 6. Controlled Synthetic Test Fixtures (Isolated Benchmark)

To evaluate boundary sensitivity and true positive behavior under controlled conditions:
- **Strict Separation:** Synthetic test fixtures will reside purely in unit test harnesses (`tests/test_detection.py`), completely segregated from the live SQLite database and training telemetry.
- **Perturbation Injection Scenarios:**
  1. *Compute Exhaustion:* Injection of synthetic CPU spike ($\ge 98.0\%$).
  2. *Socket Flooding:* Injection of rapid socket growth ($> 50$ open TCP sockets).
  3. *Thread Ballooning:* Injection of abnormal thread churn ($> 64$ threads).
- **Explicit Labeling:** All perturbation detection rates will be explicitly documented as **controlled synthetic benchmark results**, **never** as real-world production detection accuracy.

---

## 7. Explicit Project Limitations

The Phase 5 evaluation will explicitly state the following scientific boundaries:
1. **Short Historical Horizon (355 Seconds):**
   The telemetry covers 0.10 hours of host runtime. It cannot reflect daily usage patterns, weekly cron jobs, diurnal shifts, or package upgrades.
2. **Zero Ground-Truth Security Labels:**
   All host telemetry was collected during standard VM operations. No active malware was running during collection.
3. **Serial Correlation Between Adjacent Windows:**
   Consecutive 5-second observations of long-running daemons are not independent and identically distributed ($i.i.d.$).
4. **Preliminary Reference Baselines:**
   Phase 4 baselines are preliminary ($0.0137\%$ of 30 days). Comparisons reflect agreement with preliminary heuristics rather than mature profiles.
5. **Limited Generalisation Evidence:**
   With 241 out of 247 test processes previously seen in training, the test set primarily evaluates temporal reconstruction rather than generalized zero-day detection on novel applications.

---

## 8. Confirmation

- **No Isolation Forest model has been created or trained.**
- **No production code or database tables have been modified.**
- **Phase 5 remains in planning status pending operator approval.**
