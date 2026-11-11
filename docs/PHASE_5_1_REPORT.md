# Phase 5.1: Isolation Forest Implementation and Controlled Evaluation Report

**Project:** ECHO — Endpoint Correlation and Host Orchestration  
**Phase:** Phase 5.1 — Isolation Forest Implementation and Controlled Evaluation  
**Date:** November 11, 2026  
**Status:** Completed, Evaluated, and 100% Passing  

---

## 1. Executive Summary & Verification Matrix

Phase 5.1 delivers an isolated, production-grade anomaly detection pipeline using an unsupervised **Isolation Forest** to model multi-dimensional process behaviors. All implementation, chronological dataset partitioning, sensitivity experiments, statistical comparisons, and controlled perturbation benchmarks have been executed in strict adherence to the approved Phase 5 methodology without modifying previous phase implementations, modifying database schemas, or enabling real enforcement actions.

| Verification Requirement | Status | Detailed Technical Result |
|---|---|---|
| **Module Isolation** | **VERIFIED** | Implemented isolated module in `detection/` (`isolation_forest.py`, `evaluation.py`, `metrics.py`, `__init__.py`). |
| **Model Configuration** | **VERIFIED** | `IsolationForestConfig(n_estimators=100, random_state=42, max_samples='auto', contamination=0.05)` with deterministic reproducibility. |
| **Approved Feature Matrix** | **VERIFIED** | Strict enforcement of 13 approved numerical features. Missing or NaN values are explicitly detected and handled without silent $0.0$ conversions. |
| **Chronological Window Split** | **VERIFIED** | Window-preserving 70:30 global chronological split verified programmatically: 7 train windows (1,838 obs) vs. 4 test windows (1,054 obs). Zero window leakage. |
| **Contamination Sensitivity** | **VERIFIED** | Evaluated contamination levels $0.01$, $0.05$, and $0.10$. Monotonic shift in offset threshold confirmed ($-0.7404 \to -0.6077 \to -0.4726$). |
| **MAD Comparative Analysis** | **VERIFIED** | Evaluated against Phase 4 MAD baselines: Spearman rank correlation $\rho = 0.4830$ ($p < 0.001$), Jaccard similarity at Top-5% $J = 0.3585$. Disagreements analyzed. |
| **Synthetic Perturbation Tests** | **VERIFIED** | Controlled test fixtures (CPU $\ge 98\%$, sockets $> 50$, threads $> 64$) passed 100%. Labeled strictly as synthetic sensitivity benchmarks, not real-world security metrics. |
| **Inference Latency & Sizing** | **VERIFIED** | Single-row inference: mean $4.23\,\text{ms}$, median $3.78\,\text{ms}$, p95 $5.91\,\text{ms}$. Batch ($2,892$ rows): $10.68\,\text{ms}$. Model artifact size: $524.8\,\text{KB}$. Training time: $195.1\,\text{ms}$. |
| **Process Generalisation** | **VERIFIED** | Tested on 241 seen processes ($1,044$ obs, mean score $0.4412$) and 6 unseen kernel workers ($10$ obs, mean score $0.4327$). Unseen idle workers were correctly recognized as low-risk. |
| **Safety & Simulation Mode** | **VERIFIED** | Simulation-only mode remains active default. No process termination, network isolation, or policy execution performed. No Random Forest implemented. |
| **Database & Regression Integrity** | **VERIFIED** | All 8 SQLite database tables intact ($0$ rows altered/added/removed). Full test suite: **98 passed out of 98 tests (100% pass rate)**. |

---

## 2. Dataset Partitioning & Window Preservation

A strict global timestamp-based chronological split was enforced on `processed_features` ($2,892$ total observations spanning 11 discrete 5-second windows). Individual rows were **never** randomly split, preventing temporal data leakage.

### 2.1 Partitioning Statistics

| Partition | Window Count | Timestamp Range (UTC) | Observation Count | Unique Process Types |
|---|---|---|---|---|
| **Training (70%)** | 7 windows | `2026-11-11 06:21:15` to `2026-11-11 06:26:40` | **1,838** | 241 |
| **Testing (30%)** | 4 windows | `2026-11-11 06:26:45` to `2026-11-11 06:27:10` | **1,054** | 247 |
| **Total** | 11 windows | Full 355-second historical duration | **2,892** | 247 |

- **Process Overlap:** 241 processes appear in both training and testing.
- **Unseen Processes in Test:** 6 kernel worker process types appeared exclusively in the test windows:
  1. `kworker/3:3-events` (2 observations)
  2. `kworker/u17:2-events_unbound` (2 observations)
  3. `kworker/u17:3-flush-8:0` (2 observations)
  4. `kworker/u18:5-events_unbound` (2 observations)
  5. `kworker/u18:5-ext4-rsv-conversion` (1 observation)
  6. `kworker/u20:0-writeback` (1 observation)

---

## 3. Isolation Forest Implementation Architecture

The detection system is encapsulated within the [`detection/`](file:///home/vboxuser/Downloads/echo-project/detection) package:

- [`detection/isolation_forest.py`](file:///home/vboxuser/Downloads/echo-project/detection/isolation_forest.py): Implements `ProcessIsolationForest` using scikit-learn's `IsolationForest` engine.
- [`detection/metrics.py`](file:///home/vboxuser/Downloads/echo-project/detection/metrics.py): Implements rank correlation (`compute_spearman_rank_correlation`), set overlap (`compute_top_k_jaccard_overlap`), and latency distribution calculations (`compute_latency_percentiles`).
- [`detection/evaluation.py`](file:///home/vboxuser/Downloads/echo-project/detection/evaluation.py): Orchestrates chronological splitting, sensitivity analysis, MAD comparison, and generalisation profiling.

### 3.1 Approved Feature Matrix (13 Numerical Features)
The model consumes strictly validated numerical features derived from Phase 3 preprocessing:
1. `cpu_mean`
2. `cpu_max`
3. `cpu_std`
4. `memory_mean`
5. `memory_max`
6. `memory_rss_mean`
7. `num_threads_mean`
8. `num_threads_max`
9. `open_sockets_count`
10. `distinct_remote_ips`
11. `sample_count`
12. `cpu_mem_ratio`
13. `socket_thread_ratio`

Missing or NaN features are intercepted during feature matrix validation; rows with unmeasured features are identified explicitly and flagged rather than silently coerced to $0.0$.

### 3.2 Continuous Anomaly Score Normalisation
Raw scikit-learn decision function outputs $D(x)$ (where negative values represent outliers and positive values represent inliers) are transformed into a normalized anomaly score $S(x) \in [0.0, 1.0]$ via a logistic sigmoid transformation:

$$S(x) = \frac{1}{1 + e^{D(x)}}$$

- **Threshold Behavior:** When $D(x) = 0.0$ (the boundary between inlier and outlier under default zero-centering), $S(x) = 0.50$.
- **Inlier Behavior:** As $D(x) > 0$ (deep inlier), $S(x) < 0.50$, approaching $0.0$.
- **Outlier Behavior:** As $D(x) < 0$ (extreme isolation), $S(x) > 0.50$, approaching $1.0$.

---

## 4. Contamination Parameter Sensitivity Analysis

The contamination parameter governs the decision boundary offset ($\text{offset}\_$) calculated on the training distribution. It represents an assumed proportion of statistical outliers in the baseline training data, **not** an estimate of malware prevalence.

| Contamination ($\gamma$) | Decision Offset ($\text{offset}\_$) | Train Outliers Flagged | Train Outlier % | Test Outliers Flagged | Test Outlier % |
|---|---|---|---|---|---|
| **0.01** | $-0.7404$ | $18\,/\,1,838$ | $1.0\%$ | $14\,/\,1,054$ | $1.3\%$ |
| **0.05 (Baseline)** | $-0.6077$ | $90\,/\,1,838$ | $4.9\%$ | $52\,/\,1,054$ | $4.9\%$ |
| **0.10** | $-0.4726$ | $184\,/\,1,838$ | $10.0\%$ | $101\,/\,1,054$ | $9.6\%$ |

### 4.1 Observations
1. **Monotonicity:** As contamination increases from $0.01$ to $0.10$, the offset shifts monotonically upward from $-0.7404$ to $-0.4726$, loosening the criterion required to be classified as an outlier.
2. **Generalisation Stability:** For the baseline $\gamma = 0.05$, the test set outlier proportion ($4.9\%$, 52 observations) mirrors the training set proportion ($4.9\%$, 90 observations), demonstrating stability across chronological windows without drift collapse.

---

## 5. Comparative Evaluation: Isolation Forest vs. MAD Baselines

Isolation Forest was compared against the Phase 4 MAD baseline anomaly scoring across all $2,866$ observations that had corresponding active baseline profiles.

### 5.1 Statistical Metrics

| Metric | Result | Interpretation |
|---|---|---|
| **Spearman Rank Correlation ($\rho$)** | **$0.4830$** ($p < 0.001$) | Moderate positive monotonic alignment. Demonstrates directional agreement while capturing distinct structural behaviors. |
| **Top-5% Jaccard Index ($J$)** | **$0.3585$** | Noticeable overlap in the most extreme anomalies with complementary detection coverage. |
| **Top-5% Outlier Set Size ($k$)** | $144$ observations | Top $5\%$ most anomalous readings in the $2,866$ observation evaluation set. |
| **Intersection (Both Detectors)** | **$76$ observations** | Concordant extreme outliers recognized by both MAD and Isolation Forest. |
| **Isolation Forest Only** | **$68$ observations** | Flagged due to multivariate feature correlation (e.g. socket-to-thread anomalies or high-memory paired with unusual thread counts) where univariate MAD remained sub-threshold. |
| **MAD Only** | **$68$ observations** | Flagged due to single-variable deviations from narrow historical baselines (e.g. idle processes having single minor spikes) where global tree isolation did not isolate the sample. |

### 5.2 Why Agreement Does Not Establish Security Correctness
Statistical concordance ($\rho = 0.4830$) indicates that both models detect deviations from typical historical measurements. However:
- Neither model possesses awareness of semantic maliciousness. A large legitimate workload spike (e.g., database compilation, package manager update) will produce high scores in both models.
- Concordance proves mathematical stability of outlier identification across independent statistical paradigms (tree-based spatial partitioning vs. univariate median dispersion), but cannot replace semantic policy and host correlation.

---

## 6. Controlled Synthetic Perturbation Benchmarks

> [!IMPORTANT]
> **Controlled Benchmark Notice:** The perturbation results below are synthetic sensitivity benchmarks designed to verify algorithmic response to extreme behavioral deviations. They do **not** represent production security accuracy, malware classification precision, or operational detection rates.

Three controlled anomaly fixtures were evaluated by perturbing normal baseline process observations:

| Perturbation Scenario | Synthetic Perturbation Injected | Expected Algorithmic Response | Observed Anomaly Score | Test Status |
|---|---|---|---|---|
| **Extreme CPU Spike** | CPU Mean set to $99.5\%$, CPU Max set to $100.0\%$, CPU Std set to $0.25$ | High isolation, score $> 0.50$, higher than normal observation | Normal: $0.4410$ $\to$ Perturbed: **$0.5117$** | **PASSED** |
| **Socket Burst** | Sockets set to $75$, Remote IPs set to $45$, Socket-Thread ratio set to $37.5$ | Significant multi-dimensional isolation, score $> 0.50$ | Normal: $0.4287$ $\to$ Perturbed: **$0.5190$** | **PASSED** |
| **Thread Churn** | Threads Mean set to $128$, Threads Max set to $128$ | Multi-tree rapid isolation, score $> 0.50$ | Normal: $0.4336$ $\to$ Perturbed: **$0.5161$** | **PASSED** |

In all three synthetic scenarios, the model successfully isolated the perturbed observations into outlier territory ($S > 0.50$, corresponding to negative decision function values).

---

## 7. Inference Latency & Resource Utilization

Benchmarks were measured using Python `time.perf_counter()` on the host system (Linux x86_64).

| Evaluation Parameter | Measurement | Target / Budget | Operational Suitability |
|---|---|---|---|
| **Single-Row Inference Mean** | **$4.23\,\text{ms}$** | $< 20.0\,\text{ms}$ | Fully suitable for real-time per-window evaluation |
| **Single-Row Inference Median** | **$3.78\,\text{ms}$** | $< 10.0\,\text{ms}$ | Low jitter under typical conditions |
| **Single-Row Inference P95** | **$5.91\,\text{ms}$** | $< 30.0\,\text{ms}$ | Within real-time 5-second ingestion window |
| **Single-Row Inference Max** | **$14.24\,\text{ms}$** | $< 50.0\,\text{ms}$ | No excessive latency spikes |
| **Batch Inference ($2,892$ rows)** | **$10.68\,\text{ms}$** | $< 500.0\,\text{ms}$ | $0.0037\,\text{ms}$ per observation in vectorized mode |
| **Model Training Time** | **$195.1\,\text{ms}$** | $< 5,000.0\,\text{ms}$ | Rapid retraining capability |
| **Model Artifact Size on Disk** | **$524.8\,\text{KB}$** | $< 10.0\,\text{MB}$ | Compact deployment footprint (`baseline_iforest.joblib`) |

---

## 8. Process Generalisation Analysis

The test partition contains 241 process types previously seen during training and 6 kernel worker process types seen exclusively during test windows.

### 8.1 Comparison of Score Distributions

| Process Group | Observation Count | Mean Anomaly Score | Median Anomaly Score | P95 Anomaly Score | Outlier Count ($S > 0.50$) |
|---|---|---|---|---|---|
| **Seen Processes** | $1,044$ | **$0.4412$** | $0.4336$ | $0.5000$ | $52$ ($5.0\%$) |
| **Unseen Processes (Kernel Workers)** | $10$ | **$0.4327$** | $0.4287$ | $0.4504$ | **$0$ ($0.0\%$)** |

### 8.2 Breakdown of Unseen Kernel Workers
All 6 unseen kernel workers exhibited normal, low-resource background profiles:
1. `kworker/3:3-events`: $n=2$, mean score $= 0.4287$, max score $= 0.4287$
2. `kworker/u17:2-events_unbound`: $n=2$, mean score $= 0.4484$, max score $= 0.4681$
3. `kworker/u17:3-flush-8:0`: $n=2$, mean score $= 0.4287$, max score $= 0.4287$
4. `kworker/u18:5-events_unbound`: $n=2$, mean score $= 0.4287$, max score $= 0.4287$
5. `kworker/u18:5-ext4-rsv-conversion`: $n=1$, mean score $= 0.4287$, max score $= 0.4287$
6. `kworker/u20:0-writeback`: $n=1$, mean score $= 0.4287$, max score $= 0.4287$

**Key Finding:** The model demonstrated solid inductive bias: unseen kernel workers were not falsely flagged as anomalous simply because their process names were novel. Because the Isolation Forest evaluates numerical feature coordinates rather than nominal labels, low-activity kernel workers clustered tightly in the dominant inlier region of the feature space.

---

## 9. Methodological Limitations & Safety Controls

1. **Short Historical Duration:** Telemetry spans 355 seconds across 11 discrete 5-second windows. While sufficient for statistical evaluation of algorithm dynamics, it does not represent multi-week operational variation (e.g. daily backups, maintenance crons).
2. **Absence of Ground-Truth Malware Labels:** The dataset contains genuine host telemetry collected from an uninfected Linux system. Consequently, **precision, recall, and F1 scores cannot be computed or claimed as real-world security metrics**. Any such claims would be scientifically misleading.
3. **Serial Correlation:** Consecutive 5-second windows are not independent and identically distributed ($i.i.d.$). Adjacent windows share state; hence, split boundaries were preserved at window granularity to minimize leakage.
4. **Reference Baseline Nature:** Phase 4 MAD profiles serve as an empirical comparative baseline, not ground truth.
5. **No Random Forest Implemented:** Supervised classification remains unjustified and deferred due to the lack of verified malicious sample labels.
6. **No Real Enforcement:** Simulation-only mode remains strictly active across all project modules.

---

## 10. Database State & Regression Verification

### 10.1 Database Record Counts

| Table Name | Pre-Phase 5.1 Count | Post-Phase 5.1 Count | Change | Integrity Status |
|---|---|---|---|---|
| `process_events` | 1 | 1 | $0$ | Preserved |
| `alerts` | 1 | 1 | $0$ | Preserved |
| `response_actions` | 1 | 1 | $0$ | Preserved |
| `verification_results` | 1 | 1 | $0$ | Preserved |
| `raw_process_telemetry` | 3,154 | 3,154 | $0$ | Preserved |
| `raw_network_telemetry` | 412 | 412 | $0$ | Preserved |
| `processed_features` | 2,892 | 2,892 | $0$ | Preserved |
| `process_baselines` | 496 | 496 | $0$ | Preserved |

### 10.2 Regression Test Suite Results
The full test suite was executed against `.venv/bin/pytest -v`:

```
============================== 98 passed in 2.16s ==============================
```

- **Phase 1–4 Tests:** 89 passed out of 89.
- **Phase 5.1 Detection Tests:** 9 passed out of 9:
  - `test_contamination_parameter_shifts_offset` (PASSED)
  - `test_controlled_cpu_spike_perturbation` (PASSED)
  - `test_controlled_socket_burst_perturbation` (PASSED)
  - `test_controlled_thread_churn_perturbation` (PASSED)
  - `test_fit_score_and_save_model` (PASSED)
  - `test_metrics_spearman_and_jaccard` (PASSED)
  - `test_missing_feature_column_raises_error` (PASSED)
  - `test_missing_or_nan_values_handled_explicitly` (PASSED)
  - `test_unseen_processes_generalisation_handling` (PASSED)

---

## 11. Conclusion & Next Steps

Phase 5.1 is complete, verified, and audited. The trained model artifact is stored at `models/baseline_iforest.joblib`. All constraints have been respected:
- No Phase 1–4 modules rewritten.
- No SQLite schema alterations made.
- No database telemetry fabricated or altered.
- No Random Forest trained or implemented.
- Default simulation mode strictly preserved.
- Real process termination and network isolation remain disabled.

**Awaiting user review and authorization before proceeding to Phase 5.2.**
