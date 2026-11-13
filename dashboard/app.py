"""
dashboard/app.py
================
ECHO — Endpoint Correlation and Host Orchestration: Interactive Security Operations Dashboard
Author: Mayank (M4)

Real-Time Multi-Process Behavioral Monitoring, Anomaly Detection & Safe Containment.
Covers 8 core functional views:
1. System Overview (Host status, telemetry metrics, alerts, risk distribution)
2. Live Process Monitoring (Real host process inspection, CPU/RAM, sockets)
3. ML Anomaly Detection (Isolation Forest scores, approved features, metadata)
4. Behavioural Profiling & MAD (Per-process baseline vs observation deviations)
5. Correlation & Risk Scoring (M, A, Q signals -> Composite Risk R)
6. Security Alerts (Triaged severity, lifecycle status, details)
7. Safe Response Management (Simulation containment, approval gates, audit history)
8. Closed-Loop Verification (Verification outcomes, zero collateral impact asserts)
"""

import os
import sys
import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List

import pandas as pd
import streamlit as st

# Setup project root import
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from dashboard.database import (
    DB_PATH,
    init_database,
    get_recent_process_events,
    get_active_alerts,
    get_response_history,
    get_verification_history,
    _get_connection,
)
from detection.isolation_forest import APPROVED_FEATURE_COLUMNS

# ---------------------------------------------------------------------------
# Streamlit Page Configuration
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="ECHO — Security Operations Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for styling
st.markdown("""
<style>
    .metric-card {
        background-color: #1E222A;
        border-radius: 8px;
        padding: 15px;
        margin-bottom: 15px;
        border-left: 4px solid #4CAF50;
    }
    .metric-card-alert {
        background-color: #1E222A;
        border-radius: 8px;
        padding: 15px;
        margin-bottom: 15px;
        border-left: 4px solid #F44336;
    }
    .metric-card-warning {
        background-color: #1E222A;
        border-radius: 8px;
        padding: 15px;
        margin-bottom: 15px;
        border-left: 4px solid #FF9800;
    }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Data Retrieval Helpers
# ---------------------------------------------------------------------------

@st.cache_data(ttl=5)
def load_database_tables():
    """Load core tables from SQLite into DataFrames."""
    if not DB_PATH.exists():
        init_database(DB_PATH)

    conn = _get_connection(DB_PATH)
    try:
        events_df = pd.read_sql_query("SELECT * FROM process_events ORDER BY timestamp DESC", conn)
        alerts_df = pd.read_sql_query("SELECT * FROM alerts ORDER BY timestamp DESC", conn)
        responses_df = pd.read_sql_query("SELECT * FROM response_actions ORDER BY timestamp DESC", conn)
        verifications_df = pd.read_sql_query("SELECT * FROM verification_results ORDER BY timestamp DESC", conn)
        
        # Check if correlation_records exists
        corr_exists = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='correlation_records'").fetchone()
        if corr_exists:
            correlation_df = pd.read_sql_query("SELECT * FROM correlation_records ORDER BY timestamp DESC", conn)
        else:
            correlation_df = pd.DataFrame()

        # Check if processed_features exists
        feat_exists = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='processed_features'").fetchone()
        if feat_exists:
            features_df = pd.read_sql_query("SELECT * FROM processed_features ORDER BY window_start DESC LIMIT 200", conn)
        else:
            features_df = pd.DataFrame()

        return events_df, alerts_df, responses_df, verifications_df, correlation_df, features_df
    finally:
        conn.close()


def load_model_metadata():
    """Load Isolation Forest training metadata."""
    meta_path = _PROJECT_ROOT / "models" / "metadata.json"
    if meta_path.exists():
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    return None


# ---------------------------------------------------------------------------
# Sidebar Navigation
# ---------------------------------------------------------------------------
st.sidebar.image("https://img.icons8.com/color/96/000000/shield.png", width=64)
st.sidebar.title("ECHO Security Console")
st.sidebar.caption("Endpoint Correlation & Host Orchestration")

st.sidebar.markdown("---")
page = st.sidebar.radio(
    "Navigation",
    [
        "1. System Overview",
        "2. Live Process Monitoring",
        "3. ML Anomaly Detection",
        "4. Correlation & Risk Scoring",
        "5. Security Alerts",
        "6. Response Management",
        "7. Closed-Loop Verification",
        "8. Prometheus & Monitoring",
    ]
)

st.sidebar.markdown("---")
st.sidebar.markdown("### Operational Controls")
if st.sidebar.button("🔄 Refresh Data"):
    st.cache_data.clear()
    st.rerun()

st.sidebar.info("""
**Execution Mode:** `SIMULATION`  
**Safety Allowlist:** Active  
**Enforcement:** Zero OS-Harm  
""")

events_df, alerts_df, responses_df, verifications_df, correlation_df, features_df = load_database_tables()
model_meta = load_model_metadata()

# ---------------------------------------------------------------------------
# PAGE 1: SYSTEM OVERVIEW
# ---------------------------------------------------------------------------
if page == "1. System Overview":
    st.header("🛡️ System Overview & Security Posture")
    st.caption("High-level operational metrics across telemetry, detection, correlation, and response.")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Process Events", len(events_df))
    with col2:
        open_alerts = len(alerts_df[alerts_df["status"] == "open"]) if not alerts_df.empty else 0
        st.metric("Active Alerts (Open)", open_alerts, delta="High Priority" if open_alerts > 0 else "Clear")
    with col3:
        st.metric("Simulated Responses", len(responses_df))
    with col4:
        if not verifications_df.empty:
            success_count = (verifications_df["success"] == 1).sum()
            success_rate = (success_count / len(verifications_df)) * 100.0
            st.metric("Verification Rate", f"{success_rate:.1f}%")
        else:
            st.metric("Verification Rate", "100.0%")

    st.markdown("---")

    col_left, col_right = st.columns([1, 1])

    with col_left:
        st.subheader("📊 Events by Risk Level")
        if not events_df.empty and "risk_level" in events_df.columns:
            risk_counts = events_df["risk_level"].value_counts().reset_index()
            risk_counts.columns = ["Risk Level", "Count"]
            st.bar_chart(risk_counts.set_index("Risk Level"))
        else:
            st.info("No process events recorded yet.")

    with col_right:
        st.subheader("🚨 Security Alerts by Severity")
        if not alerts_df.empty and "severity" in alerts_df.columns:
            sev_counts = alerts_df["severity"].value_counts().reset_index()
            sev_counts.columns = ["Severity", "Count"]
            st.bar_chart(sev_counts.set_index("Severity"))
        else:
            st.info("No security alerts recorded.")

    st.markdown("---")
    st.subheader("🕒 Recent Security Events")
    if not events_df.empty:
        st.dataframe(
            events_df[["event_id", "timestamp", "pid", "process_name", "cpu_percent", "memory_percent", "risk_level"]].head(10),
            use_container_width=True,
        )
    else:
        st.info("No recent events available.")

# ---------------------------------------------------------------------------
# PAGE 2: LIVE PROCESS MONITORING
# ---------------------------------------------------------------------------
elif page == "2. Live Process Monitoring":
    st.header("🖥️ Live Host Process Telemetry")
    st.caption("Telemetry stream captured by the M1 Collector and ingested into SQLite.")

    if not events_df.empty:
        col1, col2 = st.columns([2, 1])
        with col1:
            search_term = st.text_input("Filter by Process Name or PID:", "")
        with col2:
            risk_filter = st.selectbox("Filter by Risk Level:", ["All", "high", "medium", "low", "unknown"])

        filtered_df = events_df.copy()
        if search_term:
            filtered_df = filtered_df[
                filtered_df["process_name"].str.contains(search_term, case=False, na=False) |
                filtered_df["pid"].astype(str).str.contains(search_term)
            ]
        if risk_filter != "All":
            filtered_df = filtered_df[filtered_df["risk_level"] == risk_filter]

        st.dataframe(filtered_df, use_container_width=True)

        st.subheader("Resource Usage Analysis")
        col_c1, col_c2 = st.columns(2)
        with col_c1:
            st.scatter_chart(data=filtered_df, x="cpu_percent", y="memory_percent", color="risk_level")
        with col_c2:
            st.line_chart(data=filtered_df.head(30), y="cpu_percent")
    else:
        st.info("No telemetry events found. Run `python run_echo.py` or `python dashboard/seed_demo.py` to ingest observations.")

# ---------------------------------------------------------------------------
# PAGE 3: ML ANOMALY DETECTION
# ---------------------------------------------------------------------------
elif page == "3. ML Anomaly Detection":
    st.header("🤖 Isolation Forest ML Anomaly Detection")
    st.caption("Unsupervised Isolation Forest evaluation on 13 approved telemetry features.")

    if model_meta:
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Model Type", model_meta.get("model_type", "IsolationForest"))
        with col2:
            st.metric("Samples Trained", model_meta.get("training_samples", "N/A"))
        with col3:
            st.metric("Unique Profiles", model_meta.get("unique_processes", "N/A"))
        with col4:
            st.metric("Data Source", model_meta.get("data_source", "synthetic").upper())

        st.markdown("### Approved Feature Columns (13 Features)")
        feat_cols = model_meta.get("approved_features", list(APPROVED_FEATURE_COLUMNS))
        st.write(", ".join([f"`{f}`" for f in feat_cols]))

        st.markdown("### Model Hyperparameters")
        st.json(model_meta.get("hyperparameters", {}))
    else:
        st.warning("Model metadata (models/metadata.json) not found. Run `python models/train.py --db-path /tmp/echo_train.db` to generate artifacts.")

    if not features_df.empty:
        st.subheader("Processed 5-Second Feature Windows")
        st.dataframe(features_df.head(20), use_container_width=True)

# ---------------------------------------------------------------------------
# PAGE 4: CORRELATION & RISK SCORING
# ---------------------------------------------------------------------------
elif page == "4. Correlation & Risk Scoring":
    st.header("🔗 Multi-Signal Risk Correlation Engine")
    st.caption("Evaluates: Composite Risk R = w_m * M + w_a * A + w_r * Q")

    st.markdown("""
    - **ML Anomaly Score (M):** Isolation Forest unsupervised anomaly probability.
    - **Behavioural Score (A):** Median Absolute Deviation (MAD) modified Z-score against learned baseline.
    - **Context Rule Score (Q):** Contextual execution path, parent hierarchy, and socket bursts.
    """)

    if not correlation_df.empty:
        st.subheader("Audited Correlation Records")
        st.dataframe(
            correlation_df[[
                "event_id", "timestamp", "process_name", "pid",
                "overall_risk_score", "risk_level",
                "ml_score", "behavioural_score", "resource_score",
                "recommended_action", "explanation"
            ]],
            use_container_width=True,
        )

        st.subheader("Signal Weight Contribution Breakdown")
        st.bar_chart(correlation_df.head(10).set_index("process_name")[["ml_score", "behavioural_score", "resource_score"]])
    else:
        st.info("No correlation records found in database. Run `python run_echo.py` or `python scripts/run_m3_demo.py`.")

# ---------------------------------------------------------------------------
# PAGE 5: SECURITY ALERTS
# ---------------------------------------------------------------------------
elif page == "5. Security Alerts":
    st.header("🚨 Security Alerts Management")
    st.caption("Actionable security alerts generated by graduated policy rules.")

    if not alerts_df.empty:
        col1, col2 = st.columns([1, 1])
        with col1:
            st.metric("Total Alerts Raised", len(alerts_df))
        with col2:
            st.metric("Open Unresolved Alerts", (alerts_df["status"] == "open").sum())

        st.dataframe(alerts_df, use_container_width=True)

        st.subheader("Alert Severity Distribution")
        st.bar_chart(alerts_df["severity"].value_counts())
    else:
        st.success("Zero security alerts currently present in the system.")

# ---------------------------------------------------------------------------
# PAGE 6: RESPONSE MANAGEMENT
# ---------------------------------------------------------------------------
elif page == "6. Response Management":
    st.header("⚡ Safe Response Execution & Audit Log")
    st.caption("Defensive containment actions executed under safe simulation mode.")

    st.info("🔒 **Safety Invariant:** All defensive actions are executed in `simulation` mode with zero host harm.")

    if not responses_df.empty:
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Actions Recorded", len(responses_df))
        with col2:
            st.metric("Simulation Mode", (responses_df["execution_mode"] == "simulation").sum())
        with col3:
            st.metric("Operator Approved", (responses_df["approval_status"] == "approved").sum())

        st.dataframe(responses_df, use_container_width=True)

        st.subheader("Actions Breakdown by Type")
        st.bar_chart(responses_df["action_type"].value_counts())
    else:
        st.info("No response actions recorded yet.")

# ---------------------------------------------------------------------------
# PAGE 7: CLOSED-LOOP VERIFICATION
# ---------------------------------------------------------------------------
elif page == "7. Closed-Loop Verification":
    st.header("✅ Closed-Loop Verification Subsystem")
    st.caption("Asserts post-containment success and verifies zero collateral impact.")

    if not verifications_df.empty:
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Verifications", len(verifications_df))
        with col2:
            verified_success = (verifications_df["success"] == 1).sum()
            st.metric("Verified Successful", verified_success)
        with col3:
            no_collateral = (verifications_df["collateral_impact"] == "none").sum()
            st.metric("Zero Collateral Impact", no_collateral)

        st.dataframe(verifications_df, use_container_width=True)

        st.subheader("Collateral Impact Breakdown")
        st.bar_chart(verifications_df["collateral_impact"].value_counts())
    else:
        st.info("No verification results recorded yet.")

# ---------------------------------------------------------------------------
# PAGE 8: PROMETHEUS & MONITORING
# ---------------------------------------------------------------------------
elif page == "8. Prometheus & Monitoring":
    st.header("📈 Prometheus Metrics & Observability")
    st.caption("OpenMetrics exposition and Grafana dashboard integration.")

    st.markdown("""
    ECHO includes an integrated zero-dependency Prometheus exporter running on port `9108` (`/metrics`).
    
    ### Exposed OpenMetrics
    - `echo_process_events_total{risk_level="..."}` (Counter)
    - `echo_active_alerts{severity="..."}` (Gauge)
    - `echo_response_actions_total{action_type="...",result="...",execution_mode="..."}` (Counter)
    - `echo_verification_results_total{success="...",collateral_impact="..."}` (Counter)
    - `echo_verification_success_rate` (Gauge 0.0 - 1.0)
    """)

    st.code("""
    # Start Prometheus Exporter CLI
    python dashboard/prometheus/exporter.py
    
    # Scrape with Prometheus CLI
    prometheus --config.file=dashboard/prometheus/prometheus.yml
    """, language="bash")

