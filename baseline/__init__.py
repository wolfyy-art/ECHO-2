"""
baseline/__init__.py
====================
ECHO — Behavioural Profiling and MAD Baseline Learning Package.
"""

from baseline.mad import compute_median_and_mad, compute_modified_z_score, MADScorer
from baseline.identity import build_process_type_identity, build_process_instance_identity
from baseline.historical_analyzer import HistoricalAnalyzer, HistoricalCoverageReport
from baseline.storage import BaselineStorage, init_baselines_table
from baseline.profiler import BehaviouralProfiler
from baseline.comparator import BaselineComparator
from baseline.updater import BaselineUpdater

__all__ = [
    "compute_median_and_mad",
    "compute_modified_z_score",
    "MADScorer",
    "build_process_type_identity",
    "build_process_instance_identity",
    "HistoricalAnalyzer",
    "HistoricalCoverageReport",
    "BaselineStorage",
    "init_baselines_table",
    "BehaviouralProfiler",
    "BaselineComparator",
    "BaselineUpdater",
]
