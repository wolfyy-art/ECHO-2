"""
collector/config.py
===================
ECHO — Telemetry Collection Configuration.

Provides validated defaults and environment variable overrides for process
and network telemetry collection.

Environment Variables
---------------------
ECHO_SAMPLING_INTERVAL : float
    Frequency of collection cycles in seconds (must be > 0, default: 5.0).
ECHO_COLLECTION_DURATION : float
    Total duration in seconds to collect telemetry (must be >= 0, default: 0.0).
    A duration of 0.0 indicates continuous collection until stopped.
ECHO_COLLECT_NETWORK : bool
    Whether to collect process network socket telemetry ('true'/'false', default: 'true').
ECHO_BATCH_SIZE : int
    Maximum number of telemetry records per SQLite batch insert (must be > 0, default: 500).
ECHO_DB_PATH : str
    Custom filesystem path to the SQLite database file (default: data/echo.db).
"""

import os
from dataclasses import dataclass
from pathlib import Path


def _parse_env_float(name: str, default: float) -> float:
    """Parse float from environment variable with clear error message."""
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw.strip())
    except ValueError as exc:
        raise ValueError(
            f"Invalid configuration for {name}: '{raw}' is not a valid floating-point number."
        ) from exc


def _parse_env_int(name: str, default: int) -> int:
    """Parse integer from environment variable with clear error message."""
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw.strip())
    except ValueError as exc:
        raise ValueError(
            f"Invalid configuration for {name}: '{raw}' is not a valid integer."
        ) from exc


def _parse_env_bool(name: str, default: bool) -> bool:
    """Parse boolean from environment variable with clear error message."""
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    normalized = raw.strip().lower()
    if normalized in ("true", "1", "yes", "on"):
        return True
    if normalized in ("false", "0", "no", "off"):
        return False
    raise ValueError(
        f"Invalid configuration for {name}: '{raw}' is not a valid boolean. "
        f"Expected true/false, 1/0, yes/no, on/off."
    )


@dataclass(frozen=True)
class CollectorConfig:
    """
    Configuration parameters for process and network collectors.

    Parameters
    ----------
    sampling_interval : float
        Sampling frequency in seconds (must be > 0.0).
    default_duration : float
        Run duration in seconds (must be >= 0.0; 0.0 = run until interrupted).
    collect_network : bool
        Whether to collect network socket telemetry for processes.
    batch_size : int
        SQLite batch insert limit (must be > 0).
    db_path : Path
        Filesystem path to the SQLite database.
    """
    sampling_interval: float = None
    default_duration: float = None
    collect_network: bool = None
    batch_size: int = None
    db_path: Path = None

    def __init__(
        self,
        sampling_interval: float = None,
        default_duration: float = None,
        collect_network: bool = None,
        batch_size: int = None,
        db_path: Path = None,
    ):
        # Resolve from parameter or environment variable
        interval = (
            sampling_interval
            if sampling_interval is not None
            else _parse_env_float("ECHO_SAMPLING_INTERVAL", 5.0)
        )
        duration = (
            default_duration
            if default_duration is not None
            else _parse_env_float("ECHO_COLLECTION_DURATION", 0.0)
        )
        net_flag = (
            collect_network
            if collect_network is not None
            else _parse_env_bool("ECHO_COLLECT_NETWORK", True)
        )
        batch = (
            batch_size
            if batch_size is not None
            else _parse_env_int("ECHO_BATCH_SIZE", 500)
        )

        if db_path is not None:
            resolved_db = Path(db_path)
        else:
            env_db = os.getenv("ECHO_DB_PATH")
            if env_db and env_db.strip():
                resolved_db = Path(env_db.strip())
            else:
                resolved_db = Path(__file__).resolve().parent.parent / "data" / "echo.db"

        # Validations
        if interval <= 0:
            raise ValueError(
                f"Invalid sampling_interval={interval}: sampling interval must be strictly positive (> 0)."
            )

        if duration < 0:
            raise ValueError(
                f"Invalid default_duration={duration}: duration must be non-negative (>= 0)."
            )

        if batch <= 0:
            raise ValueError(
                f"Invalid batch_size={batch}: batch size must be strictly positive (> 0)."
            )

        # Assign values to frozen dataclass using object.__setattr__
        object.__setattr__(self, "sampling_interval", float(interval))
        object.__setattr__(self, "default_duration", float(duration))
        object.__setattr__(self, "collect_network", bool(net_flag))
        object.__setattr__(self, "batch_size", int(batch))
        object.__setattr__(self, "db_path", resolved_db)
