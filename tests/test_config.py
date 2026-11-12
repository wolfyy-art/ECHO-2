"""
tests/test_config.py
====================
Unit tests for ECHO CollectorConfig.
Validates defaults, positive intervals, non-negative duration, batch sizing,
environment variable overrides, and clear error reporting for invalid configs.
"""

import os
import unittest
from pathlib import Path
from unittest.mock import patch

from collector.config import CollectorConfig


class TestCollectorConfig(unittest.TestCase):
    """Test suite for configuration validation and environment loading."""

    def test_default_values(self):
        """Verify standard default configuration parameters."""
        config = CollectorConfig()
        self.assertEqual(config.sampling_interval, 5.0)
        self.assertEqual(config.default_duration, 0.0)
        self.assertTrue(config.collect_network)
        self.assertEqual(config.batch_size, 500)
        self.assertTrue(str(config.db_path).replace("\\", "/").endswith("data/echo.db"))

    def test_explicit_valid_values(self):
        """Verify custom values supplied directly to constructor."""
        custom_db = Path("/tmp/custom.db")
        config = CollectorConfig(
            sampling_interval=2.5,
            default_duration=30.0,
            collect_network=False,
            batch_size=100,
            db_path=custom_db,
        )
        self.assertEqual(config.sampling_interval, 2.5)
        self.assertEqual(config.default_duration, 30.0)
        self.assertFalse(config.collect_network)
        self.assertEqual(config.batch_size, 100)
        self.assertEqual(config.db_path, custom_db)

    def test_sampling_interval_must_be_positive(self):
        """Interval <= 0 must raise ValueError."""
        with self.assertRaises(ValueError) as ctx:
            CollectorConfig(sampling_interval=0.0)
        self.assertIn("sampling interval must be strictly positive", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            CollectorConfig(sampling_interval=-5.0)
        self.assertIn("sampling interval must be strictly positive", str(ctx.exception))

    def test_duration_must_be_non_negative(self):
        """Duration < 0 must raise ValueError; duration 0.0 must be allowed."""
        config = CollectorConfig(default_duration=0.0)
        self.assertEqual(config.default_duration, 0.0)

        with self.assertRaises(ValueError) as ctx:
            CollectorConfig(default_duration=-1.0)
        self.assertIn("duration must be non-negative", str(ctx.exception))

    def test_batch_size_must_be_positive(self):
        """Batch size <= 0 must raise ValueError."""
        with self.assertRaises(ValueError) as ctx:
            CollectorConfig(batch_size=0)
        self.assertIn("batch size must be strictly positive", str(ctx.exception))

    @patch.dict(
        os.environ,
        {
            "ECHO_SAMPLING_INTERVAL": "10.0",
            "ECHO_COLLECTION_DURATION": "60.0",
            "ECHO_COLLECT_NETWORK": "false",
            "ECHO_BATCH_SIZE": "250",
            "ECHO_DB_PATH": "/tmp/env_echo.db",
        },
    )
    def test_valid_environment_variables(self):
        """Verify environment variables are parsed correctly."""
        config = CollectorConfig()
        self.assertEqual(config.sampling_interval, 10.0)
        self.assertEqual(config.default_duration, 60.0)
        self.assertFalse(config.collect_network)
        self.assertEqual(config.batch_size, 250)
        self.assertEqual(config.db_path, Path("/tmp/env_echo.db"))

    @patch.dict(os.environ, {"ECHO_SAMPLING_INTERVAL": "not-a-number"})
    def test_invalid_float_environment_variable(self):
        """Non-numeric float environment variables must raise clear ValueError."""
        with self.assertRaises(ValueError) as ctx:
            CollectorConfig()
        self.assertIn("Invalid configuration for ECHO_SAMPLING_INTERVAL", str(ctx.exception))
        self.assertIn("not-a-number", str(ctx.exception))

    @patch.dict(os.environ, {"ECHO_BATCH_SIZE": "invalid-int"})
    def test_invalid_int_environment_variable(self):
        """Non-numeric int environment variables must raise clear ValueError."""
        with self.assertRaises(ValueError) as ctx:
            CollectorConfig()
        self.assertIn("Invalid configuration for ECHO_BATCH_SIZE", str(ctx.exception))

    @patch.dict(os.environ, {"ECHO_COLLECT_NETWORK": "maybe"})
    def test_invalid_bool_environment_variable(self):
        """Invalid boolean environment variables must raise clear ValueError."""
        with self.assertRaises(ValueError) as ctx:
            CollectorConfig()
        self.assertIn("Invalid configuration for ECHO_COLLECT_NETWORK", str(ctx.exception))
        self.assertIn("maybe", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
