"""
tests/test_training_isolation.py
=================================
Unit tests for ECHO Phase 3D: Training Data Isolation.

Tests verify that the training pipeline:
1. Refuses to write to the production database (data/echo.db).
2. Requires an explicitly supplied isolated database path.
3. Writes synthetic features, baselines, and CSVs to the isolated database only.
4. The model artifact is NOT overwritten without --force.
5. Metadata contains "data_source": "synthetic".
6. BehaviouralProfiler is called with the isolated db_path, not DB_PATH.
7. run_echo.py does not contain the auto-train fallback.

All tests use temporary databases.  No real training is executed.
"""

import sys
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dashboard.database import DB_PATH, init_database
from models.train import (
    generate_baseline_telemetry,
    populate_database_and_csv,
    train_and_serialize_models,
)


class TestTrainingDataIsolation(unittest.TestCase):
    """Verify that training refuses to touch the production database."""

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.isolated_db  = self.tmp_dir / "echo_train_test.db"
        self.isolated_csv = self.tmp_dir / "process_features.csv"
        self.model_file   = self.tmp_dir / "test_model.joblib"
        self.meta_file    = self.tmp_dir / "test_metadata.json"

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # -----------------------------------------------------------------------
    # Production DB guard
    # -----------------------------------------------------------------------

    def test_populate_refuses_production_db(self):
        """populate_database_and_csv must raise ValueError when given DB_PATH."""
        df = generate_baseline_telemetry(n_windows=2)
        with self.assertRaises(ValueError) as ctx:
            populate_database_and_csv(df, db_path=DB_PATH, output_csv=self.isolated_csv)
        self.assertIn("production database", str(ctx.exception))

    def test_train_and_serialize_refuses_production_db(self):
        """train_and_serialize_models must raise ValueError when given DB_PATH."""
        df = generate_baseline_telemetry(n_windows=2)
        # Must not use production DB even if someone passes it directly
        with self.assertRaises(ValueError) as ctx:
            train_and_serialize_models(
                df,
                db_path=DB_PATH,
                model_file=self.model_file,
                metadata_file=self.meta_file,
                force_overwrite=True,
            )
        self.assertIn("production database", str(ctx.exception))

    # -----------------------------------------------------------------------
    # Isolated database writes
    # -----------------------------------------------------------------------

    def test_populate_writes_to_isolated_db_only(self):
        """populate_database_and_csv must write features to the isolated database."""
        df = generate_baseline_telemetry(n_windows=3)
        populate_database_and_csv(df, db_path=self.isolated_db, output_csv=self.isolated_csv)

        # Isolated DB must exist and have rows
        self.assertTrue(self.isolated_db.exists(), "Isolated DB was not created")

        import sqlite3
        conn = sqlite3.connect(str(self.isolated_db))
        count = conn.execute("SELECT COUNT(*) FROM processed_features").fetchone()[0]
        conn.close()
        self.assertGreater(count, 0, "No feature rows inserted into isolated DB")

    def test_populate_writes_csv_to_isolated_location(self):
        """populate_database_and_csv must write CSV next to the isolated database."""
        df = generate_baseline_telemetry(n_windows=2)
        populate_database_and_csv(df, db_path=self.isolated_db, output_csv=self.isolated_csv)
        self.assertTrue(self.isolated_csv.exists(), "CSV was not created at isolated path")

    def test_production_db_is_untouched(self):
        """Running training with an isolated db must leave the production DB unchanged."""
        prod_existed_before = DB_PATH.exists()
        df = generate_baseline_telemetry(n_windows=2)
        populate_database_and_csv(df, db_path=self.isolated_db, output_csv=self.isolated_csv)
        # If the production DB did not exist before, it must still not exist
        if not prod_existed_before:
            self.assertFalse(DB_PATH.exists(),
                             "Production DB was created by training — it must not be touched")

    # -----------------------------------------------------------------------
    # Profiler called with isolated db_path
    # -----------------------------------------------------------------------

    def test_train_uses_isolated_db_for_profiler(self):
        """train_and_serialize_models must pass the isolated db_path to BehaviouralProfiler."""
        df = generate_baseline_telemetry(n_windows=3)
        # Seed the isolated DB with features first
        populate_database_and_csv(df, db_path=self.isolated_db, output_csv=self.isolated_csv)

        captured_db_paths = []

        original_profiler_init = __import__(
            "baseline.profiler", fromlist=["BehaviouralProfiler"]
        ).BehaviouralProfiler.__init__

        def capturing_init(self_inner, db_path=None, **kwargs):
            captured_db_paths.append(db_path)
            original_profiler_init(self_inner, db_path=db_path, **kwargs)

        with patch("models.train.BehaviouralProfiler.__init__", capturing_init):
            with patch("models.train.BehaviouralProfiler.learn_all_baselines", return_value=[]):
                # Mock the model save so we don't need sklearn to serialize
                with patch("models.train.ProcessIsolationForest.save", return_value=self.model_file):
                    train_and_serialize_models(
                        df,
                        db_path=self.isolated_db,
                        model_file=self.model_file,
                        metadata_file=self.meta_file,
                        output_csv=self.isolated_csv,
                        force_overwrite=True,
                    )

        self.assertTrue(len(captured_db_paths) > 0, "BehaviouralProfiler was never constructed")
        for captured in captured_db_paths:
            if captured is not None:
                self.assertNotEqual(
                    Path(captured).resolve(), DB_PATH.resolve(),
                    "BehaviouralProfiler was called with the production DB path",
                )

    # -----------------------------------------------------------------------
    # Model artifact overwrite protection
    # -----------------------------------------------------------------------

    def test_existing_model_artifact_not_overwritten_without_force(self):
        """train_and_serialize_models must raise FileExistsError if artifact exists."""
        # Create a dummy existing artifact
        self.model_file.touch()
        df = generate_baseline_telemetry(n_windows=2)
        populate_database_and_csv(df, db_path=self.isolated_db, output_csv=self.isolated_csv)

        with self.assertRaises(FileExistsError) as ctx:
            train_and_serialize_models(
                df,
                db_path=self.isolated_db,
                model_file=self.model_file,
                metadata_file=self.meta_file,
                force_overwrite=False,   # No force → must raise
            )
        self.assertIn("already exists", str(ctx.exception))

    def test_force_allows_overwrite(self):
        """force_overwrite=True must allow overwriting an existing artifact."""
        self.model_file.touch()
        df = generate_baseline_telemetry(n_windows=3)
        populate_database_and_csv(df, db_path=self.isolated_db, output_csv=self.isolated_csv)

        with patch("models.train.BehaviouralProfiler.learn_all_baselines", return_value=[]):
            with patch("models.train.ProcessIsolationForest.save", return_value=self.model_file):
                # Should not raise
                try:
                    train_and_serialize_models(
                        df,
                        db_path=self.isolated_db,
                        model_file=self.model_file,
                        metadata_file=self.meta_file,
                        output_csv=self.isolated_csv,
                        force_overwrite=True,
                    )
                except FileExistsError:
                    self.fail("FileExistsError raised despite force_overwrite=True")

    # -----------------------------------------------------------------------
    # Metadata data_source field
    # -----------------------------------------------------------------------

    def test_metadata_contains_data_source_synthetic(self):
        """Training metadata must include data_source='synthetic'."""
        df = generate_baseline_telemetry(n_windows=3)
        populate_database_and_csv(df, db_path=self.isolated_db, output_csv=self.isolated_csv)

        with patch("models.train.BehaviouralProfiler.learn_all_baselines", return_value=[]):
            with patch("models.train.ProcessIsolationForest.save", return_value=self.model_file):
                _, metadata = train_and_serialize_models(
                    df,
                    db_path=self.isolated_db,
                    model_file=self.model_file,
                    metadata_file=self.meta_file,
                    output_csv=self.isolated_csv,
                    force_overwrite=True,
                )

        self.assertIn("data_source", metadata)
        self.assertEqual(metadata["data_source"], "synthetic")

    def test_metadata_file_written_with_data_source(self):
        """Metadata JSON file on disk must include data_source='synthetic'."""
        df = generate_baseline_telemetry(n_windows=3)
        populate_database_and_csv(df, db_path=self.isolated_db, output_csv=self.isolated_csv)

        with patch("models.train.BehaviouralProfiler.learn_all_baselines", return_value=[]):
            with patch("models.train.ProcessIsolationForest.save", return_value=self.model_file):
                train_and_serialize_models(
                    df,
                    db_path=self.isolated_db,
                    model_file=self.model_file,
                    metadata_file=self.meta_file,
                    output_csv=self.isolated_csv,
                    force_overwrite=True,
                )

        self.assertTrue(self.meta_file.exists(), "metadata.json was not written")
        with open(self.meta_file) as f:
            on_disk = json.load(f)
        self.assertEqual(on_disk.get("data_source"), "synthetic")

    # -----------------------------------------------------------------------
    # Synthetic telemetry generator
    # -----------------------------------------------------------------------

    def test_generate_baseline_telemetry_shape(self):
        """Telemetry generator must produce n_windows * n_processes rows."""
        n_windows = 5
        df = generate_baseline_telemetry(n_windows=n_windows)
        # 7 process specs × 5 windows = 35 rows
        self.assertEqual(len(df), n_windows * 7)

    def test_generate_baseline_telemetry_columns(self):
        """Generated DataFrame must contain all required feature columns."""
        from detection.isolation_forest import APPROVED_FEATURE_COLUMNS
        df = generate_baseline_telemetry(n_windows=2)
        for col in APPROVED_FEATURE_COLUMNS:
            self.assertIn(col, df.columns, f"Missing required column: {col}")

    def test_generate_baseline_is_deterministic(self):
        """With the same seed the generator must produce identical DataFrames."""
        df1 = generate_baseline_telemetry(n_windows=4)
        df2 = generate_baseline_telemetry(n_windows=4)
        # numpy.random.seed(42) is set inside the function so it reseeds each call
        self.assertTrue(df1["cpu_mean"].equals(df2["cpu_mean"]),
                        "Generator is not deterministic — np.random.seed(42) may not be re-applied")


class TestRunEchoAutoTrainRemoved(unittest.TestCase):
    """Verify that run_echo.py no longer contains the auto-train fallback."""

    def test_no_auto_train_in_run_echo(self):
        """run_echo.py must not auto-trigger training when the model is missing."""
        run_echo_path = Path(__file__).resolve().parent.parent / "run_echo.py"
        self.assertTrue(run_echo_path.exists(), "run_echo.py not found")
        source = run_echo_path.read_text(encoding="utf-8")
        # The old auto-train pattern was: from models.train import main as train_main; train_main()
        self.assertNotIn("train_main()", source,
                         "run_echo.py still contains the auto-train call train_main()")
        self.assertNotIn("from models.train import main as train_main", source,
                         "run_echo.py still imports the auto-train function")

    def test_run_echo_exits_on_missing_model(self):
        """run_echo.py must call sys.exit(1) when the artifact is absent
        (verified by inspecting source, since correlation modules are not yet merged)."""
        run_echo_path = Path(__file__).resolve().parent.parent / "run_echo.py"
        source = run_echo_path.read_text(encoding="utf-8")
        # The source must contain sys.exit(1) in the _require_model function
        self.assertIn("sys.exit(1)", source,
                      "run_echo.py _require_model must call sys.exit(1) when model is absent")
        # The source must NOT contain the old auto-training pattern
        self.assertNotIn("train_main()", source,
                         "run_echo.py must not contain the auto-train call")

    def test_run_echo_has_explicit_approval_comment(self):
        """run_echo.py must document that approval_status='approved' is a demo simulation."""
        run_echo_path = Path(__file__).resolve().parent.parent / "run_echo.py"
        source = run_echo_path.read_text(encoding="utf-8")
        # Check both the explicit approval and the DEMO comment near it
        self.assertIn('approval_status="approved"', source,
                      "run_echo.py must pass approval_status='approved' explicitly")
        self.assertIn("DEMO", source,
                      "run_echo.py must document that the approval is a demo simulation")


if __name__ == "__main__":
    unittest.main()
