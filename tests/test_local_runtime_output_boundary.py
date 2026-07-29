import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.local_runtime import LLAMA_COMPLETION_EOS_MARKER, MODEL_ARTIFACTS
from adstf.local_runtime_output_boundary import (
    OUTPUT_BOUNDARY_VERSION,
    run_output_boundary_package,
    runtime_interface_rows,
    validate_output_boundary_package,
)
from adstf.local_runtime_readiness import (
    FROZEN_EXECUTION_SETTINGS,
    frozen_execution_settings,
    readiness_candidates,
)


class LocalRuntimeOutputBoundaryTests(unittest.TestCase):
    def test_output_boundary_package_with_fake_runtime_writes_raw_and_normalized_artifacts(self) -> None:
        candidate_ids = [candidate.candidate_id for candidate in readiness_candidates()]

        def fake_runner(command, **kwargs):
            self.assertIn("--json-schema-file", command)
            self.assertIn("--single-turn", command)
            self.assertEqual(kwargs["timeout"], FROZEN_EXECUTION_SETTINGS["timeout_seconds"])
            raw_json = json.dumps(
                {
                    "ranking": [
                        {"candidate_id": candidate_id, "rationale": "Synthetic output-boundary rationale."}
                        for candidate_id in candidate_ids
                    ]
                }
            )
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=raw_json + LLAMA_COMPLETION_EOS_MARKER,
                stderr="llama_perf_context_print:        eval time = 100.00 ms /    50 runs",
            )

        with tempfile.TemporaryDirectory() as tmp:
            from adstf.local_runtime_output_boundary import LlamaCppCliClient

            original_init = LlamaCppCliClient.__init__

            def patched_init(self, *args, **kwargs):
                kwargs["runner"] = fake_runner
                original_init(self, *args, **kwargs)

            LlamaCppCliClient.__init__ = patched_init
            try:
                package = run_output_boundary_package(
                    executable=Path("llama-completion.exe"),
                    model_root=Path(tmp) / "models",
                    output_root=Path(tmp) / OUTPUT_BOUNDARY_VERSION,
                )
            finally:
                LlamaCppCliClient.__init__ = original_init

            output = Path(tmp) / OUTPUT_BOUNDARY_VERSION
            self.assertTrue(package["validation"]["measured_bakeoff_ready"], package["validation"]["errors"])
            self.assertTrue((output / "manifest.json").exists())
            self.assertTrue((output / "transport-settings.json").exists())
            self.assertTrue((output / "raw" / f"{MODEL_ARTIFACTS[0].candidate_id}.json").exists())
            self.assertTrue((output / "exact-commands" / f"{MODEL_ARTIFACTS[0].candidate_id}.json").exists())
            self.assertTrue((output / "normalized" / "readiness-results.csv").exists())
            self.assertTrue((output / "output-boundary-audit.md").exists())
            raw_artifact = json.loads((output / "raw" / f"{MODEL_ARTIFACTS[0].candidate_id}.json").read_text())
            self.assertIn(LLAMA_COMPLETION_EOS_MARKER, raw_artifact["raw_stdout"])
            self.assertNotIn(LLAMA_COMPLETION_EOS_MARKER, raw_artifact["normalized_model_content"])

    def test_runtime_interface_selection_is_common_not_per_model(self) -> None:
        rows = runtime_interface_rows({"transport_settings": {}})

        selected = [row for row in rows if row["selected"]]
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]["interface"], "llama-completion")

    def test_validation_requires_one_row_per_model_and_non_scored_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            schema = Path(tmp) / "schema.json"
            schema.write_text("{}", encoding="utf-8")
            rows = [
                {
                    "model_candidate_id": model.candidate_id,
                    "readiness_status": "ready",
                    "scored": False,
                }
                for model in MODEL_ARTIFACTS
            ]
            validation = validate_output_boundary_package(rows, frozen_execution_settings(schema), schema)

        self.assertTrue(validation["valid"], validation["errors"])
        self.assertTrue(validation["measured_bakeoff_ready"])


if __name__ == "__main__":
    unittest.main()
