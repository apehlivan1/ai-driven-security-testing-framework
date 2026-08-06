import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.local_model_bakeoff import CALIBRATION_SCENARIOS, SHORTLISTED_MODELS
from adstf.local_model_live_bakeoff import (
    LIVE_BAKEOFF_VERSION,
    execution_policy,
    execution_schedule,
    run_live_bakeoff_package,
    validate_live_package_data,
)
from adstf.local_runtime import LLAMA_COMPLETION_EOS_MARKER
from adstf.local_runtime_readiness import FROZEN_EXECUTION_SETTINGS
from adstf.xss_v13_benchmark import SCENARIOS as FINAL_XSS_V13_SCENARIOS


class LocalModelLiveBakeoffTests(unittest.TestCase):
    def test_execution_schedule_is_deterministic_and_uses_only_calibration_scenarios(self) -> None:
        schedule = execution_schedule()
        final_ids = {scenario.scenario_id for scenario in FINAL_XSS_V13_SCENARIOS}

        self.assertEqual(len(schedule), 72)
        self.assertEqual(schedule[0]["schedule_index"], 1)
        self.assertEqual(schedule[-1]["schedule_index"], 72)
        self.assertEqual(schedule[0]["model_candidate_id"], SHORTLISTED_MODELS[0].candidate_id)
        self.assertEqual(schedule[0]["scenario_id"], CALIBRATION_SCENARIOS[0].scenario_id)
        self.assertEqual(schedule[0]["trial_number"], 1)
        self.assertTrue({item["scenario_id"] for item in schedule}.isdisjoint(final_ids))
        for model in SHORTLISTED_MODELS:
            self.assertEqual(sum(1 for item in schedule if item["model_candidate_id"] == model.candidate_id), 18)

    def test_execution_policy_has_no_silent_retry(self) -> None:
        policy = execution_policy()

        self.assertIn("no silent retries", policy["retry_policy"])
        self.assertEqual(policy["retry_attempts_performed"], 0)
        self.assertFalse(policy["final_24_scenario_xss_v13_used"])
        self.assertFalse(policy["vulnerability_testing_performed"])

    def test_live_package_generation_with_fake_runtime_preserves_raw_and_normalized_outputs(self) -> None:
        def fake_runner(command, **kwargs):
            self.assertIn("--json-schema-file", command)
            self.assertEqual(kwargs["timeout"], FROZEN_EXECUTION_SETTINGS["timeout_seconds"])
            schema_path = Path(command[command.index("--json-schema-file") + 1])
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            candidate_ids = schema["properties"]["ranking"]["items"]["properties"]["candidate_id"]["enum"]
            raw_json = json.dumps(
                {
                    "ranking": [
                        {"candidate_id": candidate_id, "rationale": "Synthetic measured bake-off test response."}
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
            import adstf.local_model_live_bakeoff as live_bakeoff

            original_init = live_bakeoff.LlamaCppCliClient.__init__
            original_memory_snapshot = live_bakeoff.memory_snapshot

            def patched_init(self, *args, **kwargs):
                kwargs["runner"] = fake_runner
                original_init(self, *args, **kwargs)

            live_bakeoff.LlamaCppCliClient.__init__ = patched_init
            live_bakeoff.memory_snapshot = lambda: {
                "total_physical_bytes": 16000000000,
                "available_physical_bytes": 8000000000,
            }
            try:
                package = run_live_bakeoff_package(
                    executable=Path("llama-completion.exe"),
                    model_root=Path(tmp) / "models",
                    output_root=Path(tmp) / LIVE_BAKEOFF_VERSION,
                )
            finally:
                live_bakeoff.LlamaCppCliClient.__init__ = original_init
                live_bakeoff.memory_snapshot = original_memory_snapshot

            output = Path(tmp) / LIVE_BAKEOFF_VERSION
            self.assertTrue(package["validation_report"]["valid"], package["validation_report"]["errors"])
            self.assertEqual(len(package["trial_results"]), 72)
            self.assertEqual(package["selection_decision"]["final_selection_made"], True)
            self.assertTrue((output / "manifest.json").exists())
            self.assertTrue((output / "execution-schedule.csv").exists())
            self.assertTrue((output / "transport-settings.json").exists())
            self.assertTrue((output / "normalized" / "trial-results.csv").exists())
            self.assertTrue((output / "figures" / "model-ranking-metrics-source.csv").exists())
            raw_path = output / "raw" / SHORTLISTED_MODELS[0].candidate_id / CALIBRATION_SCENARIOS[0].scenario_id / "trial-1.json"
            raw = json.loads(raw_path.read_text(encoding="utf-8"))
            self.assertIn(LLAMA_COMPLETION_EOS_MARKER, raw["raw_stdout"])
            self.assertNotIn(LLAMA_COMPLETION_EOS_MARKER, raw["normalized_model_content"])

    def test_live_validation_rejects_wrong_denominator(self) -> None:
        validation = validate_live_package_data([], [], {"final_selection_made": False})

        self.assertFalse(validation["valid"])
        self.assertIn("expected exactly 72 scored calls", " ".join(validation["errors"]))


if __name__ == "__main__":
    unittest.main()
