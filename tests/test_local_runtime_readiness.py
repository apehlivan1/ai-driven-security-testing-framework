import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.local_model_bakeoff import CALIBRATION_SCENARIOS
from adstf.local_runtime import MODEL_ARTIFACTS
from adstf.local_runtime_readiness import (
    FROZEN_EXECUTION_SETTINGS,
    MAX_CANDIDATES,
    READINESS_SCENARIO_ID,
    frozen_execution_settings,
    readiness_candidates,
    readiness_json_schema,
    readiness_observations,
    run_readiness_package,
    validate_readiness_package,
)
from adstf.xss_v13_benchmark import SCENARIOS as FINAL_XSS_V13_SCENARIOS


class LocalRuntimeReadinessTests(unittest.TestCase):
    def test_readiness_input_is_synthetic_and_separate_from_calibration_and_final_xss(self) -> None:
        calibration_ids = {scenario.scenario_id for scenario in CALIBRATION_SCENARIOS}
        final_ids = {scenario.scenario_id for scenario in FINAL_XSS_V13_SCENARIOS}

        self.assertNotIn(READINESS_SCENARIO_ID, calibration_ids)
        self.assertNotIn(READINESS_SCENARIO_ID, final_ids)
        self.assertEqual(len(readiness_candidates()), MAX_CANDIDATES)
        for candidate in readiness_candidates():
            self.assertIn("/local-readiness/", candidate.action_url)
            self.assertNotIn("/calibration/", candidate.action_url)
            self.assertNotIn("/suite-v13/", candidate.action_url)

    def test_json_schema_constrains_max_shape_response(self) -> None:
        candidate_ids = [candidate.candidate_id for candidate in readiness_candidates()]
        schema = readiness_json_schema(candidate_ids)

        ranking = schema["properties"]["ranking"]
        self.assertEqual(ranking["minItems"], MAX_CANDIDATES)
        self.assertEqual(ranking["maxItems"], MAX_CANDIDATES)
        item_schema = ranking["items"]["properties"]
        self.assertEqual(item_schema["candidate_id"]["enum"], candidate_ids)
        self.assertEqual(item_schema["rationale"]["maxLength"], FROZEN_EXECUTION_SETTINGS["maximum_rationale_chars"])

    def test_common_settings_use_one_output_limit_and_schema_mechanism(self) -> None:
        settings = frozen_execution_settings(Path("readiness.schema.json"))

        self.assertEqual(settings["max_output_tokens"], 768)
        self.assertEqual(settings["context_size_tokens"], 4096)
        self.assertEqual(settings["temperature"], 0.0)
        self.assertEqual(settings["top_p"], 1.0)
        self.assertIn("--json-schema-file", settings["runtime_arguments"])
        self.assertEqual(settings["json_schema_path"], "readiness.schema.json")

    def test_readiness_observations_mark_valid_complete_contract(self) -> None:
        result = _fake_result(
            ordered_candidate_ids=[candidate.candidate_id for candidate in readiness_candidates()],
            validation_errors=[],
            is_valid=True,
            provider_failed=False,
            stderr_tail="llama_perf_context_print:        eval time = 100.00 ms /    42 runs",
        )

        observations = readiness_observations(result, memory_before=1000, memory_after=900)

        self.assertTrue(observations["contract_completed"])
        self.assertTrue(observations["output_not_truncated"])
        self.assertTrue(observations["json_parsed"])
        self.assertEqual(observations["generated_token_count_observed"], 42)

    def test_readiness_observations_do_not_repair_malformed_or_truncated_output(self) -> None:
        result = _fake_result(
            ordered_candidate_ids=[candidate.candidate_id for candidate in readiness_candidates()],
            validation_errors=["malformed JSON response: EOF while parsing"],
            is_valid=False,
            provider_failed=False,
            stderr_tail="llama_perf_context_print:        eval time = 100.00 ms /   767 runs",
        )

        observations = readiness_observations(result, memory_before=1000, memory_after=900)

        self.assertFalse(observations["contract_completed"])
        self.assertFalse(observations["output_not_truncated"])
        self.assertFalse(observations["json_parsed"])
        self.assertTrue(observations["possible_truncation"])

    def test_validate_readiness_package_blocks_bakeoff_when_any_model_not_ready(self) -> None:
        rows = [
            {
                "model_candidate_id": model.candidate_id,
                "contract_completed": model.candidate_id != MODEL_ARTIFACTS[0].candidate_id,
            }
            for model in MODEL_ARTIFACTS
        ]
        with tempfile.TemporaryDirectory() as tmp:
            schema_path = Path(tmp) / "schema.json"
            schema_path.write_text("{}", encoding="utf-8")
            validation = validate_readiness_package(rows, schema_path, frozen_execution_settings(schema_path))

        self.assertTrue(validation["valid"], validation["errors"])
        self.assertFalse(validation["measured_bakeoff_ready"])
        self.assertTrue(validation["global_configuration_revision_required"])

    def test_package_generation_with_fake_runner_preserves_contract_and_writes_artifacts(self) -> None:
        candidate_ids = [candidate.candidate_id for candidate in readiness_candidates()]

        def fake_runner(command, **kwargs):
            self.assertIn("--json-schema-file", command)
            self.assertEqual(kwargs["timeout"], FROZEN_EXECUTION_SETTINGS["timeout_seconds"])
            response = {
                "ranking": [
                    {"candidate_id": candidate_id, "rationale": "Synthetic readiness rationale."}
                    for candidate_id in candidate_ids
                ]
            }
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps(response),
                stderr="llama_perf_context_print:        eval time = 100.00 ms /    50 runs",
            )

        with tempfile.TemporaryDirectory() as tmp:
            from adstf.local_runtime_readiness import LlamaCppCliClient

            original_init = LlamaCppCliClient.__init__

            def patched_init(self, *args, **kwargs):
                kwargs["runner"] = fake_runner
                original_init(self, *args, **kwargs)

            LlamaCppCliClient.__init__ = patched_init
            try:
                package = run_readiness_package(
                    executable=Path("llama-completion.exe"),
                    model_root=Path(tmp) / "models",
                    output_root=Path(tmp) / "readiness",
                )
            finally:
                LlamaCppCliClient.__init__ = original_init

            output = Path(tmp) / "readiness"
            self.assertTrue(package["validation"]["measured_bakeoff_ready"])
            self.assertTrue((output / "manifest.json").exists())
            self.assertTrue((output / "execution-settings.json").exists())
            self.assertTrue((output / "local-ranking-readiness-schema-v1.3.json").exists())
            self.assertTrue((output / "normalized" / "readiness-results.csv").exists())
            self.assertTrue((output / "checksums.sha256").exists())


class _fake_result:
    def __init__(
        self,
        *,
        ordered_candidate_ids,
        validation_errors,
        is_valid,
        provider_failed,
        stderr_tail,
    ):
        self.ordered_candidate_ids = ordered_candidate_ids
        self.validation_errors = validation_errors
        self.provider_failed = provider_failed
        self.provider_metadata = {"stderr_tail": stderr_tail}
        self._is_valid = is_valid

    @property
    def is_valid(self):
        return self._is_valid


if __name__ == "__main__":
    unittest.main()
