import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.local_runtime import (
    LLAMA_COMPLETION_EOS_MARKER,
    LLAMA_CPP_RELEASE,
    MODEL_ARTIFACTS,
    PROVISIONING_VERSION,
    RUNTIME_SETTINGS,
    LlamaCppCliClient,
    llama_cli_command,
    model_metadata,
    parse_llama_completion_transport,
    smoke_candidates,
    validate_smoke_package,
    write_smoke_package,
)
from adstf.llm_ranking import rank_candidates_with_model
from adstf.metrics import NOT_AVAILABLE


class LocalRuntimeTests(unittest.TestCase):
    def test_llama_cli_command_is_pinned_and_reproducible(self) -> None:
        command = llama_cli_command(
            Path("llama-cli.exe"),
            Path("model.gguf"),
            Path("prompt.txt"),
            context_size_tokens=4096,
            max_output_tokens=32,
            temperature=0.0,
            top_p=1.0,
            seed=42,
            threads=8,
        )

        self.assertIn("llama-cli.exe", command[0])
        self.assertNotIn("-no-cnv", command)
        self.assertNotIn("--simple-io", command)
        self.assertIn("--no-display-prompt", command)
        self.assertIn("--single-turn", command)
        self.assertEqual(command[command.index("--temp") + 1], "0.0")
        self.assertEqual(command[command.index("-n") + 1], "32")
        self.assertEqual(command[command.index("--seed") + 1], "42")

    def test_llama_cli_command_can_apply_common_json_schema(self) -> None:
        command = llama_cli_command(
            Path("llama-cli.exe"),
            Path("model.gguf"),
            Path("prompt.txt"),
            context_size_tokens=4096,
            max_output_tokens=768,
            temperature=0.0,
            top_p=1.0,
            seed=42,
            threads=8,
            json_schema_path=Path("ranking.schema.json"),
        )

        self.assertEqual(command[command.index("--json-schema-file") + 1], "ranking.schema.json")

    def test_local_client_preserves_restricted_ranking_contract(self) -> None:
        def fake_runner(command, **kwargs):
            self.assertIn("-f", command)
            self.assertEqual(kwargs["timeout"], RUNTIME_SETTINGS["timeout_seconds"])
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps(
                    {
                        "ranking": [
                            {"candidate_id": "local-smoke-alpha-term", "rationale": "text form"},
                            {"candidate_id": "local-smoke-bravo-ref", "rationale": "query parameter"},
                            {"candidate_id": "local-smoke-cedar-note", "rationale": "required field"},
                        ]
                    }
                ),
                stderr="",
            )

        client = LlamaCppCliClient(
            executable=Path("llama-cli.exe"),
            model_path=Path("model.gguf"),
            model_identifier="fake-local",
            runner=fake_runner,
        )

        result = rank_candidates_with_model(
            candidates=smoke_candidates(),
            scenario_id="local-runtime-smoke-non-scored",
            trial_number=1,
            model_client=client,
            settings=RUNTIME_SETTINGS,
        )

        self.assertTrue(result.is_valid)
        self.assertEqual(result.provider, "local-llama.cpp")
        self.assertEqual(result.cost["availability"], NOT_AVAILABLE)
        self.assertEqual(result.usage["total_tokens"], NOT_AVAILABLE)
        self.assertEqual(result.ordered_candidate_ids[0], "local-smoke-alpha-term")
        self.assertIn("transport", result.provider_metadata)
        self.assertEqual(result.provider_metadata["returncode"], 0)

    def test_transport_parser_separates_known_runtime_marker_after_valid_json(self) -> None:
        raw_json = json.dumps(
            {
                "ranking": [
                    {"candidate_id": "local-smoke-alpha-term", "rationale": "text form"},
                ]
            }
        )
        transport = parse_llama_completion_transport(
            stdout=raw_json + LLAMA_COMPLETION_EOS_MARKER,
            stderr="llama_perf_context_print:        eval time = 100.00 ms /    42 runs",
            max_output_tokens=768,
        )

        self.assertEqual(transport.normalized_content, raw_json)
        self.assertTrue(transport.marker_separated)
        self.assertEqual(transport.runtime_marker, "[end of text]")
        self.assertEqual(transport.stop_reason, "eos_runtime_marker")
        self.assertFalse(transport.token_limit_reached)

    def test_transport_parser_keeps_genuine_extra_model_text_invalid(self) -> None:
        raw = '{"ranking": []} unexpected generated text'
        transport = parse_llama_completion_transport(stdout=raw, stderr="", max_output_tokens=768)

        self.assertEqual(transport.normalized_content, raw)
        self.assertFalse(transport.marker_separated)

    def test_transport_parser_does_not_remove_marker_like_text_inside_json(self) -> None:
        raw = json.dumps(
            {
                "ranking": [
                    {
                        "candidate_id": "local-smoke-alpha-term",
                        "rationale": "The literal [end of text] is part of this rationale.",
                    }
                ]
            }
        )
        transport = parse_llama_completion_transport(stdout=raw, stderr="", max_output_tokens=768)

        self.assertEqual(transport.normalized_content, raw)
        self.assertFalse(transport.marker_separated)

    def test_transport_parser_records_token_limit_truncation(self) -> None:
        transport = parse_llama_completion_transport(
            stdout="{",
            stderr="llama_perf_context_print:        eval time = 100.00 ms /   767 runs",
            max_output_tokens=768,
        )

        self.assertEqual(transport.generated_token_count, 767)
        self.assertTrue(transport.token_limit_reached)

    def test_nonzero_local_runtime_exit_is_provider_failure(self) -> None:
        def fake_runner(command, **kwargs):
            return subprocess.CompletedProcess(command, 2, stdout="raw stdout", stderr="runtime error")

        result = rank_candidates_with_model(
            candidates=smoke_candidates(),
            scenario_id="local-runtime-smoke-non-scored",
            trial_number=1,
            model_client=LlamaCppCliClient(
                executable=Path("llama-cli.exe"),
                model_path=Path("model.gguf"),
                model_identifier="fake-local",
                runner=fake_runner,
            ),
            settings=RUNTIME_SETTINGS,
        )

        self.assertTrue(result.provider_failed)
        self.assertTrue(any("runtime error" in error for error in result.validation_errors))

    def test_malformed_local_output_is_recorded_not_repaired(self) -> None:
        def fake_runner(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, stdout="not-json", stderr="")

        result = rank_candidates_with_model(
            candidates=smoke_candidates(),
            scenario_id="local-runtime-smoke-non-scored",
            trial_number=1,
            model_client=LlamaCppCliClient(
                executable=Path("llama-cli.exe"),
                model_path=Path("model.gguf"),
                model_identifier="fake-local",
                runner=fake_runner,
            ),
            settings=RUNTIME_SETTINGS,
        )

        self.assertFalse(result.is_valid)
        self.assertTrue(any("malformed JSON" in error for error in result.validation_errors))
        self.assertEqual(result.ordered_candidate_ids, [candidate.candidate_id for candidate in smoke_candidates()])

    def test_model_metadata_requires_exact_four_shortlisted_artifacts(self) -> None:
        self.assertEqual(len(MODEL_ARTIFACTS), 4)
        ids = {model.candidate_id for model in MODEL_ARTIFACTS}
        self.assertEqual(
            ids,
            {
                "qwen2_5_7b_instruct_gguf_q4_k_m",
                "phi3_5_mini_instruct_gguf_q4_k_m",
                "mistral_7b_instruct_v0_3_gguf_q4_k_m",
                "gemma3_4b_it_gguf_q4_k_m",
            },
        )
        self.assertEqual(LLAMA_CPP_RELEASE["release_tag"], "b9637")
        for model in MODEL_ARTIFACTS:
            self.assertEqual(model.quantization, "Q4_K_M")
            self.assertTrue(model.revision)

    def test_missing_model_file_metadata_uses_not_available(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            metadata = model_metadata(MODEL_ARTIFACTS[1], model_root=Path(tmp))

        self.assertFalse(metadata["all_files_present"])
        self.assertEqual(metadata["files"][0]["sha256"], NOT_AVAILABLE)
        self.assertEqual(metadata["total_size_bytes"], NOT_AVAILABLE)

    def test_smoke_package_validation_does_not_select_model(self) -> None:
        rows = [
            {
                "model_candidate_id": model.candidate_id,
                "scored": False,
                "smoke_status": "valid",
            }
            for model in MODEL_ARTIFACTS
        ]
        model_rows = [{"candidate_id": model.candidate_id, "all_files_present": True} for model in MODEL_ARTIFACTS]
        validation = validate_smoke_package(rows, model_rows, {"executable_exists": True})

        self.assertTrue(validation["valid"], validation["errors"])
        self.assertFalse(validation["calibration_bakeoff_executed"])
        self.assertFalse(validation["final_24_scenario_xss_v13_used"])
        self.assertFalse(validation["final_model_selection_made"])

    def test_reporting_package_can_be_written_from_minimal_smoke_data(self) -> None:
        package = {
            "manifest": {
                "schema_version": PROVISIONING_VERSION,
                "validation_valid": True,
            },
            "hardware": {"schema_version": "test-hardware"},
            "runtime": {
                **LLAMA_CPP_RELEASE,
                "runtime_id": "llama.cpp-b9637-win-cpu-x64-llama-completion",
                "executable_sha256": "abc",
            },
            "models": [
                {
                    "candidate_id": model.candidate_id,
                    "repository": model.repository,
                    "revision": model.revision,
                    "license": model.license,
                    "quantization": model.quantization,
                    "files": [
                        {
                            "filename": model.primary_model_filename,
                            "size_bytes": NOT_AVAILABLE,
                            "sha256": NOT_AVAILABLE,
                        }
                    ],
                }
                for model in MODEL_ARTIFACTS
            ],
            "smoke_rows": [
                {
                    "model_candidate_id": model.candidate_id,
                    "display_name": model.display_name,
                    "repository": model.repository,
                    "revision": model.revision,
                    "primary_model_filename": model.primary_model_filename,
                    "smoke_status": "invalid_or_failed",
                    "model_loaded_or_call_completed": False,
                    "parser_executed": True,
                    "valid_schema_output": False,
                    "provider_failed": True,
                    "validation_errors": ["test"],
                    "raw_response_retained": False,
                    "existing_candidate_ids_only": True,
                    "latency_ms": NOT_AVAILABLE,
                    "memory_observation": NOT_AVAILABLE,
                    "scored": False,
                }
                for model in MODEL_ARTIFACTS
            ],
            "raw_artifacts": [
                {
                    "model_candidate_id": model.candidate_id,
                    "scenario_id": "local-runtime-smoke-non-scored",
                    "trial_number": 1,
                    "artifact_status": "non_scored_local_runtime_smoke",
                }
                for model in MODEL_ARTIFACTS
            ],
            "validation": {
                "schema_version": "local-runtime-smoke-validation-v1.3",
                "valid": True,
                "errors": [],
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "package"
            write_smoke_package(package, output)

            self.assertTrue((output / "manifest.json").exists())
            self.assertTrue((output / "hardware-report.json").exists())
            self.assertTrue((output / "runtime-metadata.json").exists())
            self.assertTrue((output / "normalized" / "smoke-results.csv").exists())
            self.assertTrue((output / "checksums.sha256").exists())


if __name__ == "__main__":
    unittest.main()
