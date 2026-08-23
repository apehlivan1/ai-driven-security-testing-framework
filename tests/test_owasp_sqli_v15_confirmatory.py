from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.llm_ranking import ModelCompletion, ModelProviderError  # noqa: E402
import adstf.owasp_sqli_v15_confirmatory as confirmatory  # noqa: E402
from adstf.owasp_sqli_v15_confirmatory import (  # noqa: E402
    EXPECTED_DENOMINATORS,
    EXPECTED_DIRECT_CASES,
    EXPECTED_DIRECT_REQUESTS,
    SqliConfirmatoryHarnessError,
    build_sqli_ranking_prompt,
    build_canonical_package,
    direct_case_artifact_path,
    execute_direct_schedule,
    execute_ranking_schedule_rows,
    gpt_connectivity_readiness,
    gpt_preflight,
    load_protocol_package,
    ranking_row_artifact_path,
    run_dry_validation,
    scheduled_row_id,
    validate_direct_schedule,
    validate_duplicate_and_resume_state,
    validate_existing_direct_artifact,
    validate_existing_ranking_artifact,
    validate_resume_run_directory,
    validate_protocol_package,
    validate_schedule_resolution,
)


class FakeModelClient:
    def __init__(self, *, fail: bool = False, malformed: bool = False) -> None:
        self.model_identifier = "fake-model"
        self.calls = 0
        self.fail = fail
        self.malformed = malformed

    def complete(self, prompt: str, candidate_input: list[dict], settings: dict) -> ModelCompletion:
        self.calls += 1
        if self.fail:
            raise ModelProviderError("planned fake provider failure")
        if self.malformed:
            return ModelCompletion(self.model_identifier, "not-json", provider="fake")
        ranking = [
            {"candidate_id": item["candidate_id"], "rationale": "fake complete ranking"}
            for item in candidate_input
        ]
        return ModelCompletion(
            self.model_identifier,
            json.dumps({"ranking": ranking}),
            provider="fake",
            usage={"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        )


class CapturingModelClient(FakeModelClient):
    def __init__(self) -> None:
        super().__init__()
        self.prompts: list[str] = []
        self.candidate_inputs: list[list[dict]] = []

    def complete(self, prompt: str, candidate_input: list[dict], settings: dict) -> ModelCompletion:
        self.prompts.append(prompt)
        self.candidate_inputs.append(candidate_input)
        return super().complete(prompt, candidate_input, settings)


class OwaspSqliV15ConfirmatoryHarnessTests(unittest.TestCase):
    def test_v151_sqli_prompt_is_not_reflected_input_specific(self) -> None:
        candidate_input = [
            {
                "candidate_id": "synthetic-connectivity-candidate",
                "sanitized_action_path": "/synthetic/connectivity",
                "http_method": "GET",
                "input_carrier": "query_parameter",
                "input_count_category": "single",
                "editable_input_count": 1,
                "multiple_parameters": False,
                "transport_adapter_category": "synthetic",
                "request_shape": "query",
            }
        ]

        prompt = build_sqli_ranking_prompt(candidate_input)

        self.assertIn("structured SQL injection candidate", prompt)
        self.assertIn("You may only choose from the supplied candidate_id values", prompt)
        self.assertIn("Do not create payloads", prompt)
        self.assertIn("do not request execution", prompt)
        self.assertIn("do not verify findings", prompt)
        self.assertIn("do not use ground truth", prompt)
        self.assertNotIn("reflected-input", prompt)

    def test_non_scored_gpt_connectivity_uses_synthetic_input_only(self) -> None:
        client = CapturingModelClient()

        result = gpt_connectivity_readiness(client)

        self.assertTrue(result["valid"], result)
        self.assertTrue(result["live_provider_call_executed"])
        self.assertFalse(result["scored_observation_created"])
        self.assertFalse(result["final_confirmatory_case_used"])
        self.assertEqual(client.calls, 1)
        self.assertEqual(len(client.candidate_inputs), 1)
        self.assertEqual(client.candidate_inputs[0][0]["candidate_id"], "synthetic-connectivity-candidate")
        self.assertNotIn("os15-", json.dumps(client.candidate_inputs[0]))
        self.assertNotIn("BenchmarkTest", json.dumps(client.candidate_inputs[0]))
        self.assertNotIn("reflected-input", client.prompts[0])

    def test_failed_gpt_connectivity_is_non_scored_readiness_failure(self) -> None:
        client = CapturingModelClient()
        client.fail = True

        result = gpt_connectivity_readiness(client)

        self.assertFalse(result["valid"])
        self.assertTrue(result["provider_failed"])
        self.assertFalse(result["live_provider_call_executed"])
        self.assertFalse(result["scored_observation_created"])
        self.assertFalse(result["final_confirmatory_case_used"])
        self.assertEqual(result["prompt_version"], "llm-sqli-candidate-ranking-v1")
        self.assertEqual(client.calls, 1)

    def test_v151_dry_validation_records_amendment_and_no_scored_activity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = run_dry_validation(
                output_dir=Path(tmp),
                env={"OPENAI_API_KEY": "secret", "OPENAI_RANKING_MODEL": "gpt-5.6-luna"},
            )

            self.assertEqual(report["protocol_amendment"]["amendment_version"], "v1.5.1")
            self.assertTrue(report["protocol_amendment"]["valid"])
            self.assertEqual(report["external_calls"]["gpt_calls"], 0)
            self.assertEqual(report["external_calls"]["qwen_calls"], 0)
            self.assertEqual(report["external_calls"]["final_sqli_runtime_executions"], 0)
            self.assertEqual(report["external_calls"]["scored_observations"], 0)
            self.assertEqual(report["ranking_schedule_resolution"]["per_arm_counts"]["proprietary_gpt"], 620)
            self.assertEqual(report["ranking_schedule_resolution"]["per_arm_counts"]["local_qwen"], 620)

    def test_v151_model_ranking_rows_use_sqli_prompt_version(self) -> None:
        package = load_protocol_package(Path("results/owasp-sqli-v15-protocol-freeze"))
        gpt_row = next(row for row in package["schedule_rows"] if row["arm_id"] == "proprietary_gpt")
        package = {**package, "schedule_rows": [gpt_row]}

        with tempfile.TemporaryDirectory() as tmp:
            client = CapturingModelClient()
            execute_ranking_schedule_rows(run_dir=Path(tmp), package=package, gpt_client=client, max_rows=1)
            artifact = json.loads(next((Path(tmp) / "raw" / "ranking-rows").glob("*.json")).read_text(encoding="utf-8"))

        self.assertEqual(artifact["summary"]["prompt_version"], "llm-sqli-candidate-ranking-v1")
        self.assertEqual(artifact["ranking_result"]["prompt_version"], "llm-sqli-candidate-ranking-v1")
        self.assertIn("structured SQL injection candidate", artifact["ranking_result"]["prompt"])
        self.assertNotIn("reflected-input", artifact["ranking_result"]["prompt"])
        self.assertEqual(len(client.candidate_inputs), 1)

    def test_resolves_frozen_ranking_and_direct_denominators(self) -> None:
        package = load_protocol_package(Path("results/owasp-sqli-v15-protocol-freeze"))

        ranking = validate_schedule_resolution(package)
        direct = validate_direct_schedule(package)

        self.assertTrue(ranking["valid"], ranking["errors"])
        self.assertTrue(direct["valid"], direct["errors"])
        self.assertEqual(ranking["per_arm_counts"], {
            "deterministic_structural": 124,
            "proprietary_gpt": 620,
            "local_qwen": 620,
        })
        self.assertEqual(ranking["total_rows"], EXPECTED_DENOMINATORS["total_ranking_rows"])
        self.assertEqual(direct["direct_execution_cases"], EXPECTED_DIRECT_CASES)
        self.assertEqual(direct["expected_http_requests"], EXPECTED_DIRECT_REQUESTS)

    def test_dry_validation_makes_zero_external_or_scored_calls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            probe_called = False

            def forbidden_probe(url: str) -> dict:
                nonlocal probe_called
                probe_called = True
                return {"reachable": True}

            report = run_dry_validation(
                output_dir=Path(tmp),
                env={"OPENAI_API_KEY": "secret", "OPENAI_RANKING_MODEL": "gpt-5.6-luna"},
                target_probe=forbidden_probe,
                check_target=False,
            )

            self.assertFalse(probe_called)
            self.assertTrue(report["valid"], report)
            self.assertEqual(report["external_calls"]["gpt_calls"], 0)
            self.assertEqual(report["external_calls"]["qwen_calls"], 0)
            self.assertEqual(report["external_calls"]["final_sqli_runtime_executions"], 0)
            self.assertEqual(report["external_calls"]["direct_http_requests"], 0)
            self.assertFalse(report["ground_truth_isolation"]["ground_truth_loaded_during_dry_validation"])
            self.assertTrue((Path(tmp) / "dry-validation-report.json").exists())

    def test_gpt_preflight_requires_frozen_model_without_exposing_secret(self) -> None:
        missing = gpt_preflight({"OPENAI_API_KEY": "secret"})
        valid = gpt_preflight({"OPENAI_API_KEY": "secret", "OPENAI_RANKING_MODEL": "gpt-5.6-luna"})

        self.assertFalse(missing["valid"])
        self.assertIn("OPENAI_RANKING_MODEL_not_frozen_value", missing["errors"])
        self.assertTrue(valid["valid"], valid["errors"])
        self.assertFalse(valid["secret_value_recorded"])

    def test_protocol_package_checksum_mismatch_is_hard_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "package"
            shutil.copytree("results/owasp-sqli-v15-protocol-freeze", root)
            target = root / "scenario-manifest.json"
            data = json.loads(target.read_text(encoding="utf-8"))
            data["scenario_count"] = 999
            target.write_text(json.dumps(data), encoding="utf-8")

            validation = validate_protocol_package(load_protocol_package(root))

            self.assertFalse(validation["valid"])
            self.assertGreater(validation["package_checksum_error_count"], 0)

    def test_existing_row_identity_mismatch_is_rejected(self) -> None:
        package = load_protocol_package(Path("results/owasp-sqli-v15-protocol-freeze"))
        row = package["schedule_rows"][0]
        existing = {"summary": {**row, "scenario_id": "wrong-scenario"}}

        with self.assertRaises(SqliConfirmatoryHarnessError):
            validate_existing_ranking_artifact(existing, row)

    def test_duplicate_existing_row_id_is_rejected(self) -> None:
        package = load_protocol_package(Path("results/owasp-sqli-v15-protocol-freeze"))
        row = package["schedule_rows"][0]
        summary = {
            "sequence": row["sequence"],
            "scenario_id": row["scenario_id"],
            "arm_id": row["arm_id"],
            "trial_number": row["trial_number"],
        }

        with tempfile.TemporaryDirectory() as tmp:
            row_dir = Path(tmp) / "raw" / "ranking-rows"
            row_dir.mkdir(parents=True)
            (row_dir / "sequence-0001-a.json").write_text(json.dumps({"summary": summary}), encoding="utf-8")
            (row_dir / "sequence-0001-b.json").write_text(json.dumps({"summary": summary}), encoding="utf-8")

            validation = validate_duplicate_and_resume_state(Path(tmp), package["schedule_rows"])

            self.assertFalse(validation["valid"])
            self.assertTrue(any("duplicate existing row artifact identity" in item for item in validation["errors"]))

    def test_resume_skips_existing_completed_ranking_row_without_overwrite(self) -> None:
        package = load_protocol_package(Path("results/owasp-sqli-v15-protocol-freeze"))
        package = {**package, "schedule_rows": package["schedule_rows"][:1]}

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            row_dir = run_dir / "raw" / "ranking-rows"
            row_dir.mkdir(parents=True)
            row = package["schedule_rows"][0]
            snapshot = package["snapshots_by_id"][row["scenario_id"]]
            artifact = {
                "summary": {
                    "schema_version": "owasp-sqli-v15-ranking-row-v1",
                    "sequence": row["sequence"],
                    "scenario_id": row["scenario_id"],
                    "arm_id": row["arm_id"],
                    "trial_number": row["trial_number"],
                    "snapshot_path": row["snapshot_path"],
                    "candidate_input_sha256": sha256_json(snapshot["candidate_input"]),
                    "candidate_test_budget": row["candidate_test_budget"],
                    "top_k": row["top_k"],
                    "status": "valid",
                },
                "ground_truth_included": False,
            }
            path = ranking_row_artifact_path(row_dir, row)
            path.write_text(json.dumps(artifact), encoding="utf-8")

            completed = execute_ranking_schedule_rows(run_dir=run_dir, package=package, max_rows=1)

            self.assertEqual(len(completed), 1)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), artifact)

    def test_provider_failure_and_malformed_output_are_preserved_without_retry(self) -> None:
        package = load_protocol_package(Path("results/owasp-sqli-v15-protocol-freeze"))
        gpt_row = next(row for row in package["schedule_rows"] if row["arm_id"] == "proprietary_gpt")
        package = {**package, "schedule_rows": [gpt_row]}

        with tempfile.TemporaryDirectory() as tmp:
            failing = FakeModelClient(fail=True)
            execute_ranking_schedule_rows(run_dir=Path(tmp) / "failed", package=package, gpt_client=failing, max_rows=1)
            failed_artifact = next(((Path(tmp) / "failed" / "raw" / "ranking-rows").glob("*.json")))
            failed = json.loads(failed_artifact.read_text(encoding="utf-8"))

            malformed = FakeModelClient(malformed=True)
            execute_ranking_schedule_rows(run_dir=Path(tmp) / "malformed", package=package, gpt_client=malformed, max_rows=1)
            malformed_artifact = next(((Path(tmp) / "malformed" / "raw" / "ranking-rows").glob("*.json")))
            malformed_data = json.loads(malformed_artifact.read_text(encoding="utf-8"))

            self.assertEqual(failing.calls, 1)
            self.assertEqual(malformed.calls, 1)
            self.assertEqual(failed["summary"]["status"], "provider_failed")
            self.assertTrue(failed["summary"]["provider_failed"])
            self.assertEqual(malformed_data["summary"]["status"], "malformed")
            self.assertFalse(malformed_data["summary"]["provider_failed"])

    def test_no_readiness_or_excluded_case_enters_final_schedules(self) -> None:
        package = load_protocol_package(Path("results/owasp-sqli-v15-protocol-freeze"))

        roles = {candidate.provenance.evaluation_role for candidate in package["candidates_by_id"].values()}

        self.assertEqual(roles, {"FINAL_CONFIRMATORY_ELIGIBLE"})
        self.assertEqual(len(package["direct_rows"]), 200)
        self.assertTrue(all(row["candidate_id"] in package["candidates_by_id"] for row in package["direct_rows"]))
        self.assertNotIn("provenance_records", package)
        self.assertEqual(
            {candidate.provenance.expected_result for candidate in package["candidates_by_id"].values()},
            {"not_loaded_during_runtime_execution"},
        )

    def test_stale_existing_artifacts_are_rejected_before_resume(self) -> None:
        package = load_protocol_package(Path("results/owasp-sqli-v15-protocol-freeze"))
        row = package["schedule_rows"][0]
        snapshot = package["snapshots_by_id"][row["scenario_id"]]
        existing = {
            "summary": {
                "schema_version": "owasp-sqli-v15-ranking-row-v1",
                "sequence": row["sequence"],
                "scenario_id": row["scenario_id"],
                "arm_id": row["arm_id"],
                "trial_number": row["trial_number"],
                "snapshot_path": row["snapshot_path"],
                "candidate_input_sha256": "wrong-hash",
                "candidate_test_budget": row["candidate_test_budget"],
                "top_k": row["top_k"],
                "status": "valid",
            },
            "ground_truth_included": False,
        }

        with self.assertRaises(SqliConfirmatoryHarnessError):
            validate_existing_ranking_artifact(
                existing,
                row,
                expected_candidate_input_sha256=sha256_json(snapshot["candidate_input"]),
            )

        direct_row = package["direct_rows"][0]
        bad_direct = {
            "summary": {
                "schema_version": "owasp-sqli-v15-direct-execution-row-v1",
                "sequence": direct_row["sequence"],
                "candidate_id": direct_row["candidate_id"],
                "adapter_class": direct_row["adapter_class"],
                "expected_runtime_requests": direct_row["expected_runtime_requests"],
                "request_count": 5,
                "status": "completed",
            },
            "ground_truth_included": False,
        }
        with self.assertRaises(SqliConfirmatoryHarnessError):
            validate_existing_direct_artifact(bad_direct, direct_row)

    def test_direct_runtime_exception_is_preserved_as_case_artifact(self) -> None:
        package = load_protocol_package(Path("results/owasp-sqli-v15-protocol-freeze"))
        package = {**package, "direct_rows": package["direct_rows"][:1]}
        original_execute_one_candidate = confirmatory.execute_one_candidate

        def failing_execute(*args, **kwargs):  # noqa: ANN002, ANN003
            raise RuntimeError("planned offline failure")

        confirmatory.execute_one_candidate = failing_execute
        try:
            with tempfile.TemporaryDirectory() as tmp:
                completed = execute_direct_schedule(run_dir=Path(tmp), package=package, base_url="https://127.0.0.1:8443/benchmark", max_cases=1)
                artifact = next((Path(tmp) / "raw" / "direct-sqli-cases").glob("*.json"))
                data = json.loads(artifact.read_text(encoding="utf-8"))

                self.assertEqual(len(completed), 1)
                self.assertEqual(data["summary"]["status"], "runtime_error")
                self.assertEqual(data["summary"]["finding_state"], "inconclusive")
                self.assertEqual(data["runtime_result"]["runtime_error_type"], "RuntimeError")
                self.assertFalse(data["ground_truth_included"])
        finally:
            confirmatory.execute_one_candidate = original_execute_one_candidate

    def test_resume_run_directory_allows_existing_harness_run_but_not_root_or_protected_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_root = Path(tmp) / "final"
            run_dir = output_root / "owasp-sqli-v15-confirmatory-test"
            (run_dir / "raw").mkdir(parents=True)

            validate_resume_run_directory(run_dir, output_root)

            with self.assertRaises(SqliConfirmatoryHarnessError):
                validate_resume_run_directory(output_root, output_root)

        with self.assertRaises(SqliConfirmatoryHarnessError):
            validate_resume_run_directory(Path("results/owasp-sqli-v15-protocol-freeze"), Path("results"))

        with self.assertRaises(SqliConfirmatoryHarnessError):
            validate_resume_run_directory(
                Path("results/owasp-sqli-v15-confirmatory-final/owasp-sqli-v15-confirmatory-20260823T122428Z"),
                confirmatory.DEFAULT_V151_FINAL_ROOT,
            )

    def test_canonicalization_scores_full_synthetic_run_without_rerunning_execution(self) -> None:
        package = load_protocol_package(Path("results/owasp-sqli-v15-protocol-freeze"))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = root / "run"
            protocol_copy = root / "protocol"
            canonical_dir = root / "canonical"
            shutil.copytree("results/owasp-sqli-v15-protocol-freeze", protocol_copy)
            write_full_synthetic_run(run_dir, package)

            result = build_canonical_package(run_dir=run_dir, protocol_package_dir=protocol_copy, output_dir=canonical_dir)

            self.assertTrue(result["validation"]["valid"], result["validation"]["errors"])
            self.assertEqual(result["integrity"]["completed_ranking_rows"], 1364)
            self.assertEqual(result["integrity"]["completed_direct_cases"], 200)
            self.assertEqual(result["ranking_aggregates"]["arms"]["deterministic_structural"]["scheduled_rows"], 124)
            self.assertEqual(result["direct_aggregates"]["case_denominator"], 200)
            self.assertEqual(result["manifest"]["gpt_calls_performed_by_canonicalization"], 0)
            self.assertEqual(result["manifest"]["qwen_calls_performed_by_canonicalization"], 0)
            self.assertEqual(result["manifest"]["owasp_cases_executed_by_canonicalization"], 0)


def write_full_synthetic_run(run_dir: Path, package: dict) -> None:
    ranking_dir = run_dir / "raw" / "ranking-rows"
    direct_dir = run_dir / "raw" / "direct-sqli-cases"
    ranking_dir.mkdir(parents=True)
    direct_dir.mkdir(parents=True)
    for row in package["schedule_rows"]:
        snapshot = package["snapshots_by_id"][row["scenario_id"]]
        candidate_ids = [item["candidate_id"] for item in snapshot["candidate_input"]]
        artifact = {
            "schema_version": "synthetic-test-ranking-row",
            "summary": {
                "sequence": row["sequence"],
                "scenario_id": row["scenario_id"],
                "arm_id": row["arm_id"],
                "trial_number": row["trial_number"],
                "snapshot_path": row["snapshot_path"],
                "candidate_input_sha256": sha256_json(snapshot["candidate_input"]),
                "candidate_test_budget": row["candidate_test_budget"],
                "top_k": row["top_k"],
                "status": "valid",
                "contract_valid": True,
                "provider_failed": False,
                "validation_errors": [],
                "latency_ms": 1,
                "model_identifier": "synthetic",
                "provider": "synthetic",
            },
            "ranking_result": {
                "parsed_ranking": candidate_ids,
                "usage": None,
                "cost": None,
                "validation_errors": [],
            },
            "ground_truth_included": False,
        }
        ranking_row_artifact_path(ranking_dir, row).write_text(json.dumps(artifact), encoding="utf-8")

    for row in package["direct_rows"]:
        artifact = {
            "schema_version": "synthetic-test-direct-row",
            "summary": {
                "sequence": row["sequence"],
                "candidate_id": row["candidate_id"],
                "adapter_class": row["adapter_class"],
                "expected_runtime_requests": row["expected_runtime_requests"],
                "status": "completed",
                "baseline_stable": True,
                "true_false_difference_reproducible": False,
                "server_error_observed": False,
                "finding_state": "inconclusive",
                "ground_truth_used_phase": "not_loaded_during_runtime_execution",
                "request_count": row["expected_runtime_requests"],
            },
            "runtime_result": {},
            "ground_truth_included": False,
        }
        direct_case_artifact_path(direct_dir, row).write_text(json.dumps(artifact), encoding="utf-8")


def sha256_json(value: object) -> str:
    import hashlib

    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


if __name__ == "__main__":
    unittest.main()
