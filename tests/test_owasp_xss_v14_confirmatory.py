from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.llm_ranking import ModelCompletion, ModelProviderError
from adstf.owasp_xss_v14_confirmatory import (
    EXPECTED_DENOMINATORS,
    ConfirmatoryHarnessError,
    execute_schedule_rows,
    gpt_preflight,
    load_protocol_package,
    qwen_preflight,
    row_artifact_path,
    run_dry_validation,
    run_runtime_preflight,
    scheduled_row_id,
    validate_existing_row_artifact,
    validate_protocol_package,
    validate_schedule_resolution,
)


class CountingModelClient:
    def __init__(self, *, fail: bool = False) -> None:
        self.model_identifier = "fake-counting-model"
        self.calls = 0
        self.fail = fail

    def complete(self, prompt: str, candidate_input: list[dict], settings: dict) -> ModelCompletion:
        self.calls += 1
        if self.fail:
            raise ModelProviderError("planned fake provider failure")
        ranking = [
            {"candidate_id": item["candidate_id"], "rationale": "fake test ranking"}
            for item in candidate_input
        ]
        return ModelCompletion(
            model_identifier=self.model_identifier,
            raw_response=json.dumps({"ranking": ranking}),
            provider="fake",
            usage={"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            latency_ms=1,
        )


class OwaspXssV14ConfirmatoryHarnessTests(unittest.TestCase):
    def test_resolves_exact_frozen_schedule_denominators(self) -> None:
        package = load_protocol_package(Path("results/owasp-xss-v14-protocol-freeze"))

        validation = validate_schedule_resolution(package)

        self.assertTrue(validation["valid"], validation["errors"])
        self.assertEqual(validation["total_rows"], 2926)
        self.assertEqual(validation["per_arm_counts"], {
            "deterministic_structural": 266,
            "proprietary_gpt": 1330,
            "local_qwen": 1330,
        })
        self.assertEqual(package["schedule"]["denominators"], EXPECTED_DENOMINATORS)

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
            self.assertEqual(report["external_calls"]["gpt_calls"], 0)
            self.assertEqual(report["external_calls"]["qwen_calls"], 0)
            self.assertEqual(report["external_calls"]["owasp_or_browser_final_case_calls"], 0)
            self.assertEqual(report["external_calls"]["scored_observations"], 0)
            self.assertFalse(report["ground_truth_isolation"]["ground_truth_loaded_during_dry_validation"])
            self.assertTrue((Path(tmp) / "dry-validation-report.json").exists())

    def test_runtime_preflight_reports_target_unreachable_without_execution(self) -> None:
        report = run_runtime_preflight(
            env={"OPENAI_API_KEY": "secret", "OPENAI_RANKING_MODEL": "gpt-5.6-luna"},
            target_probe=lambda url: {"reachable": False, "error": "offline", "url": url},
        )

        self.assertFalse(report["valid"])
        self.assertFalse(report["runtime_preflight"]["owasp_target"]["valid"])
        self.assertFalse(report["runtime_preflight"]["owasp_target"]["final_confirmatory_case_executed"])

    def test_gpt_preflight_rejects_missing_or_wrong_model(self) -> None:
        missing = gpt_preflight({"OPENAI_API_KEY": "secret"})
        wrong = gpt_preflight({"OPENAI_API_KEY": "secret", "OPENAI_RANKING_MODEL": "other-model"})

        self.assertFalse(missing["valid"])
        self.assertIn("OPENAI_RANKING_MODEL_not_frozen_value", missing["errors"])
        self.assertFalse(wrong["valid"])
        self.assertIn("OPENAI_RANKING_MODEL_not_frozen_value", wrong["errors"])

    def test_qwen_preflight_rejects_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "llama-completion.exe"
            runtime.write_text("wrong runtime", encoding="utf-8")

            report = qwen_preflight(runtime_path=runtime, model_root=Path(tmp))

            self.assertFalse(report["valid"])
            self.assertIn("qwen_runtime_hash_mismatch", report["errors"])

    def test_protocol_checksum_mismatch_is_hard_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "package"
            shutil.copytree("results/owasp-xss-v14-protocol-freeze", root)
            target = root / "scenario-manifest.json"
            data = json.loads(target.read_text(encoding="utf-8"))
            data["scenario_count"] = 999
            target.write_text(json.dumps(data), encoding="utf-8")

            package = load_protocol_package(root)
            validation = validate_protocol_package(package)

            self.assertFalse(validation["valid"])
            self.assertGreater(validation["package_checksum_error_count"], 0)

    def test_existing_row_artifact_identity_mismatch_is_rejected(self) -> None:
        package = load_protocol_package(Path("results/owasp-xss-v14-protocol-freeze"))
        row = package["schedule_rows"][0]
        existing = {"summary": {**row, "scenario_id": "wrong-scenario"}}

        with self.assertRaises(ConfirmatoryHarnessError):
            validate_existing_row_artifact(existing, row)

    def test_resume_skips_existing_completed_row_without_overwrite(self) -> None:
        package = load_protocol_package(Path("results/owasp-xss-v14-protocol-freeze"))
        package = {**package, "schedule_rows": package["schedule_rows"][:1]}

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            row_dir = run_dir / "raw" / "ranking-rows"
            row_dir.mkdir(parents=True)
            row = package["schedule_rows"][0]
            artifact = {
                "summary": {
                    "sequence": row["sequence"],
                    "scenario_id": row["scenario_id"],
                    "arm_id": row["arm_id"],
                    "trial_number": row["trial_number"],
                    "status": "valid",
                }
            }
            path = row_artifact_path(row_dir, row)
            path.write_text(json.dumps(artifact), encoding="utf-8")

            completed = execute_schedule_rows(run_dir=run_dir, package=package, max_rows=1)

            self.assertEqual(len(completed), 1)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), artifact)

    def test_provider_failure_is_recorded_once_without_retry(self) -> None:
        package = load_protocol_package(Path("results/owasp-xss-v14-protocol-freeze"))
        gpt_row = next(row for row in package["schedule_rows"] if row["arm_id"] == "proprietary_gpt")
        package = {**package, "schedule_rows": [gpt_row]}
        client = CountingModelClient(fail=True)

        with tempfile.TemporaryDirectory() as tmp:
            execute_schedule_rows(run_dir=Path(tmp), package=package, gpt_client=client, max_rows=1)
            artifacts = list((Path(tmp) / "raw" / "ranking-rows").glob("*.json"))
            data = json.loads(artifacts[0].read_text(encoding="utf-8"))

            self.assertEqual(client.calls, 1)
            self.assertTrue(data["summary"]["provider_failed"])
            self.assertEqual(data["summary"]["status"], "provider_failed")

    def test_scheduled_row_identity_includes_arm_scenario_trial_and_sequence(self) -> None:
        row = {"sequence": 1, "arm_id": "a", "scenario_id": "s", "trial_number": 2}

        self.assertEqual(scheduled_row_id(row), "1|a|s|2")


if __name__ == "__main__":
    unittest.main()
