import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.metrics import NOT_APPLICABLE, NOT_AVAILABLE
from adstf.xss_v13_ablation_harness import (
    DEFAULT_READINESS_DIR,
    FROZEN_TEST_BUDGET,
    HARNESS_READINESS_VERSION,
    LLM_TRIALS,
    PROPRIETARY_MODEL_IDENTIFIER,
    PROTECTED_OUTPUT_DIRS,
    build_amendment_readiness_package,
    build_execution_schedule,
    build_harness_readiness_package,
    create_proprietary_gpt_client,
    load_frozen_snapshots,
    measurement_template_summary,
    preflight_check,
    provider_connectivity_readiness,
    score_post_run_cases,
    summarize_schedule,
    timestamp_metric_dry_validation,
    validate_harness_readiness,
    validate_snapshot_package,
)
from adstf.llm_ranking import FakeModelClient
from adstf.xss_v13_protocol_prep import ARM_IDS, LOCAL_CONTINGENCY_MODEL_ID, LOCAL_PRIMARY_MODEL_ID


class XssV13AblationHarnessTests(unittest.TestCase):
    def test_schedule_has_three_explicit_arms_and_frozen_denominators(self) -> None:
        snapshots = load_frozen_snapshots()

        schedule = build_execution_schedule(snapshots)
        summary = {row["arm_id"]: row for row in summarize_schedule(schedule)}

        self.assertEqual(set(summary), set(ARM_IDS))
        self.assertEqual(summary["deterministic_structural"]["scheduled_ranking_calls"], 24)
        self.assertEqual(summary["deterministic_structural"]["provider_calls"], 0)
        self.assertEqual(summary["proprietary_gpt"]["scheduled_ranking_calls"], 24 * LLM_TRIALS)
        self.assertEqual(summary["local_qwen"]["scheduled_ranking_calls"], 24 * LLM_TRIALS)
        self.assertEqual(len(schedule), 264)
        self.assertTrue(all(item["test_budget"] == FROZEN_TEST_BUDGET for item in schedule))
        self.assertTrue(all(item["top_k"] == FROZEN_TEST_BUDGET for item in schedule))
        self.assertTrue(all(item["status"] == "planned_not_executed" for item in schedule))

    def test_snapshot_package_is_frozen_and_ground_truth_free(self) -> None:
        snapshots = load_frozen_snapshots()

        validation = validate_snapshot_package(snapshots)

        self.assertTrue(validation["valid"], validation["errors"])
        self.assertEqual(validation["scenario_count"], 24)
        self.assertFalse(validation["snapshots_contain_ground_truth"])
        self.assertFalse(validation["ground_truth_semantics_loaded"])
        self.assertEqual(validation["budget_values"], [FROZEN_TEST_BUDGET])

    def test_dry_preflight_allows_unresolved_openai_model_but_measured_preflight_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch("adstf.xss_v13_ablation_harness._check_qwen_artifacts") as qwen_check:
                qwen_check.side_effect = lambda checks, errors: checks.append({"check": "qwen_artifacts_mocked", "passed": True})
                dry = preflight_check(
                    measured_execution=False,
                    output_dir=Path(tmp) / "dry",
                    env={"OPENAI_API_KEY": "present", "OPENAI_SEND_TEMPERATURE": "false"},
                )
                measured = preflight_check(
                    measured_execution=True,
                    output_dir=Path(tmp) / "measured",
                    env={"OPENAI_API_KEY": "present", "OPENAI_SEND_TEMPERATURE": "false"},
                )

        self.assertTrue(dry["valid"], dry["errors"])
        self.assertIn("openai_model_exact", measured["errors"])
        self.assertFalse(measured["valid"])
        self.assertFalse(measured["openai_secret_recorded"])

    def test_preflight_refuses_temperature_and_protocol_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("adstf.xss_v13_ablation_harness.PROTOCOL_CRITICAL_HASHES", {"docs/metrics-definition-v1.3.md": "bad"}),
                patch("adstf.xss_v13_ablation_harness._check_qwen_artifacts") as qwen_check,
            ):
                qwen_check.side_effect = lambda checks, errors: checks.append({"check": "qwen_artifacts_mocked", "passed": True})
                report = preflight_check(
                    measured_execution=False,
                    output_dir=Path(tmp) / "dry",
                    env={"OPENAI_SEND_TEMPERATURE": "true"},
                )

        self.assertIn("openai_send_temperature_unset_or_false", report["errors"])
        self.assertIn("protocol_hash:docs/metrics-definition-v1.3.md", report["errors"])
        self.assertFalse(report["valid"])

    def test_preflight_refuses_runtime_or_model_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch("adstf.xss_v13_ablation_harness.LLAMA_COMPLETION_EXE", Path(tmp) / "missing.exe"):
                report = preflight_check(
                    measured_execution=False,
                    output_dir=Path(tmp) / "dry",
                    env={"OPENAI_SEND_TEMPERATURE": "false"},
                )

        self.assertIn("llama_completion_runtime_hash", report["errors"])
        self.assertFalse(report["valid"])

    def test_output_directory_protects_v1_2_and_previous_v1_3_packages(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            protected_v1_2 = Path(tmp) / "some-v1.2-package"
            protected_v1_2.mkdir()
            with patch("adstf.xss_v13_ablation_harness._check_qwen_artifacts") as qwen_check:
                qwen_check.side_effect = lambda checks, errors: checks.append({"check": "qwen_artifacts_mocked", "passed": True})
                reports = [
                    preflight_check(measured_execution=False, output_dir=protected_v1_2, env={}),
                ]
                for protected in PROTECTED_OUTPUT_DIRS:
                    reports.append(preflight_check(measured_execution=False, output_dir=protected, env={}))

        for report in reports:
            self.assertIn("output_not_v1_2_or_protected_v1_3", report["errors"])
            self.assertFalse(report["valid"])

    def test_provider_separation_and_no_silent_qwen_to_gemma_substitution(self) -> None:
        client = create_proprietary_gpt_client({"OPENAI_RANKING_MODEL": PROPRIETARY_MODEL_IDENTIFIER})

        self.assertEqual(client.model_identifier, PROPRIETARY_MODEL_IDENTIFIER)
        self.assertEqual(LOCAL_PRIMARY_MODEL_ID, "qwen2_5_7b_instruct_gguf_q4_k_m")
        self.assertEqual(LOCAL_CONTINGENCY_MODEL_ID, "gemma3_4b_it_gguf_q4_k_m")
        self.assertNotEqual(LOCAL_PRIMARY_MODEL_ID, LOCAL_CONTINGENCY_MODEL_ID)

    def test_measured_client_refuses_unresolved_proprietary_model_identifier(self) -> None:
        with self.assertRaises(Exception):
            create_proprietary_gpt_client({})

    def test_measurement_templates_keep_provider_cost_semantics(self) -> None:
        templates = measurement_template_summary()

        self.assertEqual(templates["deterministic_structural"]["model_provider"]["cost_per_ranking_trial_usd"], NOT_APPLICABLE)
        self.assertEqual(templates["proprietary_gpt"]["model_provider"]["cost_per_ranking_trial_usd"], NOT_AVAILABLE)
        self.assertEqual(templates["local_qwen"]["model_provider"]["cost_per_ranking_trial_usd"], NOT_AVAILABLE)
        self.assertEqual(templates["proprietary_gpt"]["first_verified_finding"]["time_to_first_verified_finding_ms"], NOT_APPLICABLE)

    def test_post_run_scoring_interface_loads_truth_only_after_execution(self) -> None:
        rows = [
            {"scenario_id": "x13-001", "action_path": "/one", "parameter_name": "a", "verified": True},
            {"scenario_id": "x13-001", "action_path": "/two", "parameter_name": "b", "verified": False},
            {"scenario_id": "x13-002", "action_path": "/missing", "parameter_name": "z", "verified": False},
        ]
        ground_truth = {
            "scenarios": [
                {
                    "scenario_id": "x13-001",
                    "cases": [
                        {"action_path": "/one", "parameter_name": "a", "vulnerable": True},
                        {"action_path": "/two", "parameter_name": "b", "vulnerable": False},
                    ],
                }
            ]
        }

        scored = score_post_run_cases(rows, ground_truth)

        self.assertEqual([row["classification"] for row in scored["rows"]], ["TP", "TN", "not_available"])
        self.assertEqual(scored["ground_truth_phase"], "post_run_only")

    def test_readiness_package_contains_raw_normalized_tables_and_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "readiness"
            package = build_harness_readiness_package(output)
            with (output / "normalized" / "execution-schedule.csv").open(encoding="utf-8") as handle:
                schedule_rows = list(csv.DictReader(handle))

            self.assertTrue(package["validation"]["valid"], package["validation"]["errors"])
            self.assertEqual(package["manifest"]["schema_version"], HARNESS_READINESS_VERSION)
            self.assertEqual(len(list((output / "raw").glob("*.json"))), 264)
            self.assertEqual(len(schedule_rows), 264)
            self.assertTrue((output / "manifest.json").exists())
            self.assertTrue((output / "validation-report.json").exists())
            self.assertTrue((output / "report.md").exists())
            self.assertTrue((output / "tables" / "thesis-tables.md").exists())
            self.assertTrue((output / "checksums.sha256").exists())

    def test_harness_readiness_validation_rejects_malformed_schedule(self) -> None:
        snapshots = load_frozen_snapshots()
        schedule = build_execution_schedule(snapshots)
        schedule[0]["status"] = "executed"
        summary = summarize_schedule(schedule)
        preflight = {"valid": True, "errors": []}

        validation = validate_harness_readiness(preflight, snapshots, schedule, summary)

        self.assertFalse(validation["valid"])
        self.assertIn("dry-run schedule contains executed items", validation["errors"])

    def test_snapshot_only_harness_does_not_expose_discovery_entrypoint(self) -> None:
        import adstf.xss_v13_ablation_harness as harness

        self.assertFalse(hasattr(harness, "discover_reflected_input_candidates"))
        self.assertEqual(harness.DEFAULT_READINESS_DIR, DEFAULT_READINESS_DIR)

    def test_provider_connectivity_readiness_uses_non_scored_synthetic_candidates(self) -> None:
        report = provider_connectivity_readiness(
            model_client=FakeModelClient(model_identifier=PROPRIETARY_MODEL_IDENTIFIER)
        )

        self.assertTrue(report["valid"], report["validation_errors"])
        self.assertFalse(report["held_out_scenario_used"])
        self.assertFalse(report["scored_observation_created"])
        self.assertFalse(report["live_provider_call_executed"])
        self.assertEqual(report["execution_mode"], "fake_offline_validation")
        self.assertEqual(report["scenario_id"], "provider-connectivity-readiness-v1.3.1")
        self.assertEqual(report["model_identifier"], PROPRIETARY_MODEL_IDENTIFIER)
        self.assertEqual(report["candidate_count"], 2)

    def test_provider_connectivity_readiness_records_provider_failure(self) -> None:
        report = provider_connectivity_readiness(
            model_client=FakeModelClient(model_identifier=PROPRIETARY_MODEL_IDENTIFIER, strategy="provider_failure")
        )

        self.assertFalse(report["valid"])
        self.assertTrue(report["provider_failed"])
        self.assertIn("fake provider failure", " ".join(report["validation_errors"]))

    def test_timestamp_metric_dry_validation_is_deterministic(self) -> None:
        report = timestamp_metric_dry_validation()

        self.assertTrue(report["valid"], report["errors"])
        first = report["measurements"]["first_verified_finding"]
        self.assertEqual(first["timestamp"], "2026-08-08T10:00:03+00:00")
        self.assertEqual(first["time_to_first_verified_finding_ms"], 3000)
        self.assertFalse(report["file_time_reconstruction_used"])

    def test_amendment_readiness_package_is_non_scored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "amendment"
            package = build_amendment_readiness_package(output)

            self.assertTrue(package["validation"]["valid"], package["validation"]["errors"])
            self.assertFalse(package["validation"]["provider_readiness_live_call_executed"])
            self.assertFalse(package["validation"]["scored_experiment_executed"])
            self.assertFalse(package["validation"]["browser_verification_executed"])
            self.assertTrue((output / "manifest.json").exists())
            self.assertTrue((output / "provider-connectivity-readiness.json").exists())
            self.assertTrue((output / "timestamp-metric-dry-validation.json").exists())
            self.assertTrue((output / "checksums.sha256").exists())


if __name__ == "__main__":
    unittest.main()
