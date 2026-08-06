import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.xss_v13_protocol_prep import (
    ARM_IDS,
    CANDIDATE_SNAPSHOT_VERSION,
    LOCAL_CONTINGENCY_MODEL_ID,
    LOCAL_PRIMARY_MODEL_ID,
    build_protocol_prep_package,
    candidate_snapshot_for_scenario,
    snapshot_contains_forbidden_data,
    validate_protocol_prep_package,
)
from adstf.xss_v13_benchmark import xss_v13_manifest


class XssV13ProtocolPrepTests(unittest.TestCase):
    def test_candidate_snapshot_uses_only_ranking_contract_fields(self) -> None:
        scenario = xss_v13_manifest()["scenarios"][0]

        snapshot = candidate_snapshot_for_scenario(scenario)

        self.assertEqual(snapshot["schema_version"], CANDIDATE_SNAPSHOT_VERSION)
        self.assertEqual(snapshot["scenario_id"], "x13-001")
        self.assertEqual(snapshot["candidate_count"], scenario["candidate_count"])
        self.assertFalse(snapshot_contains_forbidden_data(snapshot))
        self.assertNotIn("ground_truth_path", snapshot)
        self.assertNotIn("outcome_class", snapshot)
        for candidate in snapshot["candidate_input"]:
            self.assertEqual(
                set(candidate),
                {
                    "candidate_id",
                    "action_path",
                    "method",
                    "parameter_name",
                    "source",
                    "input_type",
                    "editable_input_count",
                    "required_input_count",
                    "parameter_count",
                },
            )

    def test_package_dry_validates_three_identical_arm_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = build_protocol_prep_package(output_dir=Path(tmp) / "prep")
            output = Path(tmp) / "prep"

            self.assertTrue(manifest["validation_valid"])
            self.assertEqual(manifest["scenario_count"], 24)
            self.assertEqual(manifest["arm_ids"], list(ARM_IDS))
            self.assertTrue((output / "candidate-snapshots" / "x13-001.json").exists())
            self.assertTrue((output / "checksums.sha256").exists())

            validation = json.loads((output / "dry-validation-summary.json").read_text(encoding="utf-8"))
            self.assertTrue(validation["valid"], validation["errors"])
            self.assertTrue(validation["shared_candidate_inputs_across_arms"])
            self.assertFalse(validation["candidate_snapshots_contain_ground_truth"])
            self.assertEqual(validation["budget_values"], [4])

            ledger = json.loads((output / "arm-input-ledger.json").read_text(encoding="utf-8"))
            baseline = ledger["arms"][0]["scenario_inputs"]
            for arm in ledger["arms"]:
                self.assertEqual(arm["scenario_inputs"], baseline)

    def test_dry_config_freezes_trial_counts_top_k_metrics_and_fallback_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            build_protocol_prep_package(output_dir=Path(tmp) / "prep")
            config = json.loads((Path(tmp) / "prep" / "dry-run-config.json").read_text(encoding="utf-8"))

            arms = {arm["arm_id"]: arm for arm in config["ranking_arms"]}
            self.assertEqual(arms["deterministic_structural"]["trial_count_per_scenario"], 1)
            self.assertEqual(arms["proprietary_gpt"]["trial_count_per_scenario"], 5)
            self.assertEqual(arms["local_qwen"]["trial_count_per_scenario"], 5)
            self.assertEqual(config["candidate_budget"]["unique_budget_values"], [4])
            self.assertEqual(config["candidate_budget"]["top_k_definition"], "top_k = min(test_budget, discovered_candidate_count)")
            self.assertEqual(arms["local_qwen"]["primary_model_candidate_id"], LOCAL_PRIMARY_MODEL_ID)
            self.assertEqual(config["fallback_rule"]["contingency_model"], LOCAL_CONTINGENCY_MODEL_ID)
            self.assertFalse(config["fallback_rule"]["silent_replacement_allowed"])
            self.assertIn("model_provider", config["metric_capability"]["required_metric_groups"])

    def test_validation_rejects_snapshot_with_ground_truth_like_fields(self) -> None:
        manifest = xss_v13_manifest()
        snapshot = candidate_snapshot_for_scenario(manifest["scenarios"][0])
        snapshot["vulnerable"] = True
        ledger = {
            "arm_ids": list(ARM_IDS),
            "arms": [{"arm_id": arm_id, "scenario_inputs": []} for arm_id in ARM_IDS],
        }
        config = {
            "scenario_ids": [scenario["id"] for scenario in manifest["scenarios"]],
            "candidate_budget": {"unique_budget_values": [4], "top_k_definition": "top_k = min(test_budget, discovered_candidate_count)"},
            "ranking_arms": [{"arm_id": "local_qwen", "primary_model_candidate_id": LOCAL_PRIMARY_MODEL_ID}],
            "fallback_rule": {"silent_replacement_allowed": False, "contingency_model": LOCAL_CONTINGENCY_MODEL_ID},
            "metric_capability": {"required_metric_groups": ["action_counts", "request_counts", "first_verified_finding", "model_provider"]},
        }

        validation = validate_protocol_prep_package(
            manifest=manifest,
            snapshots=[snapshot],
            arm_input_ledger=ledger,
            dry_run_config=config,
        )

        self.assertFalse(validation["valid"])
        self.assertTrue(validation["candidate_snapshots_contain_ground_truth"])
        self.assertIn("snapshot contains ground-truth-like fields", " ".join(validation["errors"]))


if __name__ == "__main__":
    unittest.main()
