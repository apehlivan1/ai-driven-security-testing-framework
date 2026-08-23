from __future__ import annotations

import json
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.owasp_sqli_v15_protocol_prep import (  # noqa: E402
    ARM_IDS,
    FINAL_CORPUS_ROLE,
    PACK_SIZE,
    PROTOCOL_PATH,
    TEST_BUDGET,
    build_protocol_freeze_package,
    model_facing_snapshot_leaks,
    validate_checksums,
)


class OwaspSqliV15ProtocolPrepTests(unittest.TestCase):
    def build_package(self, root: Path) -> dict:
        return build_protocol_freeze_package(output_dir=root, protocol_path=PROTOCOL_PATH)

    def test_builds_protocol_package_with_exact_frozen_denominators(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            manifest = self.build_package(output_dir)
            corpus = json.loads((output_dir / "final-corpus-manifest.json").read_text(encoding="utf-8"))
            scenarios = json.loads((output_dir / "scenario-manifest.json").read_text(encoding="utf-8"))
            scoring = json.loads((output_dir / "ground-truth" / "scoring-data.json").read_text(encoding="utf-8"))
            trial_schedule = json.loads((output_dir / "trial-schedule.json").read_text(encoding="utf-8"))
            direct_schedule = json.loads((output_dir / "direct-execution-schedule.json").read_text(encoding="utf-8"))
            validation = json.loads((output_dir / "preflight-validation-report.json").read_text(encoding="utf-8"))

            counts = corpus["corpus_counts"]
            self.assertTrue(manifest["validation_valid"])
            self.assertTrue(validation["valid"])
            self.assertEqual(counts["original_sqli_cases"], 504)
            self.assertEqual(counts["readiness_only"], 20)
            self.assertEqual(counts["final_confirmatory_eligible"], 200)
            self.assertEqual(counts["final_confirmatory_eligible_vulnerable"], 105)
            self.assertEqual(counts["final_confirmatory_eligible_non_vulnerable"], 95)
            self.assertEqual(counts["excluded"], 284)
            self.assertEqual(scenarios["scenario_count"], 124)
            self.assertEqual(scoring["positive_scenarios"], 105)
            self.assertEqual(scoring["negative_only_scenarios"], 19)
            self.assertEqual(trial_schedule["denominators"]["deterministic_structural"], 124)
            self.assertEqual(trial_schedule["denominators"]["proprietary_gpt"], 620)
            self.assertEqual(trial_schedule["denominators"]["local_qwen"], 620)
            self.assertEqual(trial_schedule["denominators"]["total_ranking_rows"], 1364)
            self.assertEqual(direct_schedule["case_denominator"], 200)
            self.assertEqual(direct_schedule["expected_http_request_count"], 1200)

    def test_final_corpus_excludes_readiness_and_non_final_roles(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            self.build_package(output_dir)
            final_rows = (output_dir / "final-corpus.csv").read_text(encoding="utf-8").splitlines()
            validation = json.loads((output_dir / "preflight-validation-report.json").read_text(encoding="utf-8"))
            provenance = json.loads((output_dir / "provenance" / "internal-provenance.json").read_text(encoding="utf-8"))

            self.assertEqual(len(final_rows) - 1, 200)
            self.assertFalse(validation["readiness_only_in_final_corpus"])
            self.assertFalse(validation["excluded_in_final_corpus"])
            self.assertEqual({record["evaluation_role"] for record in provenance["records"]}, {FINAL_CORPUS_ROLE})

    def test_scenarios_have_fixed_pack_budget_and_focal_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            self.build_package(output_dir)
            scenarios = json.loads((output_dir / "scenario-manifest.json").read_text(encoding="utf-8"))
            scoring = json.loads((output_dir / "ground-truth" / "scoring-data.json").read_text(encoding="utf-8"))
            decoys = json.loads((output_dir / "ground-truth" / "decoy-assignment-manifest.json").read_text(encoding="utf-8"))

            self.assertEqual(scenarios["pack_size"], PACK_SIZE)
            self.assertEqual(scenarios["candidate_test_budget"], TEST_BUDGET)
            self.assertTrue(all(item["candidate_count"] == 5 for item in scenarios["scenarios"]))
            self.assertTrue(all(item["top_k"] == 4 for item in scenarios["scenarios"]))

            positive = [item for item in scoring["scenarios"] if item["scenario_type"] == "positive"]
            focal_ids = [item["focal_vulnerable_candidate_id"] for item in positive]
            self.assertEqual(len(focal_ids), 105)
            self.assertEqual(len(set(focal_ids)), 105)
            self.assertEqual(decoys["negative_reuse_distribution_for_positive_scenarios"], {"4": 55, "5": 40})
            self.assertEqual(decoys["unused_negative_only_candidates"], [])

    def test_model_facing_snapshots_are_sanitized_and_ground_truth_separated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            self.build_package(output_dir)
            snapshot_paths = sorted((output_dir / "model-facing" / "candidate-snapshots").glob("*.json"))
            scoring = json.loads((output_dir / "ground-truth" / "scoring-data.json").read_text(encoding="utf-8"))

            self.assertEqual(len(snapshot_paths), 124)
            for path in snapshot_paths:
                snapshot = json.loads(path.read_text(encoding="utf-8"))
                self.assertFalse(model_facing_snapshot_leaks(snapshot), path.name)
                serialized = json.dumps(snapshot, sort_keys=True).lower()
                self.assertNotIn("benchmarktest", serialized)
                self.assertNotIn("expected_result", serialized)
                self.assertNotIn("ground_truth", serialized)
                self.assertNotIn("vulnerable", serialized)
                self.assertNotIn("non_vulnerable", serialized)

            self.assertEqual(scoring["artifact_status"], "post_run_scoring_only_not_model_facing")
            self.assertIn("candidate_ground_truth", scoring)

    def test_arm_configurations_and_failure_rules_are_frozen(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            self.build_package(output_dir)
            arms = json.loads((output_dir / "arm-configurations.json").read_text(encoding="utf-8"))
            schedule = json.loads((output_dir / "trial-schedule.json").read_text(encoding="utf-8"))
            arm_ids = [arm["arm_id"] for arm in arms["arms"]]

            self.assertEqual(arm_ids, list(ARM_IDS))
            self.assertIn("No silent retries", schedule["retry_policy"])
            qwen = next(arm for arm in arms["arms"] if arm["arm_id"] == "local_qwen")
            self.assertFalse(qwen["fallback_rule"]["silent_qwen_to_gemma_substitution"])

    def test_checksums_validate_and_dry_mode_records_zero_activity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            self.build_package(output_dir)
            validation = json.loads((output_dir / "preflight-validation-report.json").read_text(encoding="utf-8"))
            checksum_validation = validate_checksums(output_dir / "checksums.sha256")

            self.assertTrue(checksum_validation["valid"])
            self.assertEqual(validation["final_confirmatory_sqli_runtime_executions"], 0)
            self.assertEqual(validation["scored_ranking_rows_executed"], 0)
            self.assertEqual(validation["gpt_calls_executed"], 0)
            self.assertEqual(validation["qwen_calls_executed"], 0)


if __name__ == "__main__":
    unittest.main()
