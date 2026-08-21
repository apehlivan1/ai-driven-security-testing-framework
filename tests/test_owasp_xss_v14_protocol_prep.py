from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.owasp_xss_v14_protocol_prep import (
    ARM_IDS,
    FORBIDDEN_MODELFACING_FRAGMENTS,
    build_protocol_freeze_package,
    model_facing_snapshot_leaks,
)


class OwaspXssV14ProtocolPrepTests(unittest.TestCase):
    def test_builds_final_protocol_package_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = build_protocol_freeze_package(output_dir=Path(tmp))
            root = Path(tmp)

            validation = json.loads((root / "preflight-validation-report.json").read_text(encoding="utf-8"))
            corpus = json.loads((root / "final-corpus-manifest.json").read_text(encoding="utf-8"))
            scenarios = json.loads((root / "scenario-manifest.json").read_text(encoding="utf-8"))
            schedule = json.loads((root / "trial-schedule.json").read_text(encoding="utf-8"))
            scoring = json.loads((root / "ground-truth" / "scoring-data.json").read_text(encoding="utf-8"))
            checksums = json.loads((root / "checksum-validation-report.json").read_text(encoding="utf-8"))

            self.assertTrue(manifest["validation_valid"])
            self.assertTrue(validation["valid"])
            self.assertTrue(checksums["valid"])
            self.assertEqual(corpus["corpus_counts"]["final_confirmatory_eligible"], 388)
            self.assertEqual(corpus["corpus_counts"]["final_confirmatory_eligible_vulnerable"], 236)
            self.assertEqual(corpus["corpus_counts"]["final_confirmatory_eligible_non_vulnerable"], 152)
            self.assertEqual(corpus["corpus_counts"]["readiness_only"], 20)
            self.assertEqual(corpus["corpus_counts"]["excluded"], 47)
            self.assertEqual(scenarios["scenario_count"], 266)
            self.assertEqual(scoring["positive_scenarios"], 236)
            self.assertEqual(scoring["negative_only_scenarios"], 30)
            self.assertEqual(schedule["denominators"]["deterministic_structural"], 266)
            self.assertEqual(schedule["denominators"]["proprietary_gpt"], 1330)
            self.assertEqual(schedule["denominators"]["local_qwen"], 1330)
            self.assertEqual(schedule["denominators"]["total_ranking_rows"], 2926)
            self.assertFalse(validation["final_confirmatory_cases_executed"])
            self.assertFalse(validation["gpt_calls_executed"])
            self.assertFalse(validation["qwen_calls_executed"])

    def test_every_vulnerable_candidate_is_focal_exactly_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            build_protocol_freeze_package(output_dir=Path(tmp))
            scoring = json.loads((Path(tmp) / "ground-truth" / "scoring-data.json").read_text(encoding="utf-8"))

            focal_ids = [
                scenario["focal_vulnerable_candidate_id"]
                for scenario in scoring["scenarios"]
                if scenario["scenario_type"] == "positive"
            ]

            self.assertEqual(len(focal_ids), 236)
            self.assertEqual(len(set(focal_ids)), 236)

    def test_model_facing_snapshots_do_not_leak_ground_truth_or_benchmark_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            build_protocol_freeze_package(output_dir=Path(tmp))
            snapshot_dir = Path(tmp) / "model-facing" / "candidate-snapshots"

            for path in snapshot_dir.glob("*.json"):
                snapshot = json.loads(path.read_text(encoding="utf-8"))
                self.assertFalse(model_facing_snapshot_leaks(snapshot), path.name)
                serialized = json.dumps(snapshot, sort_keys=True)
                for fragment in FORBIDDEN_MODELFACING_FRAGMENTS:
                    self.assertNotIn(fragment, serialized)

    def test_decoy_assignment_is_balanced_and_records_leftover_negatives(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            build_protocol_freeze_package(output_dir=Path(tmp))
            decoys = json.loads((Path(tmp) / "ground-truth" / "decoy-assignment-manifest.json").read_text(encoding="utf-8"))

            self.assertEqual(decoys["negative_reuse_distribution_for_positive_scenarios"], {"6": 120, "7": 32})
            self.assertEqual(len(decoys["unused_negative_only_candidates"]), 2)

    def test_arm_configuration_freezes_three_expected_arms(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            build_protocol_freeze_package(output_dir=Path(tmp))
            arms = json.loads((Path(tmp) / "arm-configurations.json").read_text(encoding="utf-8"))

            self.assertEqual([arm["arm_id"] for arm in arms["arms"]], list(ARM_IDS))
            local = next(arm for arm in arms["arms"] if arm["arm_id"] == "local_qwen")
            self.assertFalse(local["fallback_rule"]["silent_qwen_to_gemma_substitution"])
            self.assertEqual(local["primary_model_candidate_id"], "qwen2_5_7b_instruct_gguf_q4_k_m")


if __name__ == "__main__":
    unittest.main()
