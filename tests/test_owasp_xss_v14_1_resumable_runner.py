from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.owasp_xss_v14_1_resumable_runner import (  # noqa: E402
    EXPECTED_DENOMINATORS,
    PROTOCOL_COMMIT,
    PROTOCOL_TAG,
    ResumeAuditRequired,
    build_execution_schedule,
    generate_readiness_package,
    load_protocol_package,
    run_fake_batch,
    validate_resume_state,
)


class OwaspXssV141ResumableRunnerTests(unittest.TestCase):
    def test_builds_frozen_v141_schedule_with_expected_denominators_and_metadata(self) -> None:
        package = load_protocol_package(Path("results/owasp-xss-v14-1-protocol-freeze"))

        schedule = build_execution_schedule(package)

        self.assertEqual(len(schedule), EXPECTED_DENOMINATORS["total_ranking_rows"])
        self.assertEqual(sum(1 for row in schedule if row["arm_family"] == "deterministic"), 532)
        self.assertEqual(sum(1 for row in schedule if row["arm_family"] == "gpt"), 2660)
        self.assertEqual(sum(1 for row in schedule if row["arm_family"] == "qwen"), 2660)
        self.assertEqual(schedule[0]["sequence"], 1)
        self.assertEqual(schedule[-1]["sequence"], 5852)
        self.assertEqual(schedule[0]["protocol_tag"], PROTOCOL_TAG)
        self.assertEqual(schedule[0]["protocol_commit"], PROTOCOL_COMMIT)
        self.assertIn("snapshot_sha256", schedule[0]["snapshot_reference"])
        self.assertIn("candidate_input_sha256", schedule[0]["snapshot_reference"])
        self.assertIn("expected_model_runtime", schedule[0])
        self.assertEqual(schedule[0]["candidate_test_budget"], 4)
        self.assertEqual(schedule[0]["top_k"], 4)

    def test_fake_batch_stops_after_limit_and_fresh_resume_starts_at_next_sequence(self) -> None:
        package = load_protocol_package(Path("results/owasp-xss-v14-1-protocol-freeze"))
        schedule = build_execution_schedule(package)[:6]

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            first = run_fake_batch(run_dir=run_dir, schedule=schedule, max_scheduled_calls=3)
            second = validate_resume_state(run_dir, schedule)

            self.assertEqual(first["executed_this_batch"], 3)
            self.assertEqual(first["next_sequence"], 4)
            self.assertEqual(second["completed_count"], 3)
            self.assertEqual(second["next_sequence"], 4)

            resumed = run_fake_batch(run_dir=run_dir, schedule=schedule, max_scheduled_calls=2)
            self.assertEqual(resumed["executed_sequences"], [4, 5])
            self.assertEqual(validate_resume_state(run_dir, schedule)["next_sequence"], 6)

    def test_malformed_terminal_result_is_not_retried_after_restart(self) -> None:
        package = load_protocol_package(Path("results/owasp-xss-v14-1-protocol-freeze"))
        schedule = build_execution_schedule(package)[:5]

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            result = run_fake_batch(
                run_dir=run_dir,
                schedule=schedule,
                max_scheduled_calls=4,
                fake_terminal_states={4: "completed_contract_invalid"},
            )
            resumed = run_fake_batch(run_dir=run_dir, schedule=schedule, max_scheduled_calls=1)
            state = validate_resume_state(run_dir, schedule)

            self.assertEqual(result["executed_sequences"], [1, 2, 3, 4])
            self.assertEqual(resumed["executed_sequences"], [5])
            self.assertEqual(state["completed_count"], 5)
            self.assertIsNone(state["next_sequence"])

    def test_corrupt_or_incomplete_artifact_stops_for_audit(self) -> None:
        package = load_protocol_package(Path("results/owasp-xss-v14-1-protocol-freeze"))
        schedule = build_execution_schedule(package)[:2]

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            calls = run_dir / "raw" / "ranking-rows"
            calls.mkdir(parents=True)
            (calls / "sequence-000001.tmp").write_text("partial", encoding="utf-8")

            with self.assertRaises(ResumeAuditRequired):
                validate_resume_state(run_dir, schedule)

    def test_duplicate_journal_sequence_stops_for_audit(self) -> None:
        package = load_protocol_package(Path("results/owasp-xss-v14-1-protocol-freeze"))
        schedule = build_execution_schedule(package)[:2]

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            run_fake_batch(run_dir=run_dir, schedule=schedule, max_scheduled_calls=1)
            journal = run_dir / "execution-journal.jsonl"
            first_line = journal.read_text(encoding="utf-8").splitlines()[0]
            journal.write_text(first_line + "\n" + first_line + "\n", encoding="utf-8")

            with self.assertRaises(ResumeAuditRequired):
                validate_resume_state(run_dir, schedule)

    def test_readiness_package_records_fake_interruption_without_external_calls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)

            report = generate_readiness_package(output_dir=output_dir)

            self.assertTrue(report["valid"], report)
            self.assertEqual(report["external_calls"]["gpt_calls"], 0)
            self.assertEqual(report["external_calls"]["qwen_calls"], 0)
            self.assertEqual(report["external_calls"]["scored_rows"], 0)
            self.assertEqual(report["fake_interruption_test"]["first_batch"]["executed_sequences"], [1, 2, 3])
            self.assertEqual(report["fake_interruption_test"]["resume_batch"]["executed_sequences"], [4])
            self.assertTrue((output_dir / "frozen-execution-schedule.json").exists())
            self.assertTrue((output_dir / "checksums.sha256").exists())
            self.assertTrue((output_dir / "resume-validation-report.json").exists())
            checksum_report = json.loads((output_dir / "checksum-validation-report.json").read_text(encoding="utf-8"))
            self.assertTrue(checksum_report["valid"], checksum_report)


if __name__ == "__main__":
    unittest.main()
