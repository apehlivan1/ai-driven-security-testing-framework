import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.contracts import (
    ActionRequest,
    ActionType,
    EvidenceRecord,
    EvidenceType,
    RedactionStatus,
    SafetyClass,
    TargetConfig,
)
from adstf.dry_run import run_dry_run
from adstf.storage import RunArtifactStore


class StorageAndDryRunTests(unittest.TestCase):
    def test_artifact_store_writes_json_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = TargetConfig(
                name="Lab",
                base_url="http://lab.local",
                allowed_hosts=["lab.local"],
                enabled_modules=["xss.reflected"],
                test_users={"alice": "secret-password"},
            )
            store = RunArtifactStore(Path(tmp), "run-1")
            store.initialize(target)
            action = ActionRequest(
                action_id="action-1",
                run_id="run-1",
                requested_by="test",
                module_id="xss.reflected",
                action_type=ActionType.NAVIGATE,
                target_ref="http://lab.local",
                scope_context={},
                parameters={"url": "http://lab.local"},
                preconditions=[],
                safety_class=SafetyClass.LOW,
                rationale="test",
                expected_evidence=[EvidenceType.HTTP_EXCHANGE],
            )
            evidence = EvidenceRecord(
                evidence_id="evidence-1",
                run_id="run-1",
                source="test",
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                target_ref="http://lab.local",
                created_at="2026-07-18T00:00:00Z",
                summary="test evidence",
                data_ref=None,
                redaction_status=RedactionStatus.ABSENT,
                related_action_ids=["action-1"],
            )

            store.save_action_request(action)
            evidence_path = store.save_evidence(evidence)

            payload = json.loads(evidence_path.read_text(encoding="utf-8"))
            target_payload = json.loads((Path(tmp) / "run-1" / "target.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["evidence_type"], "http_exchange")
            self.assertEqual(target_payload["test_users"]["alice"], "[redacted]")
            self.assertNotIn("secret-password", (Path(tmp) / "run-1" / "target.json").read_text(encoding="utf-8"))
            self.assertTrue((Path(tmp) / "run-1" / "actions" / "action-1.json").exists())

    def test_dry_run_creates_artifacts_and_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = run_dry_run(Path(tmp))

            self.assertTrue((run_dir / "target.json").exists())
            self.assertTrue((run_dir / "report.md").exists())
            self.assertGreater(len(list((run_dir / "actions").glob("*.json"))), 0)
            self.assertGreater(len(list((run_dir / "results").glob("*.json"))), 0)
            self.assertGreater(len(list((run_dir / "evidence").glob("*.json"))), 0)
            self.assertGreater(len(list((run_dir / "findings").glob("*.json"))), 0)
            self.assertGreater(len(list((run_dir / "verification").glob("*.json"))), 0)
            self.assertIn("Mock reflected XSS", (run_dir / "report.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
