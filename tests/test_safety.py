import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.contracts import ActionRequest, ActionType, EvidenceType, SafetyClass, TargetConfig
from adstf.safety import SafetyBoundary


def action(url: str, module_id: str = "xss.reflected") -> ActionRequest:
    return ActionRequest(
        action_id="action-1",
        run_id="run-1",
        requested_by="test",
        module_id=module_id,
        action_type=ActionType.NAVIGATE,
        target_ref=url,
        scope_context={},
        parameters={"url": url},
        preconditions=[],
        safety_class=SafetyClass.LOW,
        rationale="test action",
        expected_evidence=[EvidenceType.HTTP_EXCHANGE],
    )


class SafetyBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target = TargetConfig(
            name="Lab",
            base_url="http://lab.local",
            allowed_hosts=["lab.local"],
            allowed_ports=[80],
            enabled_modules=["xss.reflected"],
        )
        self.safety = SafetyBoundary(self.target)

    def test_approves_in_scope_action(self) -> None:
        decision = self.safety.evaluate(action("http://lab.local/search"))

        self.assertTrue(decision.approved)
        self.assertEqual(decision.reasons, [])

    def test_blocks_out_of_scope_host(self) -> None:
        decision = self.safety.evaluate(action("http://outside.example/search"))

        self.assertFalse(decision.approved)
        self.assertIn("host 'outside.example' is not in the target allowlist", decision.reasons)

    def test_blocks_disabled_module(self) -> None:
        decision = self.safety.evaluate(action("http://lab.local/search", "sqli.boolean"))

        self.assertFalse(decision.approved)
        self.assertIn("module 'sqli.boolean' is not enabled for this run", decision.reasons)


if __name__ == "__main__":
    unittest.main()
