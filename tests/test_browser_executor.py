import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.browser import BrowserExecutor
from adstf.contracts import ActionRequest, ActionStatus, ActionType, EvidenceType, SafetyClass, TargetConfig
from adstf.safety import SafetyBoundary
from adstf.storage import RunArtifactStore


class FakePage:
    def __init__(self, final_url: str, marker_observed: bool = True) -> None:
        self.url = "about:blank"
        self.final_url = final_url
        self.marker_observed = marker_observed
        self.routes = []
        self.unrouted = False

    def route(self, pattern, handler) -> None:
        self.routes.append((pattern, handler))

    def unroute(self, pattern, handler) -> None:
        self.unrouted = True

    def add_init_script(self, script: str) -> None:
        self.init_script = script

    def goto(self, url: str, wait_until: str) -> None:
        self.requested_url = url
        self.url = self.final_url

    def evaluate(self, expression: str) -> bool:
        self.expression = expression
        return self.marker_observed

    def screenshot(self, full_page: bool) -> bytes:
        return b"fake-image"

    def content(self) -> str:
        return "<html>fake</html>"

    def title(self) -> str:
        return "Fake Page"


def action(url: str) -> ActionRequest:
    return ActionRequest(
        action_id="action-1",
        run_id="run-1",
        requested_by="test",
        module_id="xss.reflected",
        action_type=ActionType.OBSERVE_BROWSER,
        target_ref=url,
        scope_context={},
        parameters={
            "url": url,
            "marker_variable": "__adstfXssMarker",
            "expected_marker": "marker",
            "artifact_prefix": "observation",
        },
        preconditions=[],
        safety_class=SafetyClass.LOW,
        rationale="test browser observation",
        expected_evidence=[EvidenceType.BROWSER_OBSERVATION],
    )


class BrowserExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target = TargetConfig(
            name="Lab",
            base_url="http://lab.local",
            allowed_hosts=["lab.local"],
            allowed_ports=[80],
            enabled_modules=["xss.reflected"],
        )

    def test_observe_records_browser_evidence_and_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RunArtifactStore(Path(tmp), "run-1")
            store.initialize(self.target)
            page = FakePage("http://lab.local/reflected", marker_observed=True)

            result, evidence = BrowserExecutor(SafetyBoundary(self.target), store).observe(
                action("http://lab.local/reflected"),
                page,
            )

            self.assertEqual(result.status, ActionStatus.EXECUTED)
            self.assertEqual(evidence.evidence_type, EvidenceType.BROWSER_OBSERVATION)
            self.assertTrue(evidence.attributes["execution_marker_observed"])
            self.assertEqual(evidence.attributes["final_url"], "http://lab.local/reflected")
            self.assertTrue((store.run_dir / "artifacts" / "observation.png").exists())
            self.assertTrue((store.run_dir / "artifacts" / "observation.html").exists())

    def test_observe_fails_when_final_url_leaves_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RunArtifactStore(Path(tmp), "run-1")
            store.initialize(self.target)
            page = FakePage("http://outside.example/reflected", marker_observed=True)

            result, evidence = BrowserExecutor(SafetyBoundary(self.target), store).observe(
                action("http://lab.local/redirect"),
                page,
            )

            self.assertEqual(result.status, ActionStatus.FAILED)
            self.assertEqual(evidence.evidence_type, EvidenceType.BLOCKED_ACTION)
            self.assertIn("not in the target allowlist", result.error or "")


if __name__ == "__main__":
    unittest.main()
