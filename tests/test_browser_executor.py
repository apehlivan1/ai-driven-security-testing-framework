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
        self.extra_headers = None
        self.goto_options = {}

    def route(self, pattern, handler) -> None:
        self.routes.append((pattern, handler))

    def unroute(self, pattern, handler) -> None:
        self.unrouted = True

    def add_init_script(self, script: str) -> None:
        self.init_script = script

    def set_extra_http_headers(self, headers: dict[str, str]) -> None:
        self.extra_headers = headers

    def goto(self, url: str, **options) -> None:
        self.requested_url = url
        self.goto_options = options
        self.url = self.final_url
        return FakeResponse(url, 200)

    def evaluate(self, expression: str) -> bool:
        self.expression = expression
        return self.marker_observed

    def screenshot(self, full_page: bool) -> bytes:
        return b"fake-image"

    def content(self) -> str:
        return "<html>fake</html>"

    def title(self) -> str:
        return "Fake Page"


class FakeResponse:
    def __init__(self, url: str, status: int) -> None:
        self.url = url
        self.status = status


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
            self.assertEqual(evidence.attributes["main_response_status"], 200)
            self.assertTrue((store.run_dir / "artifacts" / "observation.png").exists())
            self.assertTrue((store.run_dir / "artifacts" / "observation.html").exists())

    def test_observe_can_apply_action_scoped_headers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RunArtifactStore(Path(tmp), "run-1")
            store.initialize(self.target)
            page = FakePage("http://lab.local/reflected", marker_observed=True)

            result, evidence = BrowserExecutor(SafetyBoundary(self.target), store).observe(
                header_action("http://lab.local/reflected"),
                page,
            )

            self.assertEqual(result.status, ActionStatus.EXECUTED)
            self.assertEqual(evidence.attributes["request_header_names"], ["X-Test-Input"])
            self.assertEqual(page.extra_headers, {})
            self.assertNotIn("referer", {key.lower() for key in page.goto_options})

    def test_observe_passes_referer_header_through_navigation_options(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RunArtifactStore(Path(tmp), "run-1")
            store.initialize(self.target)
            page = FakePage("http://lab.local/reflected", marker_observed=True)

            result, evidence = BrowserExecutor(SafetyBoundary(self.target), store).observe(
                header_action("http://lab.local/reflected", {"Referer": "marker"}),
                page,
            )

            self.assertEqual(result.status, ActionStatus.EXECUTED)
            self.assertEqual(evidence.attributes["request_header_names"], ["Referer"])
            self.assertEqual(page.goto_options["referer"], "marker")
            self.assertEqual(page.extra_headers, {})

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


def header_action(url: str, headers: dict[str, str] | None = None) -> ActionRequest:
    base = action(url)
    parameters = dict(base.parameters)
    parameters["headers"] = headers or {"X-Test-Input": "marker"}
    return ActionRequest(
        action_id=base.action_id,
        run_id=base.run_id,
        requested_by=base.requested_by,
        module_id=base.module_id,
        action_type=base.action_type,
        target_ref=base.target_ref,
        scope_context=base.scope_context,
        parameters=parameters,
        preconditions=base.preconditions,
        safety_class=base.safety_class,
        rationale=base.rationale,
        expected_evidence=base.expected_evidence,
    )


if __name__ == "__main__":
    unittest.main()
