import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.contracts import ActionRequest, ActionStatus, ActionType, EvidenceType, SafetyClass, TargetConfig
from adstf.execution import HttpExecutor
from adstf.safety import SafetyBoundary
from adstf.sessions import SessionRegistry


class SmokeHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/cookie":
            if self.headers.get("Cookie") != "adstf_session=secret-token":
                self.send_response(401)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"content_marker":"private"}')
            return
        if self.path == "/redirect-safe":
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.end_headers()
            return
        if self.path == "/redirect-unsafe":
            self.send_response(302)
            self.send_header("Location", "http://example.com/")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format: str, *args) -> None:
        return


class HttpExecutorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), SmokeHandler)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        self.target = TargetConfig(
            name="Local Test Server",
            base_url=f"http://127.0.0.1:{self.port}",
            allowed_hosts=["127.0.0.1"],
            allowed_schemes=["http"],
            allowed_ports=[self.port],
            enabled_modules=["xss.reflected"],
        )
        self.executor = HttpExecutor(SafetyBoundary(self.target))

    def action(self, url: str) -> ActionRequest:
        return ActionRequest(
            action_id="action-1",
            run_id="run-1",
            requested_by="test",
            module_id=None,
            action_type=ActionType.REPLAY_REQUEST,
            target_ref=url,
            scope_context={},
            parameters={"method": "GET", "url": url},
            preconditions=[],
            safety_class=SafetyClass.LOW,
            rationale="test HTTP action",
            expected_evidence=[EvidenceType.HTTP_EXCHANGE],
        )

    def test_executes_in_scope_http_request_and_normalizes_evidence(self) -> None:
        result, evidence = self.executor.execute(self.action(f"http://127.0.0.1:{self.port}/ok"))

        self.assertEqual(result.status, ActionStatus.EXECUTED)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].evidence_type, EvidenceType.HTTP_EXCHANGE)
        self.assertEqual(evidence[0].attributes["status_code"], 200)
        self.assertEqual(evidence[0].attributes["body_length"], 2)
        self.assertIn("body_sha256", evidence[0].attributes)

    def test_blocks_out_of_scope_http_request_before_execution(self) -> None:
        result, evidence = self.executor.execute(self.action("http://example.com/"))

        self.assertEqual(result.status, ActionStatus.BLOCKED)
        self.assertEqual(evidence[0].evidence_type, EvidenceType.BLOCKED_ACTION)
        self.assertIn("not in the target allowlist", result.safety_notes[0])

    def test_allows_safe_redirect(self) -> None:
        result, evidence = self.executor.execute(
            self.action(f"http://127.0.0.1:{self.port}/redirect-safe")
        )

        self.assertEqual(result.status, ActionStatus.EXECUTED)
        self.assertEqual(evidence[0].attributes["status_code"], 200)
        self.assertEqual(len(evidence[0].attributes["redirect_chain"]), 1)
        self.assertTrue(evidence[0].attributes["redirect_chain"][0]["approved"])

    def test_blocks_unsafe_redirect(self) -> None:
        result, evidence = self.executor.execute(
            self.action(f"http://127.0.0.1:{self.port}/redirect-unsafe")
        )

        self.assertEqual(result.status, ActionStatus.FAILED)
        self.assertIn("redirect blocked by safety boundary", result.error or "")
        self.assertEqual(evidence[0].evidence_type, EvidenceType.BLOCKED_ACTION)

    def test_injects_session_headers_without_persisting_cookie_in_action(self) -> None:
        registry = SessionRegistry()
        session = registry.add_cookie_session(
            user_label="user_a",
            username="atlas",
            cookie_name="adstf_session",
            token="secret-token",
        )
        executor = HttpExecutor(SafetyBoundary(self.target), session_registry=registry)
        action = self.action(f"http://127.0.0.1:{self.port}/cookie")
        action.parameters["session_ref"] = session.session_ref
        action.parameters["capture_body_text"] = True

        result, evidence = executor.execute(action)

        self.assertEqual(result.status, ActionStatus.EXECUTED)
        self.assertEqual(evidence[0].attributes["status_code"], 200)
        self.assertIn("private", evidence[0].attributes["body_text"])
        self.assertNotIn("secret-token", str(action))


if __name__ == "__main__":
    unittest.main()
