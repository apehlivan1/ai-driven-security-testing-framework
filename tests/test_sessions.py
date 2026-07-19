import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.sessions import SessionRegistry, session_context_evidence


class SessionRegistryTests(unittest.TestCase):
    def test_sessions_are_isolated_by_reference(self) -> None:
        registry = SessionRegistry()
        first = registry.add_cookie_session(
            user_label="user_a",
            username="atlas",
            cookie_name="adstf_session",
            token="token-a",
        )
        second = registry.add_cookie_session(
            user_label="user_b",
            username="blair",
            cookie_name="adstf_session",
            token="token-b",
        )

        self.assertNotEqual(first.session_ref, second.session_ref)
        self.assertIn("token-a", registry.headers_for(first.session_ref)["Cookie"])
        self.assertIn("token-b", registry.headers_for(second.session_ref)["Cookie"])

    def test_session_context_evidence_redacts_token(self) -> None:
        registry = SessionRegistry()
        record = registry.add_cookie_session(
            user_label="user_a",
            username="atlas",
            cookie_name="adstf_session",
            token="super-secret-token",
        )

        evidence = session_context_evidence(
            run_id="run-1",
            record=record,
            related_action_ids=["action-1"],
        )
        serialized = str(evidence)

        self.assertTrue(evidence.attributes["token_redacted"])
        self.assertTrue(evidence.attributes["credential_redacted"])
        self.assertIn("token_sha256", evidence.attributes)
        self.assertNotIn("super-secret-token", serialized)


if __name__ == "__main__":
    unittest.main()
