import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.openai_ranking_wrapper import build_request_payload, completion_envelope, response_text


class OpenAIRankingWrapperTests(unittest.TestCase):
    def test_build_request_payload_uses_structured_output_without_credentials(self) -> None:
        payload = build_request_payload(
            {"prompt": "rank these", "settings": {"temperature": 0.0}},
            "test-model",
        )

        self.assertEqual(payload["model"], "test-model")
        self.assertNotIn("temperature", payload)
        self.assertEqual(payload["text"]["format"]["type"], "json_schema")
        self.assertNotIn("OPENAI_API_KEY", str(payload))

    def test_response_text_reads_responses_api_output(self) -> None:
        text = response_text(
            {
                "output": [
                    {
                        "content": [
                            {
                                "type": "output_text",
                                "text": '{"ranking":[]}',
                            }
                        ]
                    }
                ]
            }
        )

        self.assertEqual(text, '{"ranking":[]}')

    def test_completion_envelope_keeps_metadata_without_secret_values(self) -> None:
        envelope = completion_envelope(
            {"candidate_input": [{"candidate_id": "a"}]},
            {
                "id": "resp_1",
                "model": "test-model",
                "status": "completed",
                "output_text": '{"ranking":[]}',
                "usage": {"input_tokens": 5, "output_tokens": 2},
            },
            "fallback-model",
            42,
        )

        self.assertEqual(envelope["provider"], "openai")
        self.assertEqual(envelope["model_identifier"], "test-model")
        self.assertEqual(envelope["raw_response"], '{"ranking":[]}')
        self.assertEqual(envelope["latency_ms"], 42)
        self.assertEqual(envelope["usage"]["input_tokens"], 5)
        self.assertNotIn("api_key", str(envelope).lower())


if __name__ == "__main__":
    unittest.main()
