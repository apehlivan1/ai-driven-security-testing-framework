import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.dev_benchmark_server import render_response


class DevelopmentBenchmarkServerTests(unittest.TestCase):
    def test_seed_pages_expose_multiple_neutral_get_candidates(self) -> None:
        status, start = render_response("/start")
        panel_status, panel = render_response("/panel", "item=sample")

        self.assertEqual(status, 200)
        self.assertEqual(panel_status, 200)
        self.assertIn('method="GET" action="/alpha"', start)
        self.assertIn('method="GET" action="/beta"', start)
        self.assertIn('method="GET" action="/gamma"', panel)
        self.assertIn('method="GET" action="/delta"', panel)

    def test_alpha_reflects_without_escaping_for_development_ground_truth(self) -> None:
        payload = "<script>window.__adstfXssMarker='marker'</script>"

        status, body = render_response("/alpha", f"term={payload}")

        self.assertEqual(status, 200)
        self.assertIn(payload, body)

    def test_non_vulnerable_routes_escape_supplied_markup(self) -> None:
        payload = "<script>marker</script>"

        for path, query in [
            ("/beta", f"item={payload}"),
            ("/panel", f"item={payload}"),
            ("/gamma", f"entry={payload}"),
            ("/delta", f"term={payload}&mode={payload}"),
        ]:
            with self.subTest(path=path):
                status, body = render_response(path, query)

                self.assertEqual(status, 200)
                self.assertNotIn(payload, body)
                self.assertIn("&lt;script&gt;", body)


if __name__ == "__main__":
    unittest.main()
