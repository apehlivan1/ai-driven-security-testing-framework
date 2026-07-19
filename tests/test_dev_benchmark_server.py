import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.dev_benchmark_server import _idor_get_response, _idor_login_response, render_response


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

    def test_named_scenarios_are_reproducible_on_same_server(self) -> None:
        for scenario in ["case-b", "case-c", "case-d"]:
            with self.subTest(scenario=scenario):
                status, body = render_response(f"/s/{scenario}/start")

                self.assertEqual(status, 200)
                self.assertIn('method="GET"', body)

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

    def test_case_b_vulnerable_candidate_is_not_structurally_first(self) -> None:
        payload = "<script>window.__adstfXssMarker='marker'</script>"

        non_vulnerable_status, non_vulnerable = render_response("/s/case-b/kappa", f"query={payload}")
        vulnerable_status, vulnerable = render_response("/s/case-b/lambda", f"entry={payload}&trace=sample")

        self.assertEqual(non_vulnerable_status, 200)
        self.assertEqual(vulnerable_status, 200)
        self.assertNotIn(payload, non_vulnerable)
        self.assertIn(payload, vulnerable)

    def test_case_c_has_no_vulnerable_reflection(self) -> None:
        payload = "<script>window.__adstfXssMarker='marker'</script>"

        for path, query in [
            ("/s/case-c/north", f"name={payload}"),
            ("/s/case-c/east", f"input={payload}"),
            ("/s/case-c/south", f"comment={payload}"),
            ("/s/case-c/west", f"term={payload}"),
        ]:
            with self.subTest(path=path):
                status, body = render_response(path, query)

                self.assertEqual(status, 200)
                self.assertNotIn(payload, body)

    def test_idor_login_returns_cookie_without_token_in_body(self) -> None:
        status, body, headers = _idor_login_response("username=atlas&password=atlas-password")

        self.assertEqual(status, 200)
        self.assertIn("Set-Cookie", headers)
        self.assertNotIn("token-atlas-development", body)

    def test_idor_open_route_allows_cross_user_read_for_development_case(self) -> None:
        status, body, _ = _idor_get_response(
            "/idor/open",
            "rid=n-104",
            "adstf_session=token-blair-development",
        )

        self.assertEqual(status, 200)
        self.assertIn("user_a", body)
        self.assertIn("ledger-alpha-owned-by-user-a", body)

    def test_idor_guarded_route_blocks_cross_user_read_for_control_case(self) -> None:
        status, body, _ = _idor_get_response(
            "/idor/guarded",
            "rid=n-306",
            "adstf_session=token-blair-development",
        )

        self.assertEqual(status, 403)
        self.assertIn("not authorized", body)


if __name__ == "__main__":
    unittest.main()
