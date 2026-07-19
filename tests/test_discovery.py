import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.discovery import discover_reflected_input_candidates


class ReflectedInputDiscoveryTests(unittest.TestCase):
    def test_discovers_simple_get_form_inputs(self) -> None:
        html = """
        <form method="GET" action="/vulnerabilities/xss_r/">
          <input type="text" name="name">
          <input type="submit" value="Submit">
          <input type="hidden" name="user_token" value="abc">
        </form>
        """

        candidates = discover_reflected_input_candidates("http://lab.local/start", html)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].action_url, "http://lab.local/vulnerabilities/xss_r/")
        self.assertEqual(candidates[0].parameter_name, "name")
        self.assertEqual(candidates[0].method, "GET")
        self.assertEqual(candidates[0].source, "get_form")

    def test_discovers_query_parameters_from_seed_url(self) -> None:
        candidates = discover_reflected_input_candidates("http://lab.local/search?q=test", "<html></html>")

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].action_url, "http://lab.local/search?q=test")
        self.assertEqual(candidates[0].parameter_name, "q")
        self.assertEqual(candidates[0].source, "query_parameter")

    def test_candidate_builds_url_with_supplied_value(self) -> None:
        html = '<form method="GET" action="/search"><input name="q"></form>'
        candidate = discover_reflected_input_candidates("http://lab.local/start", html)[0]

        url = candidate.url_with_value("<script>marker</script>")

        self.assertEqual(
            url,
            "http://lab.local/search?q=%3Cscript%3Emarker%3C%2Fscript%3E",
        )

    def test_ignores_non_get_forms(self) -> None:
        html = '<form method="POST" action="/search"><input name="q"></form>'

        candidates = discover_reflected_input_candidates("http://lab.local/start", html)

        self.assertEqual(candidates, [])


if __name__ == "__main__":
    unittest.main()
