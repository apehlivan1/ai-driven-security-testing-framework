import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.discovery import ReflectedInputCandidate, discover_reflected_input_candidates, rank_reflected_input_candidates


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
        self.assertEqual(candidates[0].input_type, "text")
        self.assertEqual(candidates[0].editable_input_count, 1)
        self.assertEqual(candidates[0].required_input_count, 0)
        self.assertEqual(candidates[0].parameter_count, 1)

    def test_discovers_form_input_structure(self) -> None:
        html = """
        <form method="GET" action="/search">
          <input type="search" name="q" required>
          <textarea name="comment"></textarea>
          <input type="submit" value="Submit">
        </form>
        """

        candidates = discover_reflected_input_candidates("http://lab.local/start", html)

        self.assertEqual(len(candidates), 2)
        self.assertEqual(candidates[0].input_type, "search")
        self.assertEqual(candidates[0].editable_input_count, 2)
        self.assertEqual(candidates[0].required_input_count, 1)
        self.assertEqual(candidates[0].parameter_count, 2)

    def test_discovers_query_parameters_from_seed_url(self) -> None:
        candidates = discover_reflected_input_candidates("http://lab.local/search?q=test", "<html></html>")

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].action_url, "http://lab.local/search?q=test")
        self.assertEqual(candidates[0].parameter_name, "q")
        self.assertEqual(candidates[0].source, "query_parameter")
        self.assertEqual(candidates[0].input_type, "query_parameter")
        self.assertEqual(candidates[0].parameter_count, 1)

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

    def test_ranking_prefers_in_scope_simple_get_form(self) -> None:
        candidates = [
            ReflectedInputCandidate(
                candidate_id="query",
                page_url="http://lab.local/search?q=test",
                action_url="http://lab.local/search?q=test",
                method="GET",
                parameter_name="q",
                source="query_parameter",
                input_type="query_parameter",
            ),
            ReflectedInputCandidate(
                candidate_id="form",
                page_url="http://lab.local/start",
                action_url="http://lab.local/search",
                method="GET",
                parameter_name="q",
                source="get_form",
                input_type="search",
            ),
        ]

        rankings = rank_reflected_input_candidates(candidates, lambda candidate: True)

        self.assertEqual(rankings[0].candidate.candidate_id, "form")
        self.assertTrue(rankings[0].selected)
        self.assertGreater(rankings[0].score, rankings[1].score)
        self.assertTrue(rankings[0].rationale)

    def test_ranking_uses_deterministic_tie_breaking(self) -> None:
        candidates = [
            ReflectedInputCandidate(
                candidate_id="b",
                page_url="http://lab.local/start",
                action_url="http://lab.local/b",
                method="GET",
                parameter_name="q",
                source="get_form",
                input_type="text",
            ),
            ReflectedInputCandidate(
                candidate_id="a",
                page_url="http://lab.local/start",
                action_url="http://lab.local/a",
                method="GET",
                parameter_name="q",
                source="get_form",
                input_type="text",
            ),
        ]

        rankings = rank_reflected_input_candidates(candidates, lambda candidate: True)

        self.assertEqual([ranking.candidate.candidate_id for ranking in rankings], ["a", "b"])

    def test_ranking_does_not_boost_benchmark_route_hints(self) -> None:
        hinted = ReflectedInputCandidate(
            candidate_id="hinted",
            page_url="http://lab.local/vulnerabilities/xss_r/",
            action_url="http://lab.local/vulnerabilities/xss_r/",
            method="GET",
            parameter_name="q",
            source="get_form",
            input_type="text",
        )
        neutral = ReflectedInputCandidate(
            candidate_id="neutral",
            page_url="http://lab.local/neutral/",
            action_url="http://lab.local/neutral/",
            method="GET",
            parameter_name="q",
            source="get_form",
            input_type="text",
        )

        rankings = rank_reflected_input_candidates([hinted, neutral], lambda candidate: True)

        self.assertEqual(rankings[0].score, rankings[1].score)
        self.assertEqual(rankings[0].candidate.candidate_id, "neutral")
        self.assertFalse(
            any("xss" in reason.lower() or "reflect" in reason.lower() for ranking in rankings for reason in ranking.rationale)
        )


if __name__ == "__main__":
    unittest.main()
