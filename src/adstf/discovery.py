from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Callable
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse


TEXT_LIKE_INPUT_TYPES = {"text", "search", "url", "email", "tel", "textarea"}
DETERMINISTIC_RANKING_RULESET_VERSION = "deterministic-structural-v1"
WEAK_GENERIC_PARAMETER_NAMES = {
    "comment",
    "input",
    "message",
    "name",
    "q",
    "query",
    "search",
    "term",
    "text",
}


@dataclass(frozen=True)
class ReflectedInputCandidate:
    candidate_id: str
    page_url: str
    action_url: str
    method: str
    parameter_name: str
    source: str
    input_type: str = "text"
    editable_input_count: int = 1
    required_input_count: int = 0
    parameter_count: int = 1

    def url_with_value(self, value: str) -> str:
        parsed = urlparse(self.action_url)
        pairs = [(key, val) for key, val in parse_qsl(parsed.query, keep_blank_values=True)]
        replaced = False
        updated: list[tuple[str, str]] = []
        for key, val in pairs:
            if key == self.parameter_name:
                updated.append((key, value))
                replaced = True
            else:
                updated.append((key, val))
        if not replaced:
            updated.append((self.parameter_name, value))
        return urlunparse(parsed._replace(query=urlencode(updated)))


@dataclass(frozen=True)
class CandidateRanking:
    candidate: ReflectedInputCandidate
    rank: int
    score: int
    rationale: list[str]
    selected: bool = False


def discover_reflected_input_candidates(page_url: str, html: str) -> list[ReflectedInputCandidate]:
    parser = _GetFormParser(page_url)
    parser.feed(html)
    candidates = parser.candidates
    candidates.extend(_query_parameter_candidates(page_url))
    return candidates


def candidate_to_attributes(candidate: ReflectedInputCandidate) -> dict:
    return {
        "candidate_id": candidate.candidate_id,
        "page_url": candidate.page_url,
        "action_url": candidate.action_url,
        "method": candidate.method,
        "parameter_name": candidate.parameter_name,
        "source": candidate.source,
        "input_type": candidate.input_type,
        "editable_input_count": candidate.editable_input_count,
        "required_input_count": candidate.required_input_count,
        "parameter_count": candidate.parameter_count,
    }


def candidate_ranking_to_attributes(ranking: CandidateRanking) -> dict:
    return {
        **candidate_to_attributes(ranking.candidate),
        "rank": ranking.rank,
        "score": ranking.score,
        "selected": ranking.selected,
        "ranking_rationale": ranking.rationale,
    }


def rank_reflected_input_candidates(
    candidates: list[ReflectedInputCandidate],
    in_scope: Callable[[ReflectedInputCandidate], bool],
) -> list[CandidateRanking]:
    scored = [_score_candidate(candidate, in_scope(candidate)) for candidate in candidates]
    ordered = sorted(
        scored,
        key=lambda item: (
            -item[0],
            _normalized_url_for_tiebreak(item[2].action_url),
            item[2].parameter_name.lower(),
            item[2].source,
            item[2].candidate_id,
        ),
    )
    return [
        CandidateRanking(
            candidate=candidate,
            rank=index + 1,
            score=score,
            rationale=rationale,
            selected=index == 0,
        )
        for index, (score, rationale, candidate) in enumerate(ordered)
    ]


def _score_candidate(
    candidate: ReflectedInputCandidate,
    is_in_scope: bool,
) -> tuple[int, list[str], ReflectedInputCandidate]:
    score = 0
    rationale: list[str] = []
    if is_in_scope:
        score += 100
        rationale.append("candidate action URL is inside the configured target scope")
    else:
        score -= 1000
        rationale.append("candidate action URL is outside the configured target scope")

    if candidate.source == "get_form":
        score += 30
        rationale.append("GET form candidate can be exercised by submitting editable inputs")
    elif candidate.source == "query_parameter":
        score += 10
        rationale.append("existing query parameter candidate is directly replayable")

    if candidate.input_type.lower() in TEXT_LIKE_INPUT_TYPES:
        score += 15
        rationale.append("candidate uses a text-like editable input")

    if candidate.editable_input_count == 1:
        score += 10
        rationale.append("form has a single editable input")
    elif candidate.editable_input_count <= 3:
        score += 5
        rationale.append("form has few editable inputs")

    if candidate.required_input_count == 0:
        score += 5
        rationale.append("candidate does not require additional mandatory inputs")

    if candidate.parameter_name.lower() in WEAK_GENERIC_PARAMETER_NAMES:
        score += 3
        rationale.append("parameter name is a weak generic text-input signal")

    if candidate.method.upper() == "GET":
        score += 2
        rationale.append("candidate uses the allowed GET method")

    return score, rationale, candidate


def _normalized_url_for_tiebreak(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse(
        parsed._replace(
            scheme=parsed.scheme.lower(),
            netloc=parsed.netloc.lower(),
            fragment="",
        )
    )


class _GetFormParser(HTMLParser):
    def __init__(self, page_url: str) -> None:
        super().__init__()
        self.page_url = page_url
        self.candidates: list[ReflectedInputCandidate] = []
        self._form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "form":
            method = values.get("method", "get").lower()
            if method != "get":
                self._form = None
                return
            action = values.get("action") or self.page_url
            self._form = {
                "action_url": urljoin(self.page_url, action),
                "inputs": [],
            }
            return

        if self._form is not None and tag.lower() in {"input", "textarea"}:
            name = values.get("name")
            input_type = "textarea" if tag.lower() == "textarea" else values.get("type", "text").lower()
            if name and input_type not in {"submit", "button", "hidden", "reset", "file", "image"}:
                self._form["inputs"].append(
                    {
                        "name": name,
                        "input_type": input_type,
                        "required": "required" in values,
                    }
                )

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "form" or self._form is None:
            return
        action_url = self._form["action_url"]
        inputs = self._form["inputs"]
        required_input_count = sum(1 for input_data in inputs if input_data["required"])
        for input_data in inputs:
            self.candidates.append(
                ReflectedInputCandidate(
                    candidate_id=f"get-form:{action_url}:{input_data['name']}",
                    page_url=self.page_url,
                    action_url=action_url,
                    method="GET",
                    parameter_name=input_data["name"],
                    source="get_form",
                    input_type=input_data["input_type"],
                    editable_input_count=len(inputs),
                    required_input_count=required_input_count,
                    parameter_count=len(inputs),
                )
            )
        self._form = None


def _query_parameter_candidates(page_url: str) -> list[ReflectedInputCandidate]:
    parsed = urlparse(page_url)
    names = [key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    return [
        ReflectedInputCandidate(
            candidate_id=f"query:{page_url}:{name}",
            page_url=page_url,
            action_url=page_url,
            method="GET",
            parameter_name=name,
            source="query_parameter",
            input_type="query_parameter",
            editable_input_count=1,
            required_input_count=0,
            parameter_count=len(names),
        )
        for name in names
    ]
