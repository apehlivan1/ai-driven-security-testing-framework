from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse


@dataclass(frozen=True)
class ReflectedInputCandidate:
    candidate_id: str
    page_url: str
    action_url: str
    method: str
    parameter_name: str
    source: str

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
    }


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
            input_type = values.get("type", "text").lower()
            if name and input_type not in {"submit", "button", "hidden", "reset"}:
                self._form["inputs"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "form" or self._form is None:
            return
        action_url = self._form["action_url"]
        for name in self._form["inputs"]:
            self.candidates.append(
                ReflectedInputCandidate(
                    candidate_id=f"get-form:{action_url}:{name}",
                    page_url=self.page_url,
                    action_url=action_url,
                    method="GET",
                    parameter_name=name,
                    source="get_form",
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
        )
        for name in names
    ]
