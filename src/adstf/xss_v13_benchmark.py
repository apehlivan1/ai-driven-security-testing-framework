from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlparse

from adstf.discovery import DETERMINISTIC_RANKING_RULESET_VERSION, discover_reflected_input_candidates
from adstf.serialization import to_json_value


REPO_ROOT = Path(__file__).resolve().parents[2]
BENCHMARK_ID = "xss-v13-expanded-reflected-input"
MANIFEST_VERSION = "xss-v13-manifest-v1"
GROUND_TRUTH_VERSION = "xss-v13-ground-truth-v1"
STRUCTURAL_VALIDATION_VERSION = "xss-v13-structural-validation-v1"
BASE_PATH = "/suite-v13"
DEFAULT_PORT = 4395
DEFAULT_BASE_URL = f"http://127.0.0.1:{DEFAULT_PORT}"
DEFAULT_MANIFEST_PATH = REPO_ROOT / "examples" / "benchmarks" / "xss-v13-manifest.json"
DEFAULT_GROUND_TRUTH_PATH = REPO_ROOT / "examples" / "benchmarks" / "xss-v13-ground-truth.json"
DEFAULT_TARGET_CONFIG_PATH = REPO_ROOT / "examples" / "targets" / "xss-v13-local.json"
DEFAULT_VALIDATION_DIR = REPO_ROOT / "results" / "xss-v13-structural-validation"
CATALOG_PATH = REPO_ROOT / "docs" / "benchmark-catalog-v1.3.md"
BANNED_NEUTRAL_TERMS = (
    "attack",
    "control",
    "exploit",
    "negative",
    "reflect",
    "safe",
    "script",
    "sink",
    "vuln",
    "xss",
)


@dataclass(frozen=True)
class InputSpec:
    name: str
    behavior: str
    input_type: str = "text"
    required: bool = False


@dataclass(frozen=True)
class FormSpec:
    action_route: str
    inputs: tuple[InputSpec, ...]


@dataclass(frozen=True)
class SeedSpec:
    route: str
    forms: tuple[FormSpec, ...] = ()
    query_inputs: tuple[InputSpec, ...] = ()


@dataclass(frozen=True)
class ScenarioSpec:
    scenario_id: str
    outcome_class: str
    purpose: str
    position_design: str
    structural_challenge: str
    tags: tuple[str, ...]
    seeds: tuple[SeedSpec, ...]
    test_budget: int = 4


def inp(name: str, behavior: str, input_type: str = "text", required: bool = False) -> InputSpec:
    return InputSpec(name, behavior, input_type, required)


def form(action_route: str, *inputs: InputSpec) -> FormSpec:
    return FormSpec(action_route, tuple(inputs))


def seed(
    route: str,
    *,
    forms: FormSpec | tuple[FormSpec, ...] = (),
    query_inputs: InputSpec | tuple[InputSpec, ...] = (),
) -> SeedSpec:
    normalized_forms = (forms,) if isinstance(forms, FormSpec) else forms
    normalized_query_inputs = (query_inputs,) if isinstance(query_inputs, InputSpec) else query_inputs
    return SeedSpec(route, normalized_forms, normalized_query_inputs)


SCENARIOS: tuple[ScenarioSpec, ...] = (
    ScenarioSpec(
        "x13-001",
        "vulnerable",
        "Basic positive control with multiple candidates.",
        "structurally favoured GET text input",
        "one safe reflected distractor",
        ("safe-reflection-distractor", "favoured-positive"),
        (
            seed("north", forms=(form("amber", inp("tone", "raw")), form("birch", inp("memo", "escaped")))),
            seed("cedar", query_inputs=(inp("item", "escaped"),)),
            seed("dune", forms=(form("dune", inp("line", "none")),)),
        ),
    ),
    ScenarioSpec(
        "x13-002",
        "vulnerable",
        "Tests whether ranking over-prefers forms over an existing query parameter.",
        "structurally unfavoured query parameter",
        "forms look more promising than the query parameter",
        ("query-positive", "adversarial-structure"),
        (
            seed("north", forms=(form("lumen", inp("query", "escaped")), form("mason", inp("text", "escaped")))),
            seed("river", forms=(form("noble", inp("name", "none")), form("olive", inp("code", "escaped", required=True)))),
            seed("keel", query_inputs=(inp("ref", "raw"),)),
        ),
    ),
    ScenarioSpec(
        "x13-003",
        "vulnerable",
        "Multi-seed prioritization where the first seed contains safe reflections.",
        "second form on second seed page",
        "first seed contains only safe reflections",
        ("multi-seed", "safe-reflection-distractor"),
        (
            seed("north", forms=(form("atlas", inp("word", "escaped")), form("brook", inp("note", "escaped")))),
            seed("east", forms=(form("cabin", inp("mark", "escaped")), form("delta", inp("line", "raw")))),
            seed("west", query_inputs=(inp("view", "none"), inp("page", "escaped"))),
        ),
    ),
    ScenarioSpec(
        "x13-004",
        "vulnerable",
        "Required-field decoy with a vulnerable optional text field.",
        "required-field form with vulnerable optional field",
        "required decoy looks dominant",
        ("required-field-decoy", "form-structure-decoy"),
        (
            seed("north", forms=(form("echo", inp("name", "escaped", required=True), inp("memo", "raw")),)),
            seed("south", forms=(form("field", inp("query", "escaped")), form("grove", inp("item", "none", required=True)))),
            seed("west", query_inputs=(inp("ref", "escaped"), inp("kind", "none"))),
        ),
    ),
    ScenarioSpec(
        "x13-005",
        "vulnerable",
        "Input-type variation using a textarea candidate.",
        "textarea candidate",
        "several text input distractors",
        ("textarea-positive", "input-type-variation"),
        (
            seed("north", forms=(form("harbor", inp("comment", "raw", "textarea")), form("iris", inp("name", "escaped")))),
            seed("east", forms=(form("juniper", inp("search", "escaped")), form("krypton", inp("title", "none")))),
            seed("south", query_inputs=(inp("memo", "escaped"), inp("ref", "none"), inp("view", "escaped"))),
        ),
    ),
    ScenarioSpec(
        "x13-006",
        "vulnerable",
        "High candidate-count case with a query parameter on a neutral detail page.",
        "query parameter on neutral detail page",
        "many editable form distractors",
        ("high-candidate-count", "query-positive"),
        (
            seed("north", forms=(form("lagoon", inp("query", "escaped")), form("mesa", inp("text", "escaped")))),
            seed("east", forms=(form("nectar", inp("name", "none")), form("onyx", inp("message", "escaped")))),
            seed("detail", query_inputs=(inp("ref", "raw"), inp("page", "escaped"), inp("mode", "none"), inp("kind", "escaped"))),
        ),
    ),
    ScenarioSpec(
        "x13-007",
        "vulnerable",
        "Checks a structurally favoured search input with a query-parameter distractor.",
        "structurally favoured search input",
        "safe reflected query parameter distractor",
        ("favoured-positive", "query-distractor"),
        (
            seed("north", forms=(form("prism", inp("search", "raw", "search")), form("quartz", inp("memo", "escaped")))),
            seed("east", query_inputs=(inp("ref", "escaped"), inp("view", "none"))),
            seed("south", forms=(form("ridge", inp("item", "escaped")),)),
        ),
    ),
    ScenarioSpec(
        "x13-008",
        "vulnerable",
        "Neutral naming under ambiguity.",
        "unfavoured candidate with generic parameter name",
        "parameter names do not reveal intent",
        ("neutral-naming", "adversarial-structure"),
        (
            seed("north", forms=(form("sable", inp("query", "escaped")), form("tango", inp("name", "escaped")))),
            seed("east", forms=(form("umber", inp("line", "none"), inp("memo", "escaped")))),
            seed("south", query_inputs=(inp("item", "raw"), inp("mode", "escaped"))),
        ),
    ),
    ScenarioSpec(
        "x13-009",
        "vulnerable",
        "Escaped-reflection distractor where the actionable form is on the second page.",
        "form action on second page",
        "first page has only escaped reflections",
        ("multi-seed", "escaped-reflection-distractor"),
        (
            seed("north", forms=(form("violet", inp("term", "escaped")), form("willow", inp("note", "escaped")))),
            seed("east", forms=(form("xenon", inp("entry", "raw")),)),
            seed("west", query_inputs=(inp("ref", "escaped"),)),
        ),
    ),
    ScenarioSpec(
        "x13-010",
        "vulnerable",
        "Discovery includes non-reflecting inputs before the vulnerable candidate.",
        "candidate after two non-reflecting candidates",
        "non-reflection decoys",
        ("non-reflection-decoy", "candidate-order"),
        (
            seed("north", forms=(form("yarrow", inp("name", "none")), form("zenith", inp("memo", "none")))),
            seed("east", forms=(form("aurora", inp("text", "raw")), form("benton", inp("line", "escaped")))),
            seed("south", query_inputs=(inp("code", "none"), inp("view", "escaped"), inp("page", "escaped"))),
        ),
    ),
    ScenarioSpec(
        "x13-011",
        "vulnerable",
        "Evidence robustness with a stable-baseline query parameter.",
        "query parameter requiring stable baseline",
        "response shape similar to safe cases",
        ("query-positive", "evidence-robustness"),
        (
            seed("north", forms=(form("cobalt", inp("query", "escaped")), form("drift", inp("memo", "escaped")))),
            seed("east", query_inputs=(inp("line", "raw"), inp("page", "escaped"))),
            seed("south", forms=(form("ember", inp("title", "none")), form("fable", inp("name", "escaped")))),
        ),
    ),
    ScenarioSpec(
        "x13-012",
        "vulnerable",
        "Adversarial structural case where simple ranking signals are misleading.",
        "structurally unfavoured candidate among many safe reflections",
        "simple structural ranking likely misleading",
        ("adversarial-structure", "high-candidate-count"),
        (
            seed("north", forms=(form("garden", inp("search", "escaped", "search")), form("hazel", inp("query", "escaped")))),
            seed("east", forms=(form("islet", inp("name", "escaped")), form("juno", inp("text", "escaped")))),
            seed("south", forms=(form("kepler", inp("message", "none")),)),
            seed("west", query_inputs=(inp("slot", "raw"), inp("page", "escaped"), inp("mode", "escaped"))),
        ),
    ),
    ScenarioSpec(
        "x13-013",
        "vulnerable",
        "Parameter-level distinction inside a multi-input form.",
        "form with two editable fields where only one executes",
        "companion field is escaped",
        ("parameter-level-distinction", "form-structure-decoy"),
        (
            seed("north", forms=(form("larch", inp("memo", "raw"), inp("code", "escaped")),)),
            seed("east", forms=(form("marble", inp("query", "escaped")), form("nova", inp("item", "none")))),
            seed("south", query_inputs=(inp("view", "escaped"),)),
        ),
    ),
    ScenarioSpec(
        "x13-014",
        "vulnerable",
        "Seed order puts safe pages before the vulnerable candidate.",
        "hidden behind seed page ordering",
        "safe page appears first",
        ("seed-order", "multi-seed"),
        (
            seed("north", forms=(form("orbit", inp("search", "escaped")), form("pearl", inp("name", "escaped")))),
            seed("east", query_inputs=(inp("page", "escaped"), inp("kind", "none"))),
            seed("south", forms=(form("quill", inp("line", "raw")), form("raven", inp("memo", "escaped")))),
        ),
    ),
    ScenarioSpec(
        "x13-015",
        "vulnerable",
        "Route-neutral positive case.",
        "safe-looking route with vulnerable field",
        "route name is neutral",
        ("route-neutral", "candidate-order"),
        (
            seed("north", forms=(form("stone", inp("title", "escaped")), form("thistle", inp("comment", "none")))),
            seed("east", forms=(form("upland", inp("message", "raw")),)),
            seed("south", query_inputs=(inp("ref", "escaped"), inp("mode", "none"), inp("page", "escaped"), inp("item", "escaped"))),
        ),
    ),
    ScenarioSpec(
        "x13-016",
        "vulnerable",
        "Ranker-adversarial positive where a safe candidate has stronger generic features.",
        "vulnerable candidate appears after stable safe reflection",
        "safe candidate has stronger generic features",
        ("adversarial-structure", "safe-reflection-distractor"),
        (
            seed("north", forms=(form("valley", inp("search", "escaped", "search")), form("walnut", inp("query", "escaped")))),
            seed("east", forms=(form("yonder", inp("slot", "raw"), inp("memo", "escaped", required=True)),)),
            seed("south", query_inputs=(inp("page", "none"),)),
        ),
    ),
    ScenarioSpec(
        "x13-017",
        "negative",
        "Escaped negative control.",
        "none",
        "all reflections escaped",
        ("negative", "escaped-reflection"),
        (
            seed("north", forms=(form("amber", inp("tone", "escaped")), form("birch", inp("memo", "escaped")))),
            seed("east", query_inputs=(inp("item", "escaped"), inp("line", "escaped"))),
        ),
    ),
    ScenarioSpec(
        "x13-018",
        "negative",
        "Non-reflection negative control.",
        "none",
        "submitted values are not reflected",
        ("negative", "non-reflection"),
        (
            seed("north", forms=(form("cedar", inp("query", "none")), form("dune", inp("text", "none")))),
            seed("east", forms=(form("echo", inp("name", "none")),)),
            seed("south", query_inputs=(inp("ref", "none"), inp("page", "none"))),
        ),
    ),
    ScenarioSpec(
        "x13-019",
        "negative",
        "Multi-seed negative with several safe reflections.",
        "none",
        "multiple safe reflections across seed pages",
        ("negative", "multi-seed"),
        (
            seed("north", forms=(form("field", inp("comment", "escaped", "textarea")), form("grove", inp("search", "escaped")))),
            seed("east", forms=(form("harbor", inp("memo", "escaped")),)),
            seed("south", query_inputs=(inp("code", "escaped"), inp("view", "escaped"), inp("kind", "none"))),
        ),
    ),
    ScenarioSpec(
        "x13-020",
        "negative",
        "High candidate-count negative where all candidates are non-executing.",
        "none",
        "many candidates, all non-executing",
        ("negative", "high-candidate-count"),
        (
            seed("north", forms=(form("iris", inp("query", "escaped")), form("juniper", inp("text", "escaped")))),
            seed("east", forms=(form("krypton", inp("name", "none")), form("lagoon", inp("message", "escaped")))),
            seed("south", query_inputs=(inp("ref", "escaped"), inp("page", "none"), inp("mode", "escaped"))),
        ),
    ),
    ScenarioSpec(
        "x13-021",
        "negative",
        "Decoy-rich negative with required fields and query parameters.",
        "none",
        "required fields and query parameters are decoys",
        ("negative", "required-field-decoy", "query-distractor"),
        (
            seed("north", forms=(form("mesa", inp("name", "escaped", required=True), inp("memo", "escaped")),)),
            seed("east", forms=(form("nectar", inp("query", "none", required=True)), form("onyx", inp("item", "escaped")))),
            seed("south", query_inputs=(inp("code", "escaped"), inp("view", "none"))),
        ),
    ),
    ScenarioSpec(
        "x13-022",
        "negative",
        "Reflection-is-not-execution control.",
        "none",
        "literal-like payload text remains escaped or inert",
        ("negative", "non-executable-reflection"),
        (
            seed("north", forms=(form("prism", inp("line", "escaped")), form("quartz", inp("comment", "textarea")))),
            seed("east", query_inputs=(inp("term", "escaped"), inp("page", "escaped"))),
            seed("south", forms=(form("ridge", inp("title", "none")), form("sable", inp("memo", "escaped")))),
        ),
    ),
    ScenarioSpec(
        "x13-023",
        "negative",
        "Adversarial negative where structurally strong candidates are safe.",
        "none",
        "structurally strong candidates are all safe",
        ("negative", "adversarial-structure", "high-candidate-count"),
        (
            seed("north", forms=(form("tango", inp("search", "escaped", "search")), form("umber", inp("query", "escaped")))),
            seed("east", forms=(form("violet", inp("name", "escaped")), form("willow", inp("text", "none")))),
            seed("south", query_inputs=(inp("ref", "escaped"), inp("page", "none"), inp("mode", "escaped"), inp("kind", "escaped"))),
        ),
    ),
    ScenarioSpec(
        "x13-024",
        "negative",
        "Simple negative sanity case.",
        "none",
        "stable pages with no executable sink",
        ("negative", "sanity-control"),
        (
            seed("north", forms=(form("xenon", inp("memo", "escaped")), form("yarrow", inp("line", "none")))),
            seed("east", query_inputs=(inp("item", "escaped"), inp("view", "none"))),
        ),
    ),
)


class XssV13BenchmarkHandler(BaseHTTPRequestHandler):
    server_version = "ADSTFXssV13Benchmark/0.1"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        status, body, headers = render_v13_xss_response(parsed.path, parsed.query)
        self.send_response(status)
        body_bytes = body.encode("utf-8")
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    def log_message(self, format: str, *args: object) -> None:
        return


def render_v13_xss_response(path: str, query: str = "") -> tuple[int, str, dict[str, str]]:
    if path == f"{BASE_PATH}/health":
        return _html_response(_page("Status", "<main><p>ok</p></main>"))
    if path == f"{BASE_PATH}/reset":
        return _html_response(_page("Reset", "<main><p>state reset</p></main>"))

    scenario, route = _scenario_for_path(path)
    if scenario is None:
        return 404, _page("Not Found", "<main><p>not found</p></main>"), {"Content-Type": "text/html; charset=utf-8"}
    if route == "health":
        return _html_response(_page("Status", f"<main><p>{scenario.scenario_id} ok</p></main>"))
    if route == "reset":
        return _html_response(_page("Reset", f"<main><p>{scenario.scenario_id} reset</p></main>"))

    params = parse_qs(query, keep_blank_values=True)
    seed_spec = next((item for item in scenario.seeds if item.route == route), None)
    if seed_spec is not None:
        body = _render_seed_page(scenario, seed_spec, params)
        return _html_response(_page(f"{scenario.scenario_id} {route}", body))

    body = _render_response_fragments(scenario, route, params)
    if body is None:
        return 404, _page("Not Found", "<main><p>not found</p></main>"), {"Content-Type": "text/html; charset=utf-8"}
    return _html_response(_page(f"{scenario.scenario_id} {route}", body))


def xss_v13_manifest() -> dict:
    scenarios = [_manifest_scenario(scenario) for scenario in SCENARIOS]
    return {
        "benchmark_id": BENCHMARK_ID,
        "manifest_version": MANIFEST_VERSION,
        "description": "Expanded v1.3 reflected-XSS structural benchmark manifest. Semantic ground truth is separate and reserved for post-run evaluation.",
        "ground_truth_available_to_framework": False,
        "ground_truth_path": "examples/benchmarks/xss-v13-ground-truth.json",
        "target_config_path": "examples/targets/xss-v13-local.json",
        "scenario_count": len(scenarios),
        "vulnerable_scenario_count": sum(1 for scenario in scenarios if scenario["outcome_class"] == "vulnerable"),
        "negative_scenario_count": sum(1 for scenario in scenarios if scenario["outcome_class"] == "negative"),
        "candidate_count_bounds": {"min": 4, "max": 8},
        "ranking_ruleset_version": DETERMINISTIC_RANKING_RULESET_VERSION,
        "scenarios": scenarios,
    }


def xss_v13_ground_truth() -> dict:
    return {
        "benchmark_id": BENCHMARK_ID,
        "ground_truth_version": GROUND_TRUTH_VERSION,
        "description": "Semantic ground truth for v1.3 reflected-XSS scenarios. Use only after execution completes.",
        "ground_truth_available_to_framework": False,
        "ranking_ruleset_version": DETERMINISTIC_RANKING_RULESET_VERSION,
        "scenarios": [
            {
                "scenario_id": scenario.scenario_id,
                "expected_vulnerable_count": len(_vulnerable_cases(scenario)),
                "cases": [
                    {
                        "action_path": _action_path(scenario.scenario_id, route),
                        "parameter_name": input_spec.name,
                        "vulnerable": input_spec.behavior == "raw",
                        "behavior": input_spec.behavior,
                    }
                    for route, input_spec in _candidate_specs(scenario)
                ],
            }
            for scenario in SCENARIOS
        ],
    }


def xss_v13_target_config() -> dict:
    return {
        "name": "XSS v1.3 Expanded Reflected-Input Benchmark",
        "base_url": DEFAULT_BASE_URL,
        "allowed_hosts": ["127.0.0.1"],
        "allowed_schemes": ["http"],
        "allowed_ports": [DEFAULT_PORT],
        "enabled_modules": ["xss.reflected"],
        "max_actions": 200,
        "test_users": {},
        "metadata": {
            "benchmark": BENCHMARK_ID,
            "benchmark_version": MANIFEST_VERSION,
            "local_only": True,
            "development_benchmark": True,
            "v13_extended_study": True,
            "scenarios": [
                {
                    "id": scenario.scenario_id,
                    "seed_paths": _seed_paths(scenario),
                    "test_budget": scenario.test_budget,
                }
                for scenario in SCENARIOS
            ],
            "ground_truth_path": "examples/benchmarks/xss-v13-ground-truth.json",
            "notes": "Expanded reflected-XSS benchmark. Ground truth is separate and may be used only during post-run evaluation.",
        },
    }


def load_xss_v13_ground_truth(path: Path = DEFAULT_GROUND_TRUTH_PATH) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_xss_v13_structure(
    *,
    base_url: str = DEFAULT_BASE_URL,
    manifest_path: Path = DEFAULT_MANIFEST_PATH,
    ground_truth_path: Path = DEFAULT_GROUND_TRUTH_PATH,
) -> dict:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    errors: list[str] = []
    scenario_summaries = []
    discovered_counts: list[int] = []

    if manifest.get("scenario_count") != 24:
        errors.append("manifest scenario_count must be 24")
    if manifest.get("vulnerable_scenario_count") != 16:
        errors.append("manifest vulnerable_scenario_count must be 16")
    if manifest.get("negative_scenario_count") != 8:
        errors.append("manifest negative_scenario_count must be 8")
    if [item["id"] for item in manifest.get("scenarios", [])] != [item.scenario_id for item in SCENARIOS]:
        errors.append("manifest scenario order does not match benchmark definitions")

    neutral_errors = neutral_name_errors()
    errors.extend(neutral_errors)

    for scenario in SCENARIOS:
        candidates = []
        for seed_path in _seed_paths(scenario):
            parsed = urlparse(urljoin(f"{base_url.rstrip('/')}/", seed_path))
            _, body, _ = render_v13_xss_response(parsed.path, parsed.query)
            candidates.extend(discover_reflected_input_candidates(parsed.geturl(), body))
        candidate_count = len(candidates)
        discovered_counts.append(candidate_count)
        if candidate_count < 4 or candidate_count > 8:
            errors.append(f"{scenario.scenario_id} has {candidate_count} candidates; expected 4-8")
        expected_count = _candidate_count(scenario)
        if candidate_count != expected_count:
            errors.append(f"{scenario.scenario_id} discovered {candidate_count} candidates but definition expects {expected_count}")
        scenario_summaries.append(
            {
                "scenario_id": scenario.scenario_id,
                "outcome_class": scenario.outcome_class,
                "seed_count": len(scenario.seeds),
                "candidate_count": candidate_count,
                "test_budget": scenario.test_budget,
                "position_design": scenario.position_design,
                "structural_challenge": scenario.structural_challenge,
                "tags": list(scenario.tags),
            }
        )

    outcome_counts = {
        "vulnerable": sum(1 for scenario in SCENARIOS if scenario.outcome_class == "vulnerable"),
        "negative": sum(1 for scenario in SCENARIOS if scenario.outcome_class == "negative"),
    }
    return {
        "validation_id": STRUCTURAL_VALIDATION_VERSION,
        "benchmark_id": BENCHMARK_ID,
        "manifest_version": MANIFEST_VERSION,
        "valid": not errors,
        "errors": errors,
        "scenario_count": len(SCENARIOS),
        "outcome_counts": outcome_counts,
        "candidate_count_distribution": _distribution(discovered_counts),
        "candidate_count_min": min(discovered_counts) if discovered_counts else None,
        "candidate_count_max": max(discovered_counts) if discovered_counts else None,
        "scenario_summaries": scenario_summaries,
        "neutral_name_check": {
            "valid": not neutral_errors,
            "banned_terms": list(BANNED_NEUTRAL_TERMS),
            "errors": neutral_errors,
        },
        "ground_truth_semantics_loaded": False,
        "ground_truth_path": str(ground_truth_path),
        "ground_truth_sha256": sha256_file(ground_truth_path) if ground_truth_path.exists() else None,
    }


def neutral_name_errors() -> list[str]:
    errors: list[str] = []
    for scenario in SCENARIOS:
        for seed_spec in scenario.seeds:
            _check_neutral(seed_spec.route, f"{scenario.scenario_id} seed route", errors)
            for query_input in seed_spec.query_inputs:
                _check_neutral(query_input.name, f"{scenario.scenario_id} query parameter", errors)
            for form_spec in seed_spec.forms:
                _check_neutral(form_spec.action_route, f"{scenario.scenario_id} form action", errors)
                for input_spec in form_spec.inputs:
                    _check_neutral(input_spec.name, f"{scenario.scenario_id} form parameter", errors)
    return errors


def write_xss_v13_static_assets() -> list[Path]:
    files = {
        DEFAULT_MANIFEST_PATH: xss_v13_manifest(),
        DEFAULT_GROUND_TRUTH_PATH: xss_v13_ground_truth(),
        DEFAULT_TARGET_CONFIG_PATH: xss_v13_target_config(),
    }
    written = []
    for path, value in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(to_json_value(value), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written.append(path)
    CATALOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CATALOG_PATH.write_text(render_benchmark_catalog(), encoding="utf-8")
    written.append(CATALOG_PATH)
    return written


def write_xss_v13_structural_validation(output_dir: Path = DEFAULT_VALIDATION_DIR) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = validate_xss_v13_structure()
    files = {
        output_dir / "structural-validation-summary.json": json.dumps(to_json_value(summary), indent=2, sort_keys=True) + "\n",
        output_dir / "structural-validation-report.md": render_structural_validation_report(summary),
        output_dir / "scenario-matrix.csv": render_scenario_matrix_csv(),
        output_dir / "benchmark-summary-table-template.md": render_markdown_summary_table_template(),
        output_dir / "benchmark-summary-table-template.tex": render_latex_summary_table_template(),
    }
    for path, content in files.items():
        path.write_text(content, encoding="utf-8")
    package_manifest = {
        "schema_version": "xss-v13-structural-validation-package-v1",
        "template_status": "structural_validation_only_no_experimental_results",
        "benchmark_id": BENCHMARK_ID,
        "validation_id": STRUCTURAL_VALIDATION_VERSION,
        "included_artifacts": [
            str(path.relative_to(REPO_ROOT))
            for path in [
                DEFAULT_MANIFEST_PATH,
                DEFAULT_GROUND_TRUTH_PATH,
                DEFAULT_TARGET_CONFIG_PATH,
                CATALOG_PATH,
                *files.keys(),
            ]
        ],
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(package_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checksum_paths = [
        DEFAULT_MANIFEST_PATH,
        DEFAULT_GROUND_TRUTH_PATH,
        DEFAULT_TARGET_CONFIG_PATH,
        CATALOG_PATH,
        *files.keys(),
        manifest_path,
    ]
    (output_dir / "checksums.sha256").write_text(render_checksums(checksum_paths), encoding="utf-8")
    if not summary["valid"]:
        raise RuntimeError("xss v1.3 structural validation failed")
    return output_dir


def render_benchmark_catalog() -> str:
    lines = [
        "# Benchmark Catalog v1.3",
        "",
        "Status: scenario design and structural-validation catalog only. This document does not contain experimental results and does not modify frozen v1.2 evidence.",
        "",
        "The v1.3 reflected-XSS benchmark contains 24 independent scenarios: 16 vulnerable scenarios and 8 negative/control scenarios. It is intended for a future deterministic-versus-LLM candidate-ranking ablation study.",
        "",
        "Semantic ground truth is stored separately in `examples/benchmarks/xss-v13-ground-truth.json` and must be loaded only during post-run evaluation. Discovery, ranking, execution and verification components should use the manifest and target configuration, not the semantic ground-truth file.",
        "",
        "| Scenario | Outcome class | Candidates | Seeds | Structural purpose | Structural challenge |",
        "| --- | --- | ---: | ---: | --- | --- |",
    ]
    for scenario in SCENARIOS:
        lines.append(
            f"| `{scenario.scenario_id}` | `{scenario.outcome_class}` | {_candidate_count(scenario)} | {len(scenario.seeds)} | {scenario.purpose} | {scenario.structural_challenge} |"
        )
    lines.extend(
        [
            "",
            "## Notes",
            "",
            "- Route and parameter names are neutral and must not encode expected outcomes.",
            "- Scenario IDs identify benchmark cases only; they do not identify the vulnerable candidate.",
            "- Negative scenarios contain discoverable candidates but no candidate should verify.",
            "- This catalog describes structure, not post-run scoring results.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_structural_validation_report(summary: dict) -> str:
    lines = [
        "# XSS v1.3 Structural Validation Report",
        "",
        "Report status: structural validation only. No ranking, browser vulnerability testing, ZAP scanning, LLM execution, or final scoring was performed.",
        "",
        f"- Valid: `{summary['valid']}`",
        f"- Scenarios: `{summary['scenario_count']}`",
        f"- Vulnerable scenarios: `{summary['outcome_counts']['vulnerable']}`",
        f"- Negative scenarios: `{summary['outcome_counts']['negative']}`",
        f"- Candidate count range: `{summary['candidate_count_min']}` to `{summary['candidate_count_max']}`",
        f"- Candidate-count distribution: `{summary['candidate_count_distribution']}`",
        f"- Ground-truth semantics loaded: `{summary['ground_truth_semantics_loaded']}`",
        "",
        "## Scenario Matrix",
        "",
        "| Scenario | Outcome class | Candidates | Seeds | Structural challenge |",
        "| --- | --- | ---: | ---: | --- |",
    ]
    for item in summary["scenario_summaries"]:
        lines.append(
            f"| `{item['scenario_id']}` | `{item['outcome_class']}` | {item['candidate_count']} | {item['seed_count']} | {item['structural_challenge']} |"
        )
    if summary["errors"]:
        lines.extend(["", "## Errors", ""])
        lines.extend(f"- {error}" for error in summary["errors"])
    return "\n".join(lines) + "\n"


def render_scenario_matrix_csv() -> str:
    rows = [
        {
            "scenario_id": scenario.scenario_id,
            "outcome_class": scenario.outcome_class,
            "candidate_count": _candidate_count(scenario),
            "seed_count": len(scenario.seeds),
            "test_budget": scenario.test_budget,
            "position_design": scenario.position_design,
            "structural_challenge": scenario.structural_challenge,
            "purpose": scenario.purpose,
            "tags": ";".join(scenario.tags),
            "table_status": "scenario_design_only_no_experimental_results",
        }
        for scenario in SCENARIOS
    ]
    output = []
    fieldnames = list(rows[0].keys())
    output.append(",".join(fieldnames))
    for row in rows:
        output.append(",".join(_csv_cell(row[name]) for name in fieldnames))
    return "\n".join(output) + "\n"


def render_markdown_summary_table_template() -> str:
    return """# XSS v1.3 Benchmark Summary Table Template

Template status: scenario design only. No experimental results are recorded here.

| Group | Scenarios | Candidate count range | Notes |
| --- | ---: | --- | --- |
| Vulnerable | 16 | 4-8 | Fill after structural validation package generation. |
| Negative/control | 8 | 4-8 | Fill after structural validation package generation. |
"""


def render_latex_summary_table_template() -> str:
    return r"""% XSS v1.3 benchmark summary table template.
% Template status: scenario design only. No experimental results are recorded here.

\begin{table}[htbp]
\centering
\caption{XSS v1.3 benchmark scenario summary}
\label{tab:xss-v13-benchmark-summary}
\begin{tabular}{lrrl}
\hline
Group & Scenarios & Candidate range & Notes \\
\hline
Vulnerable & 16 & 4--8 & Fill after structural validation. \\
Negative/control & 8 & 4--8 & Fill after structural validation. \\
\hline
\end{tabular}
\end{table}
"""


def render_checksums(paths: list[Path]) -> str:
    return "".join(f"{sha256_file(path)}  {path.relative_to(REPO_ROOT).as_posix()}\n" for path in paths)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_scenario(scenario: ScenarioSpec) -> dict:
    return {
        "id": scenario.scenario_id,
        "outcome_class": scenario.outcome_class,
        "seed_paths": _seed_paths(scenario),
        "candidate_count": _candidate_count(scenario),
        "test_budget": scenario.test_budget,
        "purpose": scenario.purpose,
        "position_design": scenario.position_design,
        "structural_challenge": scenario.structural_challenge,
        "tags": list(scenario.tags),
    }


def _seed_paths(scenario: ScenarioSpec) -> list[str]:
    paths = []
    for seed_spec in scenario.seeds:
        path = _action_path(scenario.scenario_id, seed_spec.route)
        if seed_spec.query_inputs:
            query = "&".join(f"{item.name}=sample" for item in seed_spec.query_inputs)
            path = f"{path}?{query}"
        paths.append(path)
    return paths


def _action_path(scenario_id: str, route: str) -> str:
    return f"{BASE_PATH}/{scenario_id}/{route}"


def _candidate_count(scenario: ScenarioSpec) -> int:
    return sum(len(seed_spec.query_inputs) + sum(len(form_spec.inputs) for form_spec in seed_spec.forms) for seed_spec in scenario.seeds)


def _candidate_specs(scenario: ScenarioSpec) -> list[tuple[str, InputSpec]]:
    specs: list[tuple[str, InputSpec]] = []
    for seed_spec in scenario.seeds:
        specs.extend((seed_spec.route, item) for item in seed_spec.query_inputs)
        for form_spec in seed_spec.forms:
            specs.extend((form_spec.action_route, item) for item in form_spec.inputs)
    return specs


def _vulnerable_cases(scenario: ScenarioSpec) -> list[tuple[str, InputSpec]]:
    return [(route, item) for route, item in _candidate_specs(scenario) if item.behavior == "raw"]


def _scenario_for_path(path: str) -> tuple[ScenarioSpec | None, str]:
    prefix = f"{BASE_PATH}/"
    if not path.startswith(prefix):
        return None, ""
    parts = [part for part in path[len(prefix):].split("/") if part]
    if len(parts) < 2:
        return None, ""
    scenario = next((item for item in SCENARIOS if item.scenario_id == parts[0]), None)
    return scenario, parts[1] if scenario else ""


def _render_seed_page(scenario: ScenarioSpec, seed_spec: SeedSpec, params: dict[str, list[str]]) -> str:
    parts = [f'<main data-scenario="{html.escape(scenario.scenario_id)}">']
    for form_spec in seed_spec.forms:
        parts.append(f'<form method="GET" action="{_action_path(scenario.scenario_id, form_spec.action_route)}">')
        for input_spec in form_spec.inputs:
            required = " required" if input_spec.required else ""
            if input_spec.input_type == "textarea":
                parts.append(f'<label>{html.escape(input_spec.name)} <textarea name="{html.escape(input_spec.name)}"{required}></textarea></label>')
            else:
                parts.append(f'<label>{html.escape(input_spec.name)} <input type="{html.escape(input_spec.input_type)}" name="{html.escape(input_spec.name)}"{required}></label>')
        parts.append('<button type="submit">Open</button></form>')
    fragments = _render_response_fragments(scenario, seed_spec.route, params)
    if fragments:
        parts.append(fragments)
    parts.append("</main>")
    return "\n".join(parts)


def _render_response_fragments(scenario: ScenarioSpec, route: str, params: dict[str, list[str]]) -> str | None:
    route_specs = [item for spec_route, item in _candidate_specs(scenario) if spec_route == route]
    if not route_specs:
        return None
    parts = ["<main>"]
    for input_spec in route_specs:
        value = _first(params, input_spec.name)
        parts.append(_render_behavior(input_spec.behavior, value))
    parts.append("</main>")
    return "\n".join(parts)


def _render_behavior(behavior: str, value: str) -> str:
    if behavior == "raw":
        return f"<section>{value}</section>"
    if behavior == "escaped":
        return f"<section>{html.escape(value)}</section>"
    if behavior == "textarea":
        return f"<textarea>{html.escape(value)}</textarea>"
    if behavior == "none":
        return "<section>record accepted</section>"
    raise ValueError(f"unknown behavior: {behavior}")


def _html_response(body: str) -> tuple[int, str, dict[str, str]]:
    return 200, body, {"Content-Type": "text/html; charset=utf-8"}


def _page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{html.escape(title)}</title>
</head>
<body>
{body}
</body>
</html>
"""


def _first(params: dict[str, list[str]], name: str) -> str:
    values = params.get(name, [""])
    return values[0] if values else ""


def _distribution(values: list[int]) -> dict[str, int]:
    distribution: dict[str, int] = {}
    for value in values:
        key = str(value)
        distribution[key] = distribution.get(key, 0) + 1
    return dict(sorted(distribution.items()))


def _check_neutral(value: str, context: str, errors: list[str]) -> None:
    lowered = value.lower()
    for term in BANNED_NEUTRAL_TERMS:
        if term in lowered:
            errors.append(f"{context} contains banned outcome hint {term!r}: {value}")


def _csv_cell(value: object) -> str:
    text = str(value)
    if any(character in text for character in [",", '"', "\n"]):
        return '"' + text.replace('"', '""') + '"'
    return text


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve or structurally validate the XSS v1.3 benchmark.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve_parser = subparsers.add_parser("serve", help="Start the local XSS v1.3 benchmark server.")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=DEFAULT_PORT)

    subparsers.add_parser("write-assets", help="Write versioned manifest, ground truth, target config and catalog.")

    validate_parser = subparsers.add_parser("validate", help="Write structural validation artifacts.")
    validate_parser.add_argument("--output-dir", type=Path, default=DEFAULT_VALIDATION_DIR)

    args = parser.parse_args()
    if args.command == "serve":
        server = ThreadingHTTPServer((args.host, args.port), XssV13BenchmarkHandler)
        print(f"XSS v1.3 benchmark listening on http://{args.host}:{args.port}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    elif args.command == "write-assets":
        for path in write_xss_v13_static_assets():
            print(path)
    else:
        write_xss_v13_static_assets()
        output_dir = write_xss_v13_structural_validation(args.output_dir)
        print(f"XSS v1.3 structural validation artifacts written to: {output_dir}")


if __name__ == "__main__":
    main()
