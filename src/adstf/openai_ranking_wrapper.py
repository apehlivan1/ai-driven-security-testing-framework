from __future__ import annotations

import json
import os
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


PROVIDER_NAME = "openai"
DEFAULT_MODEL = "gpt-5-nano"
DEFAULT_BASE_URL = "https://api.openai.com/v1"


def build_request_payload(command_request: dict, model: str) -> dict:
    settings = dict(command_request.get("settings", {}))
    payload = {
        "model": model,
        "input": [
            {
                "role": "user",
                "content": str(command_request["prompt"]),
            }
        ],
        "text": {
            "format": {
                "type": "json_schema",
                "name": "candidate_ranking",
                "strict": True,
                "schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "ranking": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": False,
                                "properties": {
                                    "candidate_id": {"type": "string"},
                                    "rationale": {"type": "string"},
                                },
                                "required": ["candidate_id", "rationale"],
                            },
                        }
                    },
                    "required": ["ranking"],
                },
            }
        },
    }
    if "temperature" in settings and _send_temperature():
        payload["temperature"] = float(settings["temperature"])
    if "max_output_tokens" in settings:
        payload["max_output_tokens"] = int(settings["max_output_tokens"])
    else:
        payload["max_output_tokens"] = 1200
    return payload


def response_text(response_data: dict) -> str:
    if isinstance(response_data.get("output_text"), str):
        return response_data["output_text"]
    chunks: list[str] = []
    for output in response_data.get("output", []):
        if not isinstance(output, dict):
            continue
        for content in output.get("content", []):
            if not isinstance(content, dict):
                continue
            if isinstance(content.get("text"), str):
                chunks.append(content["text"])
            elif isinstance(content.get("output_text"), str):
                chunks.append(content["output_text"])
    return "".join(chunks)


def completion_envelope(command_request: dict, response_data: dict, model: str, latency_ms: int) -> dict:
    return {
        "provider": PROVIDER_NAME,
        "model_identifier": response_data.get("model", model),
        "raw_response": response_text(response_data),
        "usage": response_data.get("usage"),
        "cost": None,
        "latency_ms": latency_ms,
        "metadata": {
            "response_id": response_data.get("id"),
            "status": response_data.get("status"),
            "base_url": _redacted_base_url(),
            "candidate_count": len(command_request.get("candidate_input", [])),
        },
    }


def main() -> None:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("OPENAI_API_KEY is required in the environment", file=sys.stderr)
        raise SystemExit(2)

    model = os.environ.get("OPENAI_RANKING_MODEL", DEFAULT_MODEL)
    base_url = os.environ.get("OPENAI_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
    try:
        command_request = json.loads(sys.stdin.read())
        payload = build_request_payload(command_request, model)
        started = time.perf_counter()
        request = Request(
            f"{base_url}/responses",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urlopen(request, timeout=float(os.environ.get("OPENAI_TIMEOUT_SECONDS", "60"))) as response:
            response_data = json.loads(response.read().decode("utf-8"))
        latency_ms = int((time.perf_counter() - started) * 1000)
    except HTTPError as exc:
        message = _safe_http_error_message(exc)
        print(message, file=sys.stderr)
        raise SystemExit(1) from exc
    except (URLError, TimeoutError, json.JSONDecodeError, KeyError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc

    print(json.dumps(completion_envelope(command_request, response_data, model, latency_ms)))


def _safe_http_error_message(exc: HTTPError) -> str:
    try:
        body = exc.read().decode("utf-8", errors="replace")
    finally:
        exc.close()
    return f"OpenAI API HTTP {exc.code}: {body[:1000]}"


def _redacted_base_url() -> str:
    return os.environ.get("OPENAI_BASE_URL", DEFAULT_BASE_URL).rstrip("/")


def _send_temperature() -> bool:
    return os.environ.get("OPENAI_SEND_TEMPERATURE", "").lower() in {"1", "true", "yes"}


if __name__ == "__main__":
    main()
