from __future__ import annotations

import argparse
import html
import json
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


@dataclass(frozen=True)
class Reflection:
    parameter: str
    escaped: bool


SCENARIOS = {"case-a", "case-b", "case-c", "case-d"}
IDOR_USERS = {
    "atlas": {"password": "atlas-password", "label": "user_a"},
    "blair": {"password": "blair-password", "label": "user_b"},
}
IDOR_TOKENS = {
    "token-atlas-development": "user_a",
    "token-blair-development": "user_b",
}
IDOR_RESOURCES = {
    "n-104": {
        "owner": "user_a",
        "content_marker": "ledger-alpha-owned-by-user-a",
        "endpoint": "open",
    },
    "n-205": {
        "owner": "user_b",
        "content_marker": "ledger-beta-owned-by-user-b",
        "endpoint": "open",
    },
    "n-306": {
        "owner": "user_a",
        "content_marker": "ledger-gamma-owned-by-user-a",
        "endpoint": "guarded",
    },
}


def render_response(path: str, query: str = "") -> tuple[int, str]:
    scenario_id, route = _split_scenario_path(path)
    params = parse_qs(query, keep_blank_values=True)
    if route == "/health":
        return 200, _page("Status", "<p>ok</p>")
    if route == "/reset":
        return 200, _page("Reset", "<p>state reset</p>")
    if scenario_id == "case-a":
        return _case_a(route, params, scenario_id)
    if scenario_id == "case-b":
        return _case_b(route, params, scenario_id)
    if scenario_id == "case-c":
        return _case_c(route, params, scenario_id)
    if scenario_id == "case-d":
        return _case_d(route, params, scenario_id)
    return 404, _page("Not Found", "<p>not found</p>")


def _case_a(route: str, params: dict[str, list[str]], scenario_id: str) -> tuple[int, str]:
    prefix = _prefix(scenario_id)
    if route in {"", "/"}:
        return 200, _page("Index", f'<main><a href="{prefix}/start">Start</a></main>')
    if route == "/start":
        return 200, _page(
            "Start",
            f"""
            <main>
              <form method="GET" action="{prefix}/alpha">
                <label>Term <input type="text" name="term"></label>
                <button type="submit">Open</button>
              </form>
              <form method="GET" action="{prefix}/beta">
                <label>Item <input type="text" name="item"></label>
                <button type="submit">Open</button>
              </form>
              <a href="{prefix}/panel?item=sample">More options</a>
            </main>
            """,
        )
    if route == "/panel":
        item = html.escape(_first(params, "item"))
        return 200, _page(
            "Panel",
            f"""
            <main>
              <p>Current item: {item}</p>
              <form method="GET" action="{prefix}/gamma">
                <label>Entry <input type="text" name="entry" required></label>
                <button type="submit">Open</button>
              </form>
              <form method="GET" action="{prefix}/delta">
                <label>Term <input type="text" name="term"></label>
                <label>Mode <input type="text" name="mode"></label>
                <button type="submit">Open</button>
              </form>
            </main>
            """,
        )
    if route == "/alpha":
        return _reflected_page("Alpha", params, Reflection("term", escaped=False))
    if route == "/beta":
        return _reflected_page("Beta", params, Reflection("item", escaped=True))
    if route == "/gamma":
        return _textarea_page("Gamma", params, Reflection("entry", escaped=True))
    if route == "/delta":
        return _two_value_page("Delta", params, Reflection("term", escaped=True), Reflection("mode", escaped=True))
    return 404, _page("Not Found", "<p>not found</p>")


def _case_b(route: str, params: dict[str, list[str]], scenario_id: str) -> tuple[int, str]:
    prefix = _prefix(scenario_id)
    if route in {"", "/"}:
        return 200, _page("Index", f'<main><a href="{prefix}/start">Start</a></main>')
    if route == "/start":
        return 200, _page(
            "Start",
            f"""
            <main>
              <form method="GET" action="{prefix}/kappa">
                <label>Query <input type="search" name="query"></label>
                <button type="submit">Open</button>
              </form>
              <form method="GET" action="{prefix}/lambda">
                <label>Entry <input type="text" name="entry" required></label>
                <label>Trace <input type="text" name="trace"></label>
                <button type="submit">Open</button>
              </form>
            </main>
            """,
        )
    if route == "/panel":
        return 200, _page(
            "Panel",
            f"""
            <main>
              <form method="GET" action="{prefix}/mu">
                <label>Text <input type="text" name="text"></label>
                <button type="submit">Open</button>
              </form>
              <a href="{prefix}/nu?code=sample">Details</a>
            </main>
            """,
        )
    if route == "/kappa":
        return _reflected_page("Kappa", params, Reflection("query", escaped=True))
    if route == "/lambda":
        return _two_value_page("Lambda", params, Reflection("entry", escaped=False), Reflection("trace", escaped=True))
    if route == "/mu":
        return _reflected_page("Mu", params, Reflection("text", escaped=True))
    if route == "/nu":
        return _reflected_page("Nu", params, Reflection("code", escaped=True))
    return 404, _page("Not Found", "<p>not found</p>")


def _case_c(route: str, params: dict[str, list[str]], scenario_id: str) -> tuple[int, str]:
    prefix = _prefix(scenario_id)
    if route in {"", "/"}:
        return 200, _page("Index", f'<main><a href="{prefix}/start">Start</a></main>')
    if route == "/start":
        return 200, _page(
            "Start",
            f"""
            <main>
              <form method="GET" action="{prefix}/north">
                <label>Name <input type="text" name="name"></label>
                <button type="submit">Open</button>
              </form>
              <form method="GET" action="{prefix}/east">
                <label>Input <input type="text" name="input"></label>
                <button type="submit">Open</button>
              </form>
            </main>
            """,
        )
    if route == "/panel":
        return 200, _page(
            "Panel",
            f"""
            <main>
              <form method="GET" action="{prefix}/south">
                <label>Comment <textarea name="comment"></textarea></label>
                <button type="submit">Open</button>
              </form>
              <a href="{prefix}/west?term=sample">Details</a>
            </main>
            """,
        )
    if route == "/north":
        return _reflected_page("North", params, Reflection("name", escaped=True))
    if route == "/east":
        return _reflected_page("East", params, Reflection("input", escaped=True))
    if route == "/south":
        return _textarea_page("South", params, Reflection("comment", escaped=True))
    if route == "/west":
        return _reflected_page("West", params, Reflection("term", escaped=True))
    return 404, _page("Not Found", "<p>not found</p>")


def _case_d(route: str, params: dict[str, list[str]], scenario_id: str) -> tuple[int, str]:
    prefix = _prefix(scenario_id)
    if route in {"", "/"}:
        return 200, _page("Index", f'<main><a href="{prefix}/start">Start</a></main>')
    if route == "/start":
        return 200, _page(
            "Start",
            f"""
            <main>
              <form method="GET" action="{prefix}/orange">
                <label>Search <input type="search" name="search"></label>
                <button type="submit">Open</button>
              </form>
              <a href="{prefix}/purple?slot=sample">Details</a>
            </main>
            """,
        )
    if route == "/panel":
        return 200, _page(
            "Panel",
            f"""
            <main>
              <form method="GET" action="{prefix}/silver">
                <label>Message <input type="text" name="message"></label>
                <button type="submit">Open</button>
              </form>
              <form method="GET" action="{prefix}/yellow">
                <label>Note <input type="text" name="note" required></label>
                <button type="submit">Open</button>
              </form>
            </main>
            """,
        )
    if route == "/orange":
        return _reflected_page("Orange", params, Reflection("search", escaped=True))
    if route == "/purple":
        return _reflected_page("Purple", params, Reflection("slot", escaped=False))
    if route == "/silver":
        return _reflected_page("Silver", params, Reflection("message", escaped=True))
    if route == "/yellow":
        return _reflected_page("Yellow", params, Reflection("note", escaped=True))
    return 404, _page("Not Found", "<p>not found</p>")


class DevelopmentBenchmarkHandler(BaseHTTPRequestHandler):
    server_version = "ADSTFDevelopmentBenchmark/0.2"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path.startswith("/idor/"):
            status, body, headers = _idor_get_response(
                parsed.path,
                parsed.query,
                self.headers.get("Cookie", ""),
            )
            self._send_body(status, body, headers)
            return
        status, body = render_response(parsed.path, parsed.query)
        self._send_body(status, body, {"Content-Type": "text/html; charset=utf-8"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/idor/login":
            self._send_body(404, _page("Not Found", "<p>not found</p>"), {"Content-Type": "text/html; charset=utf-8"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        status, response_body, headers = _idor_login_response(body)
        self._send_body(status, response_body, headers)

    def _send_body(self, status: int, body: str, headers: dict[str, str]) -> None:
        body_bytes = body.encode("utf-8")
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    def log_message(self, format: str, *args: object) -> None:
        return


def _split_scenario_path(path: str) -> tuple[str, str]:
    parts = [part for part in path.split("/") if part]
    if len(parts) >= 2 and parts[0] == "s" and parts[1] in SCENARIOS:
        remainder = "/" + "/".join(parts[2:]) if len(parts) > 2 else "/"
        return parts[1], remainder
    return "case-a", path


def _idor_login_response(body: str) -> tuple[int, str, dict[str, str]]:
    params = parse_qs(body, keep_blank_values=True)
    username = _first(params, "username")
    password = _first(params, "password")
    user = IDOR_USERS.get(username)
    if not user or password != user["password"]:
        return 403, json.dumps({"authenticated": False}), {"Content-Type": "application/json"}
    token = f"token-{username}-development"
    return (
        200,
        json.dumps({"authenticated": True, "user_label": user["label"]}),
        {
            "Content-Type": "application/json",
            "Set-Cookie": f"adstf_session={token}; HttpOnly; SameSite=Strict",
        },
    )


def _idor_get_response(
    path: str,
    query: str,
    cookie_header: str,
) -> tuple[int, str, dict[str, str]]:
    if path == "/idor/health":
        return 200, json.dumps({"status": "ok"}), {"Content-Type": "application/json"}

    user_label = _user_label_from_cookie(cookie_header)
    if not user_label:
        return 401, json.dumps({"error": "authentication required"}), {"Content-Type": "application/json"}

    params = parse_qs(query, keep_blank_values=True)
    resource_id = _first(params, "rid")
    resource = IDOR_RESOURCES.get(resource_id)
    if not resource:
        return 404, json.dumps({"error": "resource not found"}), {"Content-Type": "application/json"}

    if path == "/idor/guarded" and resource["owner"] != user_label:
        return 403, json.dumps({"error": "not authorized"}), {"Content-Type": "application/json"}
    if path not in {"/idor/open", "/idor/guarded"}:
        return 404, json.dumps({"error": "not found"}), {"Content-Type": "application/json"}

    return (
        200,
        json.dumps(
            {
                "resource_id": resource_id,
                "owner_user_label": resource["owner"],
                "viewer_user_label": user_label,
                "content_marker": resource["content_marker"],
            },
            sort_keys=True,
        ),
        {"Content-Type": "application/json"},
    )


def _user_label_from_cookie(cookie_header: str) -> str | None:
    for item in cookie_header.split(";"):
        name, _, value = item.strip().partition("=")
        if name == "adstf_session":
            return IDOR_TOKENS.get(value)
    return None


def _prefix(scenario_id: str) -> str:
    return "" if scenario_id == "case-a" else f"/s/{scenario_id}"


def _reflected_page(title: str, params: dict[str, list[str]], reflection: Reflection) -> tuple[int, str]:
    value = _render_value(_first(params, reflection.parameter), reflection.escaped)
    return 200, _page(title, f"<main><p>{value}</p></main>")


def _textarea_page(title: str, params: dict[str, list[str]], reflection: Reflection) -> tuple[int, str]:
    value = _render_value(_first(params, reflection.parameter), reflection.escaped)
    return 200, _page(title, f"<main><textarea>{value}</textarea></main>")


def _two_value_page(
    title: str,
    params: dict[str, list[str]],
    first: Reflection,
    second: Reflection,
) -> tuple[int, str]:
    first_value = _render_value(_first(params, first.parameter), first.escaped)
    second_value = _render_value(_first(params, second.parameter), second.escaped)
    return 200, _page(title, f"<main><p>{first_value}</p><p>{second_value}</p></main>")


def _render_value(value: str, escaped: bool) -> str:
    return html.escape(value) if escaped else value


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


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local reflected-input development benchmark.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4291)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), DevelopmentBenchmarkHandler)
    print(f"Development benchmark listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
