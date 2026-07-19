from __future__ import annotations

import argparse
import html
import json
import sqlite3
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


@dataclass(frozen=True)
class Reflection:
    parameter: str
    escaped: bool


USERS = {
    "mira": {"password": "mira-password", "label": "user_a"},
    "niko": {"password": "niko-password", "label": "user_b"},
}
TOKENS = {
    "heldout-token-mira": "user_a",
    "heldout-token-niko": "user_b",
}
RESOURCES = {
    "r-218": {
        "owner": "user_a",
        "content_marker": "record-aurora-owner-a",
        "guarded": False,
    },
    "r-319": {
        "owner": "user_b",
        "content_marker": "record-boreal-owner-b",
        "guarded": False,
    },
    "r-427": {
        "owner": "user_a",
        "content_marker": "record-cascade-owner-a",
        "guarded": True,
    },
}
SQL_ROWS = [
    ("A100", "Atlas record", 1),
    ("B200", "Boreal record", 1),
    ("C300", "Closed record", 0),
]


class HeldoutBenchmarkHandler(BaseHTTPRequestHandler):
    server_version = "ADSTFHeldoutBenchmark/0.1"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        target_kind = getattr(self.server, "target_kind", "xss")
        if parsed.path == "/status":
            self._send_body(200, _json({"status": "ok", "target": target_kind}), "application/json")
            return
        if parsed.path == "/reset":
            self._send_body(200, _json({"status": "reset", "target": target_kind}), "application/json")
            return
        if target_kind == "xss":
            status, body, content_type = _xss_response(parsed.path, parsed.query)
        elif target_kind == "idor":
            status, body, content_type = _idor_response(
                parsed.path,
                parsed.query,
                self.headers.get("Cookie", ""),
            )
        else:
            status, body, content_type = _sqli_response(parsed.path, parsed.query)
        self._send_body(status, body, content_type)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        target_kind = getattr(self.server, "target_kind", "xss")
        if target_kind != "idor" or parsed.path != "/portal/login":
            self._send_body(404, _page("Not Found", "<p>not found</p>"), "text/html; charset=utf-8")
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        status, response_body, headers = _idor_login_response(body)
        self._send_raw(status, response_body, headers)

    def _send_body(self, status: int, body: str, content_type: str) -> None:
        self._send_raw(status, body, {"Content-Type": content_type})

    def _send_raw(self, status: int, body: str, headers: dict[str, str]) -> None:
        body_bytes = body.encode("utf-8")
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    def log_message(self, format: str, *args: object) -> None:
        return


def _xss_response(path: str, query: str) -> tuple[int, str, str]:
    params = parse_qs(query, keep_blank_values=True)
    if path == "/desk/start":
        return 200, _page(
            "Desk",
            """
            <main>
              <form method="GET" action="/desk/card">
                <label>Label <input type="text" name="label"></label>
                <button type="submit">Open</button>
              </form>
              <form method="GET" action="/desk/preview">
                <label>Note <input type="text" name="note"></label>
                <button type="submit">Open</button>
              </form>
              <a href="/desk/list?ticket=sample">List</a>
            </main>
            """,
        ), "text/html; charset=utf-8"
    if path == "/desk/list":
        ticket = html.escape(_first(params, "ticket"))
        return 200, _page("List", f"<main><p>{ticket}</p></main>"), "text/html; charset=utf-8"
    if path == "/desk/card":
        return _reflected_page("Card", params, Reflection("label", escaped=True))
    if path == "/desk/preview":
        return _reflected_page("Preview", params, Reflection("note", escaped=False))
    if path == "/ledger/start":
        return 200, _page(
            "Ledger",
            """
            <main>
              <form method="GET" action="/ledger/detail">
                <label>Code <input type="text" name="code"></label>
                <button type="submit">Open</button>
              </form>
              <form method="GET" action="/ledger/memo">
                <label>Memo <textarea name="memo"></textarea></label>
                <button type="submit">Open</button>
              </form>
            </main>
            """,
        ), "text/html; charset=utf-8"
    if path == "/ledger/detail":
        return _reflected_page("Detail", params, Reflection("code", escaped=True))
    if path == "/ledger/memo":
        return _reflected_page("Memo", params, Reflection("memo", escaped=True))
    if path == "/queue/start":
        return 200, _page(
            "Queue",
            """
            <main>
              <form method="GET" action="/queue/submit">
                <label>Key <input type="text" name="key" required></label>
                <label>Comment <input type="text" name="comment"></label>
                <button type="submit">Open</button>
              </form>
              <a href="/queue/panel">Panel</a>
            </main>
            """,
        ), "text/html; charset=utf-8"
    if path == "/queue/panel":
        return 200, _page(
            "Panel",
            """
            <main>
              <form method="GET" action="/queue/view">
                <label>Token <input type="search" name="token"></label>
                <button type="submit">Open</button>
              </form>
            </main>
            """,
        ), "text/html; charset=utf-8"
    if path == "/queue/submit":
        first = html.escape(_first(params, "key"))
        second = _first(params, "comment")
        return 200, _page("Submit", f"<main><p>{first}</p><p>{second}</p></main>"), "text/html; charset=utf-8"
    if path == "/queue/view":
        return _reflected_page("View", params, Reflection("token", escaped=True))
    return 404, _page("Not Found", "<p>not found</p>"), "text/html; charset=utf-8"


def _idor_login_response(body: str) -> tuple[int, str, dict[str, str]]:
    params = parse_qs(body, keep_blank_values=True)
    username = _first(params, "username")
    password = _first(params, "password")
    user = USERS.get(username)
    if not user or password != user["password"]:
        return 403, _json({"authenticated": False}), {"Content-Type": "application/json"}
    token = f"heldout-token-{username}"
    return (
        200,
        _json({"authenticated": True, "user_label": user["label"]}),
        {
            "Content-Type": "application/json",
            "Set-Cookie": f"adstf_heldout_session={token}; HttpOnly; SameSite=Strict",
        },
    )


def _idor_response(path: str, query: str, cookie_header: str) -> tuple[int, str, str]:
    if path not in {"/portal/file", "/portal/item"}:
        return 404, _json({"error": "not found"}), "application/json"
    user_label = _user_label_from_cookie(cookie_header)
    if not user_label:
        return 401, _json({"error": "authentication required"}), "application/json"
    params = parse_qs(query, keep_blank_values=True)
    resource = RESOURCES.get(_first(params, "doc"))
    if not resource:
        return 404, _json({"error": "resource not found"}), "application/json"
    if path == "/portal/item" and resource["guarded"] and resource["owner"] != user_label:
        return 403, _json({"error": "not authorized"}), "application/json"
    return 200, _json(
        {
            "owner_user_label": resource["owner"],
            "viewer_user_label": user_label,
            "content_marker": resource["content_marker"],
        }
    ), "application/json"


def _sqli_response(path: str, query: str) -> tuple[int, str, str]:
    params = parse_qs(query, keep_blank_values=True)
    ref = _first(params, "ref")
    if path == "/catalog/item":
        return _sql_unsafe(ref)
    if path == "/catalog/card":
        return _sql_safe(ref)
    return 404, _json({"error": "not found"}), "application/json"


def _sql_unsafe(ref: str) -> tuple[int, str, str]:
    database = _database()
    try:
        rows = database.execute(
            "SELECT code, label FROM entries "
            f"WHERE code = '{ref}' AND visible = 1 ORDER BY code"
        ).fetchall()
    except sqlite3.Error:
        return 400, _json({"error": "invalid input"}), "application/json"
    finally:
        database.close()
    return _sql_rows(rows)


def _sql_safe(ref: str) -> tuple[int, str, str]:
    database = _database()
    try:
        rows = database.execute(
            "SELECT code, label FROM entries WHERE code = ? AND visible = 1 ORDER BY code",
            (ref,),
        ).fetchall()
    finally:
        database.close()
    return _sql_rows(rows)


def _database() -> sqlite3.Connection:
    database = sqlite3.connect(":memory:")
    database.execute("CREATE TABLE entries (code TEXT PRIMARY KEY, label TEXT, visible INTEGER)")
    database.executemany("INSERT INTO entries VALUES (?, ?, ?)", SQL_ROWS)
    return database


def _sql_rows(rows: list[tuple[str, str]]) -> tuple[int, str, str]:
    return 200, _json(
        {
            "count": len(rows),
            "items": [{"code": code, "label": label} for code, label in rows],
        }
    ), "application/json"


def _user_label_from_cookie(cookie_header: str) -> str | None:
    for item in cookie_header.split(";"):
        name, _, value = item.strip().partition("=")
        if name == "adstf_heldout_session":
            return TOKENS.get(value)
    return None


def _reflected_page(title: str, params: dict[str, list[str]], reflection: Reflection) -> tuple[int, str, str]:
    value = _first(params, reflection.parameter)
    if reflection.escaped:
        value = html.escape(value)
    return 200, _page(title, f"<main><p>{value}</p></main>"), "text/html; charset=utf-8"


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


def _json(data: dict) -> str:
    return json.dumps(data, sort_keys=True)


def _first(params: dict[str, list[str]], name: str) -> str:
    values = params.get(name, [""])
    return values[0] if values else ""


def make_server(host: str, port: int, target_kind: str) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), HeldoutBenchmarkHandler)
    server.target_kind = target_kind  # type: ignore[attr-defined]
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a local held-out benchmark target.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--target", choices=["xss", "idor", "sqli"], required=True)
    args = parser.parse_args()
    server = make_server(args.host, args.port, args.target)
    try:
        print(f"Serving held-out {args.target} target on http://{args.host}:{args.port}")
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
