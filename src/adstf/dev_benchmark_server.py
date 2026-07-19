from __future__ import annotations

import argparse
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


def render_response(path: str, query: str = "") -> tuple[int, str]:
    params = parse_qs(query, keep_blank_values=True)
    if path == "/health":
        return 200, _page("Status", "<p>ok</p>")
    if path == "/reset":
        return 200, _page("Reset", "<p>state reset</p>")
    if path in {"", "/"}:
        return 200, _page(
            "Index",
            """
            <main>
              <a href="/start">Start</a>
              <a href="/panel?item=sample">Panel</a>
            </main>
            """,
        )
    if path == "/start":
        return 200, _page(
            "Start",
            """
            <main>
              <form method="GET" action="/alpha">
                <label>Term <input type="text" name="term"></label>
                <button type="submit">Open</button>
              </form>
              <form method="GET" action="/beta">
                <label>Item <input type="text" name="item"></label>
                <button type="submit">Open</button>
              </form>
              <a href="/panel?item=sample">More options</a>
            </main>
            """,
        )
    if path == "/panel":
        item = html.escape(_first(params, "item"))
        return 200, _page(
            "Panel",
            f"""
            <main>
              <p>Current item: {item}</p>
              <form method="GET" action="/gamma">
                <label>Entry <input type="text" name="entry" required></label>
                <button type="submit">Open</button>
              </form>
              <form method="GET" action="/delta">
                <label>Term <input type="text" name="term"></label>
                <label>Mode <input type="text" name="mode"></label>
                <button type="submit">Open</button>
              </form>
            </main>
            """,
        )
    if path == "/alpha":
        term = _first(params, "term")
        return 200, _page("Alpha", f"<main><p>{term}</p></main>")
    if path == "/beta":
        item = html.escape(_first(params, "item"))
        return 200, _page("Beta", f"<main><p>{item}</p></main>")
    if path == "/gamma":
        entry = html.escape(_first(params, "entry"))
        return 200, _page("Gamma", f"<main><textarea>{entry}</textarea></main>")
    if path == "/delta":
        term = html.escape(_first(params, "term"))
        mode = html.escape(_first(params, "mode"))
        return 200, _page("Delta", f"<main><p>{term}</p><p>{mode}</p></main>")
    return 404, _page("Not Found", "<p>not found</p>")


class DevelopmentBenchmarkHandler(BaseHTTPRequestHandler):
    server_version = "ADSTFDevelopmentBenchmark/0.1"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        status, body = render_response(parsed.path, parsed.query)
        body_bytes = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    def log_message(self, format: str, *args: object) -> None:
        return


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
