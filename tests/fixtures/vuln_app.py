"""Small intentionally vulnerable HTTP app used by Sentinel tests."""

from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

_STORED_COMMENTS: list[str] = []


class _Handler(BaseHTTPRequestHandler):
    server_version = "SentinelFixture/0.1"

    def log_message(self, fmt: str, *args) -> None:
        return

    def _send(self, status: int, body: str, content_type: str = "text/html") -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload), "application/json")

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        path = parsed.path
        if path == "/":
            stored = "".join(f"<p class='stored'>{comment}</p>" for comment in _STORED_COMMENTS)
            self._send(200, """
                <html><head><script src="/app.js"></script></head><body>
                  <script>
                    window.API_PREFIX = '/runtime';
                    fetch(window.API_PREFIX + '/dynamic?rid=1');
                  </script>
                  <a href="/search?q=hello">Search</a>
                  <a href="/item?id=1">Item</a>
                  <a href="/redirect?next=/">Redirect</a>
                  <form method="post" action="/post-xss">
                    <input type="hidden" name="token" value="fixture">
                    <input name="comment" value="hello">
                  </form>
                  <form method="post" action="/stored">
                    <input name="note" value="hello">
                  </form>
                  <div id="out"></div>
                  <section id="stored">
            """ + stored + """
                  </section>
                </body></html>
            """)
            return
        if path == "/app.js":
            self._send(200, """
                fetch('/api/echo', {
                  method: 'POST',
                  headers: {'Content-Type': 'application/json'},
                  body: JSON.stringify({name: "demo"})
                });
                fetch('/api/users/1');
                document.getElementById('out').innerHTML = location.hash;
            """, "application/javascript")
            return
        if path == "/search":
            self._send(200, f"<html>Search result: {query.get('q', [''])[0]}</html>")
            return
        if path == "/item":
            item_id = query.get("id", [""])[0]
            if "'" in item_id:
                self._send(200, "SQL syntax error near unexpected quote")
            else:
                self._send(200, f"<html>Item {item_id}</html>")
            return
        if path == "/redirect":
            target = query.get("next", ["/"])[0]
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()
            return
        if path == "/api/users/1":
            auth = self.headers.get("Authorization", "")
            if auth in {"Bearer user-a", "Bearer user-b"}:
                self._json(200, {"id": 1, "email": "user-a@example.test"})
            else:
                self._json(401, {"error": "unauthorized login required"})
            return
        if path == "/admin":
            self._send(200, "<title>Admin</title>Admin dashboard logout manage users")
            return
        self._send(404, "not found")

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        if parsed.path == "/post-xss":
            params = parse_qs(raw.decode(errors="replace"))
            comment = params.get("comment", [""])[0]
            self._send(200, f"<html>Saved comment: {comment}</html>")
            return
        if parsed.path == "/api/echo":
            try:
                payload = json.loads(raw.decode() or "{}")
            except json.JSONDecodeError:
                payload = {}
            self._json(200, {"echo": payload.get("name", "")})
            return
        if parsed.path == "/stored":
            params = parse_qs(raw.decode(errors="replace"))
            _STORED_COMMENTS.append(params.get("note", [""])[0])
            self._send(200, "<html>stored</html>")
            return
        self._send(404, "not found")


@contextmanager
def run_vuln_app():
    _STORED_COMMENTS.clear()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
