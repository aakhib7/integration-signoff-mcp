"""A tiny merchant webhook endpoint for trying the probe locally.

    python examples/demo_webhook_server.py --mode good   # verifies signatures, dedupes events
    python examples/demo_webhook_server.py --mode bad    # accepts everything

Then call probe_webhook with url=http://127.0.0.1:8765/webhook, signing_secret=demo-secret, allow_private=true.
It uses the default profile: HMAC-SHA256 hex of "{timestamp}.{body}" in X-Signature.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET = "demo-secret"
REPLAY_WINDOW = 300


def make_handler(mode: str, secret: str = SECRET):
    seen: set[str] = set()
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # keep test output quiet
            pass

        def _reply(self, status: int) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")

        def do_POST(self):  # noqa: N802 - http.server naming
            body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
            if mode == "bad":
                return self._reply(200)

            signature = self.headers.get("X-Signature")
            timestamp = self.headers.get("X-Timestamp", "")
            if not signature or not timestamp.isdigit():
                return self._reply(401)
            expected = hmac.new(secret.encode(), f"{timestamp}.{body}".encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, signature):
                return self._reply(401)
            if abs(time.time() - int(timestamp)) > REPLAY_WINDOW:
                return self._reply(401)
            try:
                event = json.loads(body)
            except json.JSONDecodeError:
                return self._reply(400)
            with lock:
                if event.get("id") in seen:
                    return self._reply(200)  # duplicate: acknowledge, do not re-process
                seen.add(event.get("id"))
            return self._reply(200)

    return Handler


def serve(mode: str, port: int = 8765) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(mode))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["good", "bad"], default="good")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(args.mode))
    print(f"Demo merchant webhook ({args.mode}) on http://127.0.0.1:{args.port}/webhook")
    server.serve_forever()
