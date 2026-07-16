#!/usr/bin/env python3
"""approved-api — the legitimate service the agent is supposed to reach.

Spike FIR-411, throwaway proof-of-concept. Binds loopback and echoes back
whether the request carried the *real* bearer token. The agent inside the box
only ever holds a placeholder; the sidecar injects the real token on the way
out. So a request that arrives here with the real token proves the injection
path worked, and a request with the placeholder proves it did not.

No real secrets: the "real" token is a fixed string passed in the environment.
"""

import json
import os
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REAL_TOKEN = os.environ.get("APPROVED_API_REAL_TOKEN", "real-token-unset")
PLACEHOLDER = os.environ.get("APPROVED_API_PLACEHOLDER", "PLACEHOLDER-TOKEN")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _emit(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _classify_auth(self) -> str:
        auth = self.headers.get("Authorization", "")
        token = auth[len("Bearer "):] if auth.startswith("Bearer ") else auth
        if token == REAL_TOKEN:
            return "real"
        if token == PLACEHOLDER or token == "":
            return "placeholder-or-missing"
        return "unknown"

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        self._emit(200, {"service": "approved-api", "auth": self._classify_auth()})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        _ = self.rfile.read(length) if length else b""
        self._emit(200, {"service": "approved-api", "auth": self._classify_auth()})

    def log_message(self, fmt: str, *args) -> None:  # silence access log
        pass


class V6Server(ThreadingHTTPServer):
    # `*.localhost` resolves to ::1 here, so the sidecar's outbound connector
    # and any direct probe both dial IPv6 loopback. Bind there to match.
    address_family = socket.AF_INET6


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8081
    server = V6Server(("::1", port), Handler)
    print(f"approved-api listening on [::1]:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
