#!/usr/bin/env python3
"""Local target service for the Policy Control example.

The sidecar proxies demo requests to this service after policy evaluation.
Denied calls never reach it; allowed calls return deterministic local responses
so the audit stream can show real dispatch data without external services.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from agent.tools import TOOLS, ToolCall, validate_tools


Response = tuple[HTTPStatus, dict[str, Any]]
RouteKey = tuple[str, str]
ROUTES: dict[RouteKey, Response] = {}


class FixtureHandler(BaseHTTPRequestHandler):
    """Handles local endpoints generated from the demo-agent catalog."""

    protocol_version = "HTTP/1.1"
    server_version = "openfirma-policy-control-fixture/0.1"

    def do_GET(self) -> None:
        """Serve deterministic read endpoints."""

        self._send_route("GET")

    def do_POST(self) -> None:
        """Serve deterministic write endpoints."""

        length = int(self.headers.get("content-length", "0"))
        if length > 0:
            self.rfile.read(length)
        self._send_route("POST")

    def log_message(self, format: str, *args: object) -> None:
        """Write compact request logs to the fixture log file."""

        print(f"{self.address_string()} - {format % args}", flush=True)

    def _send_route(self, method: str) -> None:
        status, body = ROUTES.get(
            (method, self.path),
            (
                HTTPStatus.NOT_FOUND,
                {
                    "error": "unknown fixture route",
                    "method": method,
                    "path": self.path,
                },
            ),
        )
        self._send_json(status, body)

    def _send_json(self, status: HTTPStatus, body: dict[str, Any]) -> None:
        payload = json.dumps(body, sort_keys=True).encode()
        self.send_response(status.value)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main() -> None:
    """Start the local fixture server."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=9000, type=int)
    parser.add_argument("--daemon", action="store_true")
    parser.add_argument("--pid-file")
    parser.add_argument("--log-file")
    args = parser.parse_args()

    if args.daemon:
        start_daemon(args.host, args.port, args.pid_file, args.log_file)
        return

    load_routes()
    server = ThreadingHTTPServer((args.host, args.port), FixtureHandler)
    print(f"fixture listening on {args.host}:{args.port}", flush=True)
    server.serve_forever()


def load_routes() -> None:
    """Build fixture routes from the demo-agent tool catalog."""

    validate_tools()
    ROUTES.clear()
    ROUTES[("GET", "/_ready")] = (HTTPStatus.OK, {"status": "ready"})
    for call in TOOLS.values():
        ROUTES[(call.method, call.path)] = response_for_tool(call)


def response_for_tool(call: ToolCall) -> Response:
    """Return a deterministic local response for one agent tool."""

    status = HTTPStatus.OK if call.method == "GET" else HTTPStatus.ACCEPTED
    body = {
        "operation": call.name,
        "label": call.label,
        "method": call.method,
        "path": call.path,
        "status": "ok" if call.method == "GET" else "accepted",
    }
    return status, body


def start_daemon(
    host: str,
    port: int,
    pid_file: str | None,
    log_file: str | None,
) -> None:
    """Start the fixture in a detached process and write its pid."""

    if pid_file is None:
        raise SystemExit("--pid-file is required with --daemon")
    if log_file is None:
        raise SystemExit("--log-file is required with --daemon")

    pid_path = Path(pid_file)
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    with log_path.open("ab", buffering=0) as log:
        process = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--host",
                host,
                "--port",
                str(port),
            ],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    pid_path.write_text(f"{process.pid}\n")


if __name__ == "__main__":
    main()
