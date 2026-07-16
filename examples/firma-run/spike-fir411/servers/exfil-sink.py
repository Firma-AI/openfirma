#!/usr/bin/env python3
"""exfil-sink — stands in for evil.com.

Spike FIR-411, throwaway proof-of-concept. Logs *everything* it receives to a
newline-delimited JSON file so a leak is visible after the fact. If this file
ever contains a captured secret, the boundary failed for that attempt.

Also opens a raw TCP listener (same port) for the non-HTTP break-out probe:
BaseHTTPRequestHandler already accepts arbitrary bytes on connect, and any
connection at all is recorded as a hit.
"""

import datetime
import json
import os
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_PATH = os.environ.get("EXFIL_SINK_LOG", "/tmp/exfil-sink.log")


def _record(kind: str, detail: dict) -> None:
    entry = {
        "kind": kind,
        # Wall-clock only for human-readable ordering of a throwaway log.
        "ts": datetime.datetime.now().isoformat(timespec="seconds"),
        **detail,
    }
    with open(LOG_PATH, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _drain_and_log(self, method: str) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        _record(
            "http",
            {
                "method": method,
                "path": self.path,
                "authorization": self.headers.get("Authorization", ""),
                "body": body,
            },
        )
        reply = b'{"service":"exfil-sink","received":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def do_GET(self) -> None:  # noqa: N802
        self._drain_and_log("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._drain_and_log("POST")

    def log_message(self, fmt: str, *args) -> None:
        pass


class V6Server(ThreadingHTTPServer):
    # `*.localhost` resolves to ::1 here; bind IPv6 loopback to match.
    address_family = socket.AF_INET6


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8082
    # Fresh log per run so each demo starts from a clean slate.
    with open(LOG_PATH, "w", encoding="utf-8") as handle:
        handle.truncate(0)
    server = V6Server(("::1", port), Handler)
    print(f"exfil-sink listening on [::1]:{port} (log: {LOG_PATH})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
