#!/usr/bin/env python3
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class MockVaultHandler(BaseHTTPRequestHandler):
    receipt_path: Path

    def do_GET(self) -> None:
        if self.path == "/health":
            self._json_response(b'{"status":"ok"}')
        elif self.path == "/v1/secret":
            self._json_response(
                b'{"name":"demo-api-key","value":"local-http-secret"}'
            )
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        if self.path != "/v1/echo":
            self.send_error(404)
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length)
        self.receipt_path.write_bytes(body)
        self._json_response(body)

    def log_message(self, format: str, *args: object) -> None:
        return

    def _json_response(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    MockVaultHandler.receipt_path = args.receipt
    ThreadingHTTPServer(("127.0.0.1", 18081), MockVaultHandler).serve_forever()


if __name__ == "__main__":
    main()
