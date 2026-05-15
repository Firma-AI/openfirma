#!/usr/bin/env python3
import argparse
import json
import socket
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Mock mediator for local-command governance demos")
    parser.add_argument("--port", type=int, default=28991)
    parser.add_argument("--unix-path", default="")
    parser.add_argument(
        "--mode",
        choices=["allow", "deny", "hitl_async", "hitl_missing_token"],
        required=True,
    )
    parser.add_argument("--once", action="store_true", default=True)
    args = parser.parse_args()

    if args.mode == "allow":
        response = {"decision": "allow", "reason": "demo-allow"}
    elif args.mode == "deny":
        response = {"decision": "deny", "reason": "demo-deny"}
    elif args.mode == "hitl_async":
        response = {
            "decision": "pending_hitl",
            "reason": "awaiting-approval",
            "approval_token": "tok_demo_123",
            "retry_after_ms": 500,
        }
    else:
        response = {
            "decision": "pending_hitl",
            "reason": "awaiting-approval",
            "retry_after_ms": 500,
        }

    payload = (json.dumps(response) + "\n").encode("utf-8")

    if args.unix_path:
        path = Path(args.unix_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(path))
    else:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", args.port))
    with server:
        server.listen(5)

        while True:
            conn, _ = server.accept()
            with conn:
                data = b""
                while not data.endswith(b"\n"):
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                conn.sendall(payload)
            if args.once:
                break

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
