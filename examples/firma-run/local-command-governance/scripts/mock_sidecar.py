#!/usr/bin/env python3
import argparse
import signal
import socket


running = True


def _stop(_sig, _frame):
    global running
    running = False


def main() -> int:
    parser = argparse.ArgumentParser(description="Tiny TCP sidecar liveness stub")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=28992)
    args = parser.parse_args()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((args.host, args.port))
        server.listen(16)
        server.settimeout(0.5)

        while running:
            try:
                conn, _ = server.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with conn:
                try:
                    _ = conn.recv(4096)
                except OSError:
                    pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
