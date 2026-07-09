#!/usr/bin/env python3
"""Inject Firma session attribution into CONNECT requests."""

from __future__ import annotations

import select
import socket
import socketserver
import sys


listen_host, listen_port = sys.argv[1].rsplit(":", 1)
upstream_host, upstream_port = sys.argv[2].rsplit(":", 1)
session_id = sys.argv[3]


def inject_connect_header(head: bytes) -> bytes:
    marker = b"\r\n\r\n"
    if marker not in head:
        return head
    request, rest = head.split(marker, 1)
    first_line = request.split(b"\r\n", 1)[0].upper()
    if not first_line.startswith(b"CONNECT "):
        return head
    if b"\r\nx-firma-session-id:" in request.lower():
        return head
    injected = request + b"\r\nx-firma-session-id: " + session_id.encode("ascii")
    return injected + marker + rest


def relay(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    while sockets:
        readable, _, _ = select.select(sockets, [], [])
        for source in readable:
            data = source.recv(65536)
            if not data:
                return
            target = right if source is left else left
            target.sendall(data)


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            data += chunk
        upstream = socket.create_connection((upstream_host, int(upstream_port)))
        try:
            upstream.sendall(inject_connect_header(data))
            relay(self.request, upstream)
        finally:
            upstream.close()


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


with Server((listen_host, int(listen_port)), Handler) as server:
    server.serve_forever()
