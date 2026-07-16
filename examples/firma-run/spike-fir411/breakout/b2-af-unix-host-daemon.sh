#!/usr/bin/env bash
# Break-out 2 — AF_UNIX to a host daemon.
#
# A host daemon listens on a Unix-domain socket that is reachable inside the box
# because it lives in the writable bind mount (cwd). The agent connects to it.
# The loopback egress guard only filters AF_INET/AF_INET6 connect() to
# loopback ports — AF_UNIX is ungoverned today — so the connection is neither
# blocked nor audited.
#
# The socket is addressed by a short *relative* path from the workspace root:
# the AF_UNIX sun_path limit (~108 bytes) is shorter than this repo's absolute
# path, and using the relative form keeps the address identical on the host and
# inside the box (both have the workspace as cwd).
#
# Expected: ESCAPES if the socket is reachable.

source "$(dirname "$0")/../lib/common.sh"

cd "$SPIKE_DIR"
SOCK_REL=".runtime/b2.sock"
RECV_LOG="$RUNTIME_DIR/b2-daemon-received.log"
rm -f "$SOCK_REL" "$RECV_LOG"

# Host daemon: accepts one AF_UNIX connection and records what it got. Runs with
# the workspace as cwd so the relative socket path resolves the same way the box
# will resolve it.
python3 - "$SOCK_REL" "$RECV_LOG" <<'PY' &
import os, socket, sys
sock_path, recv_log = sys.argv[1], sys.argv[2]
if os.path.exists(sock_path):
    os.unlink(sock_path)
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(sock_path)
srv.listen(1)
srv.settimeout(20)
try:
    conn, _ = srv.accept()
    data = conn.recv(4096).decode("utf-8", "replace")
    with open(recv_log, "w", encoding="utf-8") as fh:
        fh.write(data)
    conn.close()
except OSError:
    pass
finally:
    srv.close()
PY
daemon_pid=$!

for _ in $(seq 1 30); do [[ -S "$SOCK_REL" ]] && break; sleep 0.1; done

PAYLOAD="$RUNTIME_DIR/b2-payload.sh"
cat >"$PAYLOAD" <<PAYLOAD_EOF
#!/usr/bin/env bash
set -uo pipefail
# Enter the workspace so the short relative socket path resolves inside the box.
cd "$SPIKE_DIR"
echo "[agent] connecting to host daemon over AF_UNIX (ungoverned by egress guard)"
python3 - <<'PY'
import socket
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(".runtime/b2.sock")
    s.sendall(b"agent reached the host daemon via AF_UNIX")
    s.close()
    print("[agent] AF_UNIX write SUCCEEDED")
except OSError as exc:
    print(f"[agent] AF_UNIX write FAILED: {exc}")
PY
PAYLOAD_EOF

banner "BREAK-OUT 2 — AF_UNIX to host daemon (boxed)"
run_boxed "$PAYLOAD"
wait "$daemon_pid" 2>/dev/null || true

if [[ -s "$RECV_LOG" ]]; then
  echo "host daemon received:"
  cat "$RECV_LOG"; echo
  record_result "b2" "af-unix" "ESCAPED" "yes"
else
  record_result "b2" "af-unix" "CONTAINED" "no"
fi
