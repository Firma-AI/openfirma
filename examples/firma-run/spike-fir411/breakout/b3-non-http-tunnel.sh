#!/usr/bin/env bash
# Break-out 3 — Non-HTTP protocol over the only exit.
#
# The one network exit from the box is the loopback proxy bridge (port 18080,
# allow-listed by the egress guard) and the DNS stub (port 53). This attempt
# speaks raw, non-HTTP bytes at the proxy bridge to see whether anything can be
# smuggled through a channel the sidecar can only reason about as HTTP.
#
# Expected: CONTAINED but UNCLASSIFIED — the bytes reach the bridge (allowed
# port) but are not valid proxied HTTP, so nothing is forwarded to an upstream;
# the sidecar cannot policy-evaluate a protocol it does not parse. This feeds
# design question #2 (is destination-based HTTP enforcement sufficient?).

source "$(dirname "$0")/../lib/common.sh"

PAYLOAD="$RUNTIME_DIR/b3-payload.sh"
cat >"$PAYLOAD" <<'PAYLOAD_EOF'
#!/usr/bin/env bash
set -uo pipefail
echo "[agent] sending raw non-HTTP bytes at the proxy bridge (127.0.0.1:18080)"
python3 - <<'PY'
import socket
try:
    s = socket.create_connection(("127.0.0.1", 18080), timeout=5)
    s.sendall(b"\x00\x01RAW-NON-HTTP-TUNNEL-ATTEMPT\xff\xfe")
    s.settimeout(3)
    try:
        reply = s.recv(256)
    except OSError:
        reply = b""
    s.close()
    print(f"[agent] bridge accepted the connection; upstream reply bytes={len(reply)}")
except OSError as exc:
    print(f"[agent] connect to bridge FAILED: {exc}")
PY
PAYLOAD_EOF

cd "$SPIKE_DIR"
start_servers
trap stop_servers EXIT
banner "BREAK-OUT 3 — non-HTTP over the tunnel (boxed)"
: >"$EXFIL_SINK_LOG"
run_boxed "$PAYLOAD"

hits="$(exfil_hits)"
echo "[check] sink captured $hits request(s) (expect 0: nothing forwarded)"
if [[ "$hits" -eq 0 ]]; then
  record_result "b3" "non-http-tunnel" "CONTAINED-UNCLASSIFIED" "no"
else
  record_result "b3" "non-http-tunnel" "ESCAPED" "yes"
fi
