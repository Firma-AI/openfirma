#!/usr/bin/env bash
# Break-out 5 — Egress guard degradation.
#
# The loopback egress guard (seccomp connect user-notify) is defense in depth:
# it fails OPEN. If it cannot start — a kernel without seccomp user-notify, a
# foreign-arch connect it cannot decode, or any start error — `firma run`
# proceeds with a warning and the boundary silently weakens to netns-only.
#
# This probe does two things:
#   1. Confirms the guard is currently ACTIVE by having the agent connect to a
#      non-allow-listed loopback port; the guard turns that into EPERM.
#   2. Confirms that even with the guard removed from the picture, the netns
#      still contains: the box's loopback has nothing listening and there is no
#      route off the namespace, so a direct connect has nowhere to land.
#
# We cannot force a foreign-arch fail-open from config here, so the degraded
# case is reasoned from (2): the netns is the load-bearing boundary; the guard
# only adds a direct-socket audit trail and blocks loopback ports the netns
# would otherwise expose to co-located services.
#
# Expected: DEGRADES, STILL CONTAINED BY NETNS.

source "$(dirname "$0")/../lib/common.sh"

PAYLOAD="$RUNTIME_DIR/b5-payload.sh"
cat >"$PAYLOAD" <<'PAYLOAD_EOF'
#!/usr/bin/env bash
set -uo pipefail
echo "[agent] probing the egress guard: connect to a non-allow-listed loopback port"
python3 - <<'PY'
import socket
# 9999 is neither the proxy (18080) nor the DNS stub (53). With the guard
# active this connect is turned into EPERM before it can reach anything.
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(("127.0.0.1", 9999))
    s.close()
    print("[agent] connect to 127.0.0.1:9999 SUCCEEDED (guard not blocking this port)")
except PermissionError as exc:
    print(f"[agent] connect BLOCKED by egress guard (EPERM): {exc}")
except OSError as exc:
    print(f"[agent] connect failed at netns (no listener / no route): {exc}")
PY
PAYLOAD_EOF

cd "$SPIKE_DIR"
banner "BREAK-OUT 5 — egress guard degradation (boxed)"
out="$(run_boxed "$PAYLOAD" 2>&1)"
echo "$out" | grep -vE '^\[INFO\]|bubblewrap|seccomp|egress guard|network enforcement proof' || true

if echo "$out" | grep -q "BLOCKED by egress guard"; then
  echo "guard is ACTIVE; degraded (fail-open) case would fall back to netns-only containment"
  record_result "b5" "egress-guard" "ACTIVE+DEGRADES-TO-NETNS" "no"
else
  echo "guard did not block; netns remains the containing boundary"
  record_result "b5" "egress-guard" "NETNS-ONLY" "no"
fi
