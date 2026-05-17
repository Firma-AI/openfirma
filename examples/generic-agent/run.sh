#!/usr/bin/env bash
# Generic agent stack runner.
# Starts firma-authority + firma-sidecar, then either:
#   - wraps the given command with `firma run` (Layer 3 bwrap + L1/L4 policy), or
#   - prints smoke-test commands and waits (no command given).
#
# Usage (from repo root):
#   bash examples/generic-agent/run.sh [-- <command> [args...]]
#
# Example:
#   bash examples/generic-agent/run.sh -- claude --dangerously-skip-permissions
set -euo pipefail

command -v cargo   >/dev/null 2>&1 || { echo "ERROR: cargo not found" >&2; exit 1; }
command -v nc      >/dev/null 2>&1 || { echo "ERROR: nc not found (needed for health checks)" >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "ERROR: openssl not found (needed to generate audit key)" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

DIR="examples/generic-agent"
RUNTIME="$DIR/.runtime"
FIRMA_BIN="target/debug/firma"

AUTHORITY_ADDR="127.0.0.1:50051"
AUTHORITY_URL="http://${AUTHORITY_ADDR}"
SIDECAR_ADDR="127.0.0.1:7474"
SIDECAR_ENDPOINT="tcp://${SIDECAR_ADDR}"

# Dedicated workspace the agent is allowed to write to (FIR-116 Layer 3 contract).
# Under readonly-rootfs mode bwrap RW-binds exactly the cwd at launch, so we must
# cd into this directory before invoking `firma run` to avoid RW-binding repo root.
WORKSPACE_DIR="${WORKSPACE_DIR:-$REPO_ROOT/$DIR/workspace}"

# Parse agent command (everything after --)
AGENT_CMD=()
found_sep=0
for arg in "$@"; do
  if [[ $found_sep -eq 1 ]]; then
    AGENT_CMD+=("$arg")
  elif [[ "$arg" == "--" ]]; then
    found_sep=1
  fi
done

# ── Build ─────────────────────────────────────────────────────────────────────
echo "[1/4] Building..."
cargo build -q -p firma -p firma-authority -p firma-sidecar
echo "      Done."

# ── Setup runtime dir and workspace ──────────────────────────────────────────
echo "[2/4] Setting up .runtime/ and workspace/..."
mkdir -p "$RUNTIME/generated-firma-ca"
mkdir -p "$WORKSPACE_DIR"
rm -f "$DIR"/capability-*.toml

if [[ ! -f "$RUNTIME/authority.key" ]]; then
    "$FIRMA_BIN" authority generate-key --output "$RUNTIME/authority.key"
    echo "      Generated authority key."
fi

if [[ ! -f "$RUNTIME/audit.key" ]]; then
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
        -out "$RUNTIME/audit.key"
    echo "      Generated audit key."
fi

touch "$RUNTIME/revocations.txt"
echo "      Done."

# ── Helpers ───────────────────────────────────────────────────────────────────
wait_tcp() {
  local host="$1" port="$2"
  for _ in $(seq 1 80); do
    nc -z "$host" "$port" 2>/dev/null && return 0
    sleep 0.25
  done
  return 1
}

AUTHORITY_PID=""
SIDECAR_PID=""
cleanup() {
  echo ""
  echo "Stopping..."
  [[ -n "$AUTHORITY_PID" ]] && kill "$AUTHORITY_PID" 2>/dev/null || true
  [[ -n "$SIDECAR_PID" ]]   && kill "$SIDECAR_PID"   2>/dev/null || true
  [[ -n "$AUTHORITY_PID" ]] && wait "$AUTHORITY_PID" 2>/dev/null || true
  [[ -n "$SIDECAR_PID" ]]   && wait "$SIDECAR_PID"   2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── Start Authority ───────────────────────────────────────────────────────────
echo "[3/4] Starting firma-authority on ${AUTHORITY_ADDR}..."
"$FIRMA_BIN" authority --config "$DIR/firma.toml" &
AUTHORITY_PID=$!
wait_tcp 127.0.0.1 50051 || { echo "ERROR: authority failed to start" >&2; exit 1; }
echo "      Ready."

# ── Start Sidecar ─────────────────────────────────────────────────────────────
echo "[4/4] Starting firma-sidecar on ${SIDECAR_ADDR}..."
"$FIRMA_BIN" sidecar --config "$DIR/firma.toml" &
SIDECAR_PID=$!
wait_tcp 127.0.0.1 7474 || { echo "ERROR: sidecar failed to start" >&2; exit 1; }
echo "      Ready."

CA_CERT="$REPO_ROOT/$RUNTIME/generated-firma-ca/firma-ca.crt"
PROXY="http://${SIDECAR_ADDR}"

cat <<EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Generic agent stack running
  Authority : ${AUTHORITY_ADDR} (gRPC)
  Sidecar   : ${SIDECAR_ADDR}  (HTTP proxy)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF

# ── Agent or interactive mode ─────────────────────────────────────────────────
if [[ ${#AGENT_CMD[@]} -gt 0 ]]; then
  echo "  Launching agent via firma run (Layer 3 bwrap + L1/L4 policy)"
  echo "  Command: ${AGENT_CMD[*]}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  # cd into WORKSPACE_DIR so firma run's cwd — which bwrap RW-binds under
  # readonly-rootfs mode — resolves to the workspace, not repo root.
  (
    cd "$WORKSPACE_DIR"
    "$REPO_ROOT/$FIRMA_BIN" run \
      --profile generic \
      --config "$REPO_ROOT/$DIR/firma-run.toml" \
      --sidecar external \
      --sidecar-endpoint "$SIDECAR_ENDPOINT" \
      --authority "$AUTHORITY_URL" \
      -- "${AGENT_CMD[@]}"
  )
else
  cat <<EOF

Smoke tests — run in another terminal.
The x-firma-session-id header binds the request to the preflight token's
session_id (see [sidecar.preflight] in firma.toml). Without it the sidecar cannot
select the pre-issued capability.

  SESSION="x-firma-session-id: preflight-session"

  # ALLOW — system.install (crates.io, HTTP)
  curl -sx $PROXY -H "\$SESSION" http://crates.io/api/v1/crates/serde -o /dev/null -w "crates.io  → %{http_code} (expect 200)\n"

  # ALLOW — system.install (pypi.org, HTTPS MITM — needs firma-ca)
  curl -sx $PROXY -H "\$SESSION" --cacert "$CA_CERT" https://pypi.org/simple/requests/ -o /dev/null -w "pypi.org   → %{http_code} (expect 200)\n"

  # DENY — not mapped → default_protected blocks before Cedar
  curl -sx $PROXY -H "\$SESSION" http://evil.com/ -o /dev/null -w "evil.com   → %{http_code} (expect 403)\n"

  # DENY — cloud metadata endpoint (not mapped)
  curl -sx $PROXY -H "\$SESSION" http://169.254.169.254/ -o /dev/null -w "metadata   → %{http_code} (expect 403)\n"

  # ALLOW — code.read (GitHub MITM — GET /repos/*/*, needs firma-ca)
  curl -sx $PROXY -H "\$SESSION" --cacert "$CA_CERT" \
    https://api.github.com/repos/serde-rs/serde \
    -o /dev/null -w "github.com → %{http_code} (expect 200)\n"

  # DENY — code.destructive (hard-block in llm-agent.cedar, needs GITHUB_TOKEN)
  curl -sx $PROXY -H "\$SESSION" --cacert "$CA_CERT" -X DELETE \
    https://api.github.com/repos/owner/repo/git/refs/heads/my-branch \
    -o /dev/null -w "gh DELETE  → %{http_code} (expect 403)\n"

Layer 3 acceptance test (requires stack running):
  bash examples/generic-agent/verify-layer3.sh

Point any agent at the proxy:
  export HTTP_PROXY=$PROXY
  export HTTPS_PROXY=$PROXY
  export REQUESTS_CA_BUNDLE="$CA_CERT"   # Python / requests
  export SSL_CERT_FILE="$CA_CERT"        # Python / httpx
  export NODE_EXTRA_CA_CERTS="$CA_CERT"  # Node.js

Press Ctrl+C to stop.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
  wait
fi
