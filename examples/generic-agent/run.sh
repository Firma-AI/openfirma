#!/usr/bin/env bash
# Generic agent stack runner.
# Starts firma-authority + firma-sidecar, then prints curl smoke-test commands.
#
# Usage (from repo root):
#   bash examples/generic-agent/run.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

DIR="examples/generic-agent"
RUNTIME="$DIR/.runtime"
AUTHORITY_BIN="./target/debug/firma-authority"
SIDECAR_BIN="./target/debug/firma-sidecar"

# ── Build ─────────────────────────────────────────────────────────────────────
echo "[1/4] Building..."
cargo build -p firma-authority -p firma-sidecar
echo "      Done."

# ── Setup runtime dir ────────────────────────────────────────────────────────
echo "[2/4] Setting up .runtime/..."
mkdir -p "$RUNTIME/generated-firma-ca"

# Remove stale capability tokens — preflight will re-issue on startup.
rm -f "$DIR"/capability-*.toml

if [[ ! -f "$RUNTIME/authority.key" ]]; then
    "$AUTHORITY_BIN" generate-key --output "$RUNTIME/authority.key"
    echo "      Generated authority key."
fi

if [[ ! -f "$RUNTIME/audit.key" ]]; then
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
        -out "$RUNTIME/audit.key" 2>/dev/null
    echo "      Generated audit key."
fi

touch "$RUNTIME/revocations.txt"
echo "      Done."

# ── Start Authority ───────────────────────────────────────────────────────────
echo "[3/4] Starting firma-authority on 127.0.0.1:50051..."
"$AUTHORITY_BIN" --config "$DIR/firma.toml" &
AUTHORITY_PID=$!
sleep 1

# ── Start Sidecar ─────────────────────────────────────────────────────────────
echo "[4/4] Starting firma-sidecar on 127.0.0.1:7474..."
"$SIDECAR_BIN" --config "$DIR/firma.toml" &
SIDECAR_PID=$!
sleep 2

CA_CERT="$REPO_ROOT/$RUNTIME/generated-firma-ca/firma-ca.crt"
PROXY="http://127.0.0.1:7474"

# ── Ready ─────────────────────────────────────────────────────────────────────
cat <<EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Generic agent stack running
  Authority : 127.0.0.1:50051 (gRPC)
  Sidecar   : 127.0.0.1:7474  (HTTP proxy)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

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

Point any agent at the proxy:
  export HTTP_PROXY=$PROXY
  export HTTPS_PROXY=$PROXY
  export REQUESTS_CA_BUNDLE="$CA_CERT"   # Python / requests
  export SSL_CERT_FILE="$CA_CERT"        # Python / httpx
  export NODE_EXTRA_CA_CERTS="$CA_CERT"  # Node.js

Press Ctrl+C to stop.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF

cleanup() {
    echo ""
    echo "Stopping..."
    kill "$AUTHORITY_PID" "$SIDECAR_PID" 2>/dev/null || true
    wait "$AUTHORITY_PID" "$SIDECAR_PID" 2>/dev/null || true
}
trap cleanup INT TERM

wait
