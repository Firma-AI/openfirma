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
"$AUTHORITY_BIN" --config "$DIR/authority.toml" &
AUTHORITY_PID=$!
sleep 1

# ── Start Sidecar ─────────────────────────────────────────────────────────────
echo "[4/4] Starting firma-sidecar on 127.0.0.1:7474..."
"$SIDECAR_BIN" --config-file "$DIR/sidecar.toml" &
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

Smoke tests — run in another terminal:

  # ALLOW — system.install (pypi.org mapped)
  curl -sx $PROXY http://pypi.org/simple/requests/ -o /dev/null -w "%{http_code}\n"

  # ALLOW — system.install (crates.io mapped)
  curl -sx $PROXY http://crates.io/api/v1/crates/serde -o /dev/null -w "%{http_code}\n"

  # DENY — not mapped → default_protected blocks before Cedar
  curl -sx $PROXY http://evil.com/ -o /dev/null -w "%{http_code}\n"

  # DENY — cloud metadata endpoint (not mapped)
  curl -sx $PROXY http://169.254.169.254/latest/meta-data/ -o /dev/null -w "%{http_code}\n"

  # ALLOW — code.review.read (GitHub MITM, needs firma-ca)
  curl -sx $PROXY --cacert "$CA_CERT" https://api.github.com/zen

  # DENY — code.destructive (hard-block in llm-agent.cedar)
  # Requires a GitHub token: -H "Authorization: token \$GITHUB_TOKEN"
  curl -sx $PROXY --cacert "$CA_CERT" -X DELETE \
    https://api.github.com/repos/owner/repo/git/refs/heads/my-branch \
    -o /dev/null -w "%{http_code}\n"

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
