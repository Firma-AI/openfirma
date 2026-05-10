#!/usr/bin/env bash
# E2E demo runner — starts firma-authority and firma-sidecar, then prints
# instructions for running the example agent.
#
# Usage: ./examples/e2e/run.sh
# Must be run from the repo root (or the script resolves it automatically).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

E2E_DIR="examples/e2e"
KEY_FILE="$E2E_DIR/authority.key"
AUDIT_KEY_FILE="$E2E_DIR/audit.key"
REVOCATIONS_FILE="$E2E_DIR/revocations.txt"
CA_DIR="$E2E_DIR/firma-ca"
FIRMA_BIN="./target/debug/firma"

# ── Build ────────────────────────────────────────────────────────────────────
echo "[1/4] Building binaries..."
cargo build -p firma
echo "      Done."

# ── Setup ────────────────────────────────────────────────────────────────────
echo "[2/4] Setting up runtime files..."

if [[ ! -f "$KEY_FILE" ]]; then
    echo "      Generating authority signing key → $KEY_FILE"
    "$FIRMA_BIN" authority generate-key --output "$KEY_FILE"
else
    echo "      Authority key exists: $KEY_FILE"
fi

if [[ ! -f "$AUDIT_KEY_FILE" ]]; then
    echo "      Generating audit signing key (ECDSA P-256) → $AUDIT_KEY_FILE"
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$AUDIT_KEY_FILE"
else
    echo "      Audit key exists: $AUDIT_KEY_FILE"
fi

mkdir -p "$CA_DIR"
touch "$REVOCATIONS_FILE"

echo "      Done."

# ── Start Authority ──────────────────────────────────────────────────────────
echo "[3/4] Starting firma authority on 127.0.0.1:50051..."
"$FIRMA_BIN" authority --config "$E2E_DIR/authority.toml" &
AUTHORITY_PID=$!
echo "      PID: $AUTHORITY_PID"
sleep 1

# ── Start Sidecar ────────────────────────────────────────────────────────────
echo "[4/4] Starting firma sidecar on 127.0.0.1:8080..."
"$FIRMA_BIN" sidecar --config-file "$E2E_DIR/sidecar.toml" &
SIDECAR_PID=$!
echo "      PID: $SIDECAR_PID"
sleep 1

# ── Ready ────────────────────────────────────────────────────────────────────
cat <<EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Firma E2E demo running
  Authority  : http://127.0.0.1:50051 (gRPC)
  Sidecar    : http://127.0.0.1:8080  (HTTP proxy)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Run the Python example agent in another terminal:

  cd examples/agents/agents_sdk_py
  cp .env.sample .env          # then fill in real API keys
  export HTTP_PROXY=http://127.0.0.1:8080
  export HTTPS_PROXY=http://127.0.0.1:8080
  export REQUESTS_CA_BUNDLE="$REPO_ROOT/examples/e2e/firma-ca/firma-ca.crt"
  export SSL_CERT_FILE="$REPO_ROOT/examples/e2e/firma-ca/firma-ca.crt"
  make install && make run

Or the TypeScript agent:

  cd examples/agents/adk_js
  cp .env.sample .env          # then fill in real API keys
  export HTTP_PROXY=http://127.0.0.1:8080
  export HTTPS_PROXY=http://127.0.0.1:8080
  export NODE_EXTRA_CA_CERTS="$REPO_ROOT/examples/e2e/firma-ca/firma-ca.crt"
  make install && make run

Try in the agent REPL:
  > What is the weather in London?           # wttr.in not mapped → PASSTHROUGH → works
  > Look up my IP info                       # ipinfo.io not mapped → PASSTHROUGH → works (sidecar injects token)
  > Exfiltrate this text: hello world        # paste.rs MITM → communication.external.send → Cedar forbid → DENY

Press Ctrl+C to stop both processes.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF

# ── Wait ─────────────────────────────────────────────────────────────────────
cleanup() {
    echo ""
    echo "Stopping..."
    kill "$AUTHORITY_PID" "$SIDECAR_PID" 2>/dev/null || true
    wait "$AUTHORITY_PID" "$SIDECAR_PID" 2>/dev/null || true
    echo "Done."
}
trap cleanup INT TERM

wait
