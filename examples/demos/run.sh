#!/usr/bin/env bash
# Direct demo runner for examples/demos without the TUI.
#
# Usage:
#   ./examples/demos/run.sh demo0
#   ./examples/demos/run.sh demo1 --prompt "Fetch usage and billing for user-123"
#   ./examples/demos/run.sh demo2 --no-agent
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

DEMO="${1:-}"
if [[ -z "$DEMO" || "$DEMO" == "-h" || "$DEMO" == "--help" ]]; then
    cat <<'EOF'
Usage: ./examples/demos/run.sh <demo0|demo1|demo2> [--prompt TEXT] [--no-agent] [--no-build]

Starts firma-authority and firma-sidecar with the selected demo config,
provisions demo-local runtime files, writes audit logs to
examples/demos/<demo>/.runtime/audit.jsonl, and runs the Python agent
through the sidecar proxy unless --no-agent is set.
EOF
    exit 0
fi
shift || true

PROMPT=""
RUN_AGENT=1
BUILD=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prompt)
            PROMPT="${2:-}"
            shift 2
            ;;
        --no-agent)
            RUN_AGENT=0
            shift
            ;;
        --no-build)
            BUILD=0
            shift
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

DEMO_DIR="examples/demos/$DEMO"
if [[ ! -d "$DEMO_DIR" || ! -f "$DEMO_DIR/sidecar.toml" || ! -f "$DEMO_DIR/authority.toml" ]]; then
    echo "Unknown demo '$DEMO'. Expected demo0, demo1, or demo2." >&2
    exit 2
fi

AUTHORITY_BIN="./target/debug/firma-authority"
SIDECAR_BIN="./target/debug/firma-sidecar"
RUNTIME_DIR="$DEMO_DIR/.runtime"
AUTHORITY_KEY="$RUNTIME_DIR/authority.key"
AUDIT_KEY="$RUNTIME_DIR/audit.key"
REVOCATIONS="$RUNTIME_DIR/revocations.txt"
CA_DIR="$RUNTIME_DIR/generated-firma-ca"
AUDIT_LOG="$RUNTIME_DIR/audit.jsonl"

if [[ "$BUILD" -eq 1 ]]; then
    echo "[1/4] Building binaries..."
    cargo build -p firma-authority -p firma-sidecar
else
    echo "[1/4] Skipping build."
fi

echo "[2/4] Preparing runtime files..."
mkdir -p "$RUNTIME_DIR" "$CA_DIR"
touch "$REVOCATIONS"
: > "$AUDIT_LOG"

if [[ ! -f "$AUTHORITY_KEY" ]]; then
    "$AUTHORITY_BIN" generate-key --output "$AUTHORITY_KEY"
fi

if [[ ! -f "$AUDIT_KEY" ]]; then
    cat > "$AUDIT_KEY" <<'EOF'
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgS+9b9zHd22EAeg9M
bXfQcvk+kh+UDhxsRkIm8BsBd4ihRANCAARrNl5iPKSasLwfIihEcv8BeQsqAXMl
3wlh7RZmOnI0E3wNCaMKd3B7Sd/fXknJ0WmI6BsrvfidxQEAYvsndbvx
-----END PRIVATE KEY-----
EOF
fi

cleanup() {
    echo
    echo "Stopping demo processes..."
    if [[ -n "${AGENT_PID:-}" ]]; then
        kill "$AGENT_PID" 2>/dev/null || true
        wait "$AGENT_PID" 2>/dev/null || true
    fi
    kill "$AUTHORITY_PID" "$SIDECAR_PID" 2>/dev/null || true
    wait "$AUTHORITY_PID" "$SIDECAR_PID" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

echo "[3/4] Starting firma-authority..."
"$AUTHORITY_BIN" --config "$DEMO_DIR/authority.toml" &
AUTHORITY_PID=$!
sleep 1

echo "[4/4] Starting firma-sidecar..."
"$SIDECAR_BIN" --config-file "$DEMO_DIR/sidecar.toml" &
SIDECAR_PID=$!
sleep 1

cat <<EOF

Demo running:
  Demo      : $DEMO
  Authority : 127.0.0.1:50051
  Sidecar   : http://127.0.0.1:8080
  Audit log : $AUDIT_LOG

EOF

if [[ "$RUN_AGENT" -eq 1 ]]; then
    echo "Starting agent through sidecar proxy..."
    (
        cd examples/demos
        uv sync
        export HTTP_PROXY="http://127.0.0.1:8080"
        export HTTPS_PROXY="http://127.0.0.1:8080"
        export NO_PROXY="localhost,127.0.0.1,0.0.0.0,::1"
        export FIRMA_DEMO_PROMPT="$PROMPT"
        uv run "$DEMO/agent.py"
    ) &
    AGENT_PID=$!
fi

if [[ "$RUN_AGENT" -eq 1 ]]; then
    wait "$AGENT_PID"
else
    wait "$AUTHORITY_PID" "$SIDECAR_PID"
fi
