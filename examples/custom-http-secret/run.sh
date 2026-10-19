#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EXAMPLE_DIR="$REPO_ROOT/examples/custom-http-secret"
RUNTIME_DIR="$EXAMPLE_DIR/.runtime"
RECEIPT="$RUNTIME_DIR/received-body.json"
CLIENT_OUTPUT="$RUNTIME_DIR/client-output.log"
SERVER_PID=""
cd "$REPO_ROOT"

cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

if [[ "$(uname -s)" != "Linux" ]]; then
  printf 'ERROR: this example requires the Linux bwrap backend\n' >&2
  exit 1
fi

for command_name in bwrap cargo curl python3; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'ERROR: %s is required\n' "$command_name" >&2
    exit 1
  }
done

mkdir -p "$RUNTIME_DIR"
rm -f "$RECEIPT"
touch "$RUNTIME_DIR/revocations.txt"

python3 "$EXAMPLE_DIR/mock_server.py" --receipt "$RECEIPT" &
SERVER_PID=$!
for _ in $(seq 1 40); do
  if curl --noproxy '*' --fail --silent http://127.0.0.1:18081/health >/dev/null; then
    break
  fi
  sleep 0.1
done
if ! curl --noproxy '*' --fail --silent http://127.0.0.1:18081/health >/dev/null; then
  printf 'ERROR: local mock server failed to start\n' >&2
  exit 1
fi

printf 'Building firma...\n'
cargo build -q -p firma --bin firma
WORKSPACE_ROOT="$(dirname "$(cargo locate-project --workspace --message-format plain)")"
FIRMA_BIN="$WORKSPACE_ROOT/target/debug/firma"

printf 'Running the custom HTTP provider example...\n'
rm -f "$CLIENT_OUTPUT"
"$FIRMA_BIN" run \
  --profile generic \
  --config "$EXAMPLE_DIR/firma.toml" \
  -- bash "$EXAMPLE_DIR/client.sh" | tee "$CLIENT_OUTPUT"

client_output="$(<"$CLIENT_OUTPUT")"
if [[ "$client_output" == *"local-http-secret"* ]]; then
  printf 'ERROR: sandboxed client output contained the plaintext secret\n' >&2
  exit 1
fi
printf 'PASS: captured client output contained no plaintext.\n'

if [[ ! -f "$RECEIPT" ]]; then
  printf 'ERROR: mock server did not record the rehydrated request\n' >&2
  exit 1
fi
receipt_body="$(<"$RECEIPT")"
if [[ "$receipt_body" != *"local-http-secret"* ]]; then
  printf 'ERROR: mock server did not receive the rehydrated plaintext\n' >&2
  exit 1
fi
if [[ "$receipt_body" == *"fsp_"* ]]; then
  printf 'ERROR: mock server received an unresolved placeholder\n' >&2
  exit 1
fi

printf 'Mock server received after Sidecar rehydration:\n%s\n' "$receipt_body"
printf 'PASS: plaintext was revealed only to the host-local mock server.\n'
