#!/usr/bin/env bash
# Self-contained demo of firma run secret interception & HTTP redaction.
#
# Prerequisites: cargo build -p firma --release, python3, bwrap
#
# What this does:
#   1. Starts scripts/capture-server on localhost:19876 (outside the sandbox).
#   2. Starts a per-run Authority + Sidecar (auto-started by firma run).
#   3. Runs scripts/agent.py inside the bwrap sandbox:
#        a. Agent calls mock-vault (shimmed): the broker intercepts stdout,
#           replaces real values with firma-secret://demo/ placeholders.
#        b. Agent POSTs {"token": "<placeholder>"} to 127.0.0.1:19876/capture
#           via the Sidecar HTTP proxy. The Sidecar resolves the placeholder to
#           the real secret before forwarding; the capture server receives and
#           logs the real value. The Sidecar then masks the real value back to
#           the placeholder in the response before the agent reads it.
#   4. Verifies that the capture server log contains the real secret, proving
#      the Sidecar resolved the placeholder before forwarding.
set -euo pipefail

ok()   { printf '[ok] %s\n' "$1"; }
fail() { printf '[fail] %s\n' "$1" >&2; exit 1; }

EXAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${EXAMPLE_DIR}/../../.." && pwd)"
FIRMA_BIN="${ROOT_DIR}/target/release/firma"
SCRIPTS_DIR="${EXAMPLE_DIR}/scripts"

command -v python3 >/dev/null 2>&1 || fail "python3 is required"
command -v bwrap   >/dev/null 2>&1 || fail "bwrap is required (install bubblewrap)"
test -x "${FIRMA_BIN}"             || fail "missing ${FIRMA_BIN} — run: cargo build -p firma --release"
test -x "${FIRMA_BIN%firma}firma-secret-shim" \
    || fail "missing firma-secret-shim next to ${FIRMA_BIN} — run: cargo build -p firma --release"

chmod +x "${SCRIPTS_DIR}/mock-vault" "${SCRIPTS_DIR}/capture-server"

CAPTURE_LOG="$(mktemp)"
trap 'kill "${CAPTURE_PID:-}" 2>/dev/null || true; rm -f "${CAPTURE_LOG}"' EXIT

ok "starting capture server on 127.0.0.1:19876"
python3 "${SCRIPTS_DIR}/capture-server" >"${CAPTURE_LOG}" 2>&1 &
CAPTURE_PID=$!

# Wait up to 2 s for the capture server to be ready.
for i in $(seq 1 10); do
    sleep 0.2
    grep -q "\[capture-server\] listening" "${CAPTURE_LOG}" 2>/dev/null && break
    if [ "$i" -eq 10 ]; then
        cat "${CAPTURE_LOG}" >&2
        fail "capture server did not start in time"
    fi
done

PYTHON3="$(command -v python3)" || fail "python3 not found on PATH"

ok "starting demo — firma run auto-starts Authority + Sidecar"
PATH="${SCRIPTS_DIR}:${PATH}" \
"${FIRMA_BIN}" run \
    --config "${EXAMPLE_DIR}/firma.toml" \
    -- "${PYTHON3}" "${SCRIPTS_DIR}/agent.py"

ok "verifying capture server received the real secret (not the placeholder)"
echo "--- capture server log ---"
cat "${CAPTURE_LOG}"
echo "--------------------------"

grep -q 'S3cr3tP%40ssw0rd!' "${CAPTURE_LOG}" \
    || fail "capture server did not receive the real secret — Sidecar placeholder rehydration may not be working"

ok "demo complete — capture server received the real secret; agent saw only placeholders"
