#!/usr/bin/env bash
# Self-contained demo of firma run HTTP-vault secret interception & redaction.
# The HTTP counterpart of ../secret-redaction/ (CLI vault shim): here the
# "vault" is an HTTP service the agent calls directly, and interception
# happens on the Sidecar's own HTTP path instead of a firma-run broker shim.
#
# Prerequisites: cargo build -p firma --release, python3, bwrap
#
# What this does:
#   1. Starts scripts/vault-server on localhost:19877 and scripts/capture-server
#      on localhost:19876 (both outside the sandbox).
#   2. Starts a per-run Authority + Sidecar (auto-started by firma run).
#   3. Runs scripts/agent.py inside the bwrap sandbox:
#        a. Agent GETs a secret from the vault. Once the request itself is
#           allowed, the Sidecar matches the response against the
#           demo-http-vault provider — the match is itself the authorization
#           — extracts the real value from the JSON response, and replaces
#           it with a firma-secret://demo-http-vault/ placeholder before the
#           agent's HTTP client sees it.
#        b. Agent POSTs {"token": "<placeholder>"} to 127.0.0.1:19876/capture
#           via the Sidecar HTTP proxy. The Sidecar resolves the placeholder
#           to the real secret before forwarding; the capture server receives
#           and logs the real value. The Sidecar then masks the real value
#           back to the placeholder in the response before the agent reads it.
#   4. Verifies that the capture server log contains the real secret, proving
#      the Sidecar both extracted it from the vault response and resolved it
#      correctly during rehydration.
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

chmod +x "${SCRIPTS_DIR}/vault-server" "${SCRIPTS_DIR}/capture-server"

VAULT_LOG="$(mktemp)"
CAPTURE_LOG="$(mktemp)"
trap 'kill "${VAULT_PID:-}" "${CAPTURE_PID:-}" 2>/dev/null || true; rm -f "${VAULT_LOG}" "${CAPTURE_LOG}"' EXIT

ok "starting mock HTTP vault on 127.0.0.1:19877"
python3 "${SCRIPTS_DIR}/vault-server" >"${VAULT_LOG}" 2>&1 &
VAULT_PID=$!

ok "starting capture server on 127.0.0.1:19876"
python3 "${SCRIPTS_DIR}/capture-server" >"${CAPTURE_LOG}" 2>&1 &
CAPTURE_PID=$!

# Wait up to 2 s for each server to be ready.
for i in $(seq 1 10); do
    sleep 0.2
    grep -q "\[vault-server\] listening" "${VAULT_LOG}" 2>/dev/null && break
    if [ "$i" -eq 10 ]; then
        cat "${VAULT_LOG}" >&2
        fail "vault server did not start in time"
    fi
done
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
"${FIRMA_BIN}" run \
    --config "${EXAMPLE_DIR}/firma.toml" \
    -- "${PYTHON3}" "${SCRIPTS_DIR}/agent.py"

ok "verifying capture server received the real secret (not the placeholder)"
echo "--- capture server log ---"
cat "${CAPTURE_LOG}"
echo "--------------------------"

grep -q 'S3cr3tP%40ssw0rd!' "${CAPTURE_LOG}" \
    || fail "capture server did not receive the real secret — Sidecar placeholder rehydration may not be working"

ok "demo complete — HTTP-vault interception and rehydration both verified"
