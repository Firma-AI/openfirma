#!/usr/bin/env bash
# Self-contained demo of firma run secret interception & redaction.
#
# Prerequisites: cargo build -p firma --release, python3, bwrap
#
# What this does:
#   1. Starts a per-run Authority + Sidecar (auto-started by firma run).
#   2. Runs scripts/agent.py inside the bwrap sandbox.
#   3. The agent calls mock-vault (shimmed: broker intercepts stdout, replaces
#      real values with firma-secret:// placeholders) and then calls
#      mock-mcp-server (shimmed: broker rehydrates placeholders on stdin, masks
#      reflected secrets back to placeholders on stdout).
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

chmod +x "${SCRIPTS_DIR}/mock-vault" "${SCRIPTS_DIR}/mock-mcp-server"

ok "starting demo — firma run auto-starts Authority + Sidecar"
PATH="${SCRIPTS_DIR}:${PATH}" \
"${FIRMA_BIN}" run \
    --config "${EXAMPLE_DIR}/firma.toml" \
    -- python3 "${SCRIPTS_DIR}/agent.py"

ok "demo complete"
