#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
FIRMA_BIN="${ROOT_DIR}/target/release/firma"
POLICY_PATH="${ROOT_DIR}/crates/firma-run/policies/generic-local-command-v1.toml"
ARTIFACT_ROOT="${ROOT_DIR}/.artifacts/firma-local-command-governance"
DEFAULT_RUNTIME_SOCK_DIR="${XDG_RUNTIME_DIR:-/tmp}"
if mkdir -p "${DEFAULT_RUNTIME_SOCK_DIR}" >/dev/null 2>&1 && [ -w "${DEFAULT_RUNTIME_SOCK_DIR}" ]; then
  RUNTIME_SOCK_DIR="${DEFAULT_RUNTIME_SOCK_DIR}"
else
  RUNTIME_SOCK_DIR="${ARTIFACT_ROOT}/sockets"
fi
SIDECAR_HOST="127.0.0.1"
SIDECAR_PORT="28992"
SIDECAR_UNIX_PATH="${FIRMA_SHOWCASE_SIDECAR_UNIX_PATH:-${RUNTIME_SOCK_DIR}/firma-showcase-sidecar.sock}"
SIDECAR_ENDPOINT="${FIRMA_SHOWCASE_SIDECAR_ENDPOINT:-unix://${SIDECAR_UNIX_PATH}}"
MEDIATOR_UNIX_PATH="${FIRMA_SHOWCASE_MEDIATOR_UNIX_PATH:-${RUNTIME_SOCK_DIR}/firma-showcase-sidecar-tools.sock}"
MEDIATOR_ENDPOINT="${FIRMA_SHOWCASE_MEDIATOR_ENDPOINT:-unix://${MEDIATOR_UNIX_PATH}}"
mkdir -p "${ARTIFACT_ROOT}"
mkdir -p "${RUNTIME_SOCK_DIR}" || true

require_tools() {
  command -v python3 >/dev/null 2>&1 || {
    echo "python3 is required for mock mediator demo scripts" >&2
    exit 1
  }
  test -x "${FIRMA_BIN}" || {
    echo "Missing ${FIRMA_BIN}. Run: cargo build -p firma --release" >&2
    exit 1
  }
}

gen_config() {
  local config_path="$1"
  local artifact_dir="$2"
  local hitl_mode="$3"
  local enforce_allowlist="$4"
  local allowlist_csv="$5"

  cat >"${config_path}" <<CFG
[run.profiles.generic]
backend = "bwrap"

[run.profiles.generic.seccomp_policy]
source_policy_path = "${POLICY_PATH}"
artifact_dir = "${artifact_dir}"
verify_checksum = true
runtime_mode = "compile_on_launch"

[run.profiles.generic.sidecar_local_exec]
endpoint = "${MEDIATOR_ENDPOINT}"
timeout_ms = 600
hitl_mode = "${hitl_mode}"
enforce_known_executables = ${enforce_allowlist}
allowed_executables = [${allowlist_csv}]
CFG
}

start_mock_mediator() {
  local mode="$1"
  if [ -n "${FIRMA_SHOWCASE_MEDIATOR_ENDPOINT:-}" ]; then
    return 0
  fi
  python3 "${ROOT_DIR}/examples/firma-run/local-command-governance/scripts/mock_mediator.py" \
    --mode "${mode}" --unix-path "${MEDIATOR_UNIX_PATH}" --once &
  MEDIATOR_PID=$!
  sleep 0.2
}

start_mock_sidecar() {
  if [ -n "${FIRMA_SHOWCASE_SIDECAR_ENDPOINT:-}" ]; then
    return 0
  fi
  python3 "${ROOT_DIR}/examples/firma-run/local-command-governance/scripts/mock_sidecar.py" \
    --unix-path "${SIDECAR_UNIX_PATH}" &
  SIDECAR_PID=$!
  sleep 0.2
}

cleanup_mock_services() {
  if [ -n "${MEDIATOR_PID:-}" ]; then
    kill "${MEDIATOR_PID}" 2>/dev/null || true
    wait "${MEDIATOR_PID}" 2>/dev/null || true
  fi
  if [ -n "${SIDECAR_PID:-}" ]; then
    kill "${SIDECAR_PID}" 2>/dev/null || true
    wait "${SIDECAR_PID}" 2>/dev/null || true
  fi
}

run_firma() {
  local config_path="$1"
  shift
  "${FIRMA_BIN}" run \
    --profile generic \
    --config "${config_path}" \
    --sidecar-endpoint "${SIDECAR_ENDPOINT}" \
    -- "$@"
}
