#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
FIRMA_BIN="${ROOT_DIR}/target/release/firma"
POLICY_PATH="${ROOT_DIR}/crates/firma-run/policies/generic-local-command-v1.toml"
ARTIFACT_ROOT="${ROOT_DIR}/.artifacts/firma-local-command-governance"
SIDECAR_HOST="127.0.0.1"
SIDECAR_PORT="28992"
SIDECAR_ENDPOINT="${FIRMA_SHOWCASE_SIDECAR_ENDPOINT:-tcp://${SIDECAR_HOST}:${SIDECAR_PORT}}"
MEDIATOR_UNIX_PATH="${ARTIFACT_ROOT}/sidecar-tools.sock"
MEDIATOR_ENDPOINT="${FIRMA_SHOWCASE_MEDIATOR_ENDPOINT:-unix://${MEDIATOR_UNIX_PATH}}"
mkdir -p "${ARTIFACT_ROOT}"

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
[profiles.generic]
backend = "bwrap"

[profiles.generic.seccomp_policy]
source_policy_path = "${POLICY_PATH}"
artifact_dir = "${artifact_dir}"
verify_checksum = true
runtime_mode = "compile_on_launch"

[profiles.generic.sidecar_local_exec]
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
    --host "${SIDECAR_HOST}" --port "${SIDECAR_PORT}" &
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
  FIRMA_BUDGET_STATE_REF="budget:team-demo:2026-05" \
  "${FIRMA_BIN}" run \
    --profile generic \
    --config "${config_path}" \
    --sidecar-endpoint "${SIDECAR_ENDPOINT}" \
    -- "$@"
}
