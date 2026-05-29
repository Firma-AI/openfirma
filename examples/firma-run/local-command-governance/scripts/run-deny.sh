#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/common.sh"

require_tools
trap cleanup_mock_services EXIT
WORK_DIR="${ARTIFACT_ROOT}/deny"
ARTIFACT_DIR="${WORK_DIR}/seccomp"
CONFIG_PATH="${WORK_DIR}/firma.toml"
mkdir -p "${WORK_DIR}" "${ARTIFACT_DIR}"

gen_config "${CONFIG_PATH}" "${ARTIFACT_DIR}" "sync_wait" "false" ""
start_mock_sidecar
start_mock_mediator "deny"

if run_firma "${CONFIG_PATH}" /bin/echo "governed-deny"; then
  echo "[fail] deny scenario unexpectedly succeeded" >&2
  exit 1
else
  echo "[ok] deny scenario failed closed as expected"
fi
