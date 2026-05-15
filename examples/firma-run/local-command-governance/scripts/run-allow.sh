#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/common.sh"

require_tools
trap cleanup_mock_services EXIT
WORK_DIR="${ARTIFACT_ROOT}/allow"
ARTIFACT_DIR="${WORK_DIR}/seccomp"
CONFIG_PATH="${WORK_DIR}/firma-run.toml"
mkdir -p "${WORK_DIR}" "${ARTIFACT_DIR}"

gen_config "${CONFIG_PATH}" "${ARTIFACT_DIR}" "sync_wait" "false" ""
start_mock_sidecar
start_mock_mediator "allow"

if run_firma "${CONFIG_PATH}" /bin/echo "governed-allow"; then
  echo "[ok] allow scenario passed"
else
  echo "[fail] allow scenario failed unexpectedly" >&2
  exit 1
fi
