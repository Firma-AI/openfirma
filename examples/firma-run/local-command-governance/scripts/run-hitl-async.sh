#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/common.sh"

require_tools
trap cleanup_mock_services EXIT
WORK_DIR="${ARTIFACT_ROOT}/hitl-async"
ARTIFACT_DIR="${WORK_DIR}/seccomp"
CONFIG_PATH="${WORK_DIR}/firma-run.toml"
mkdir -p "${WORK_DIR}" "${ARTIFACT_DIR}"

gen_config "${CONFIG_PATH}" "${ARTIFACT_DIR}" "async_token" "false" ""
start_mock_sidecar
start_mock_mediator "hitl_async"

if run_firma "${CONFIG_PATH}" /bin/echo "governed-hitl"; then
  echo "[fail] hitl async scenario unexpectedly succeeded" >&2
  exit 1
else
  echo "[ok] hitl async scenario failed closed (pending token path) as expected"
fi
