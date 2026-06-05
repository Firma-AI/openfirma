#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/common.sh"

require_tools
trap cleanup_mock_services EXIT
WORK_DIR="${ARTIFACT_ROOT}/allowlist-block"
ARTIFACT_DIR="${WORK_DIR}/seccomp"
CONFIG_PATH="${WORK_DIR}/firma.toml"
mkdir -p "${WORK_DIR}" "${ARTIFACT_DIR}"

gen_config "${CONFIG_PATH}" "${ARTIFACT_DIR}" "sync_wait" "true" "\"echo\", \"bash\", \"sh\""
start_mock_sidecar
start_mock_mediator "allow"

if run_firma "${CONFIG_PATH}" /usr/bin/env; then
  echo "[fail] allowlist block scenario unexpectedly succeeded" >&2
  exit 1
else
  echo "[ok] allowlist block scenario failed closed as expected"
fi
