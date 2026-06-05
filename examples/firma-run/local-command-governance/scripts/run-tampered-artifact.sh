#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/common.sh"

require_tools
trap cleanup_mock_services EXIT
WORK_DIR="${ARTIFACT_ROOT}/tampered-artifact"
ARTIFACT_DIR="${WORK_DIR}/seccomp"
CONFIG_PATH="${WORK_DIR}/firma.toml"
mkdir -p "${WORK_DIR}" "${ARTIFACT_DIR}"

gen_config "${CONFIG_PATH}" "${ARTIFACT_DIR}" "sync_wait" "false" ""
start_mock_sidecar
start_mock_mediator "allow"

# First run compiles and writes managed artifact.
run_firma "${CONFIG_PATH}" /bin/echo "prime-artifact" >/dev/null
MEDIATOR_PID=""

ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64|amd64) TARGET_ARCH="x86_64" ;;
  aarch64|arm64) TARGET_ARCH="aarch64" ;;
  *)
    echo "[fail] unsupported architecture for demo: ${ARCH}" >&2
    exit 1
    ;;
esac

BPF_PATH="${ARTIFACT_DIR}/generic-local-command/v1/${TARGET_ARCH}/policy.bpf"
if [ ! -f "${BPF_PATH}" ]; then
  echo "[fail] expected managed artifact not found at ${BPF_PATH}" >&2
  exit 1
fi

printf '\n#tampered\n' >> "${BPF_PATH}"
# Force load-only behavior so runtime cannot recompile and overwrite the tampered artifact.
sed -i.bak 's/runtime_mode = "compile_on_launch"/runtime_mode = "precompiled_only"/' "${CONFIG_PATH}"
rm -f "${CONFIG_PATH}.bak"
start_mock_mediator "allow"

if run_firma "${CONFIG_PATH}" /bin/echo "tampered-artifact"; then
  echo "[fail] tampered artifact scenario unexpectedly succeeded" >&2
  exit 1
else
  echo "[ok] tampered artifact scenario failed closed on checksum mismatch"
fi
