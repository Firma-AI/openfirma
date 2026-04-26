#!/bin/sh
set -eu

bridge_pid=""
bridge_log=""

cleanup() {
  if [ -n "$bridge_pid" ]; then
    kill "$bridge_pid" || true
  fi
}

trap cleanup EXIT INT TERM

if [ -n "${FIRMA_RUN_PROXY_BRIDGE_UPSTREAM_UDS:-}" ]; then
  runtime_dir="${FIRMA_RUN_RUNTIME_DIR:-/tmp}"
  bridge_log="${runtime_dir}/proxy-bridge.log"
  : >"${bridge_log}"
  echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] proxy bridge starting listen=${FIRMA_RUN_PROXY_LISTEN_ADDR:-127.0.0.1:18080} upstream_uds=${FIRMA_RUN_PROXY_BRIDGE_UPSTREAM_UDS}" >>"${bridge_log}"
  "${FIRMA_RUN_SELF_EXE}" __proxy-bridge \
    --listen "${FIRMA_RUN_PROXY_LISTEN_ADDR:-127.0.0.1:18080}" \
    --upstream-uds "${FIRMA_RUN_PROXY_BRIDGE_UPSTREAM_UDS}" >>"${bridge_log}" 2>&1 &
  bridge_pid="$!"
  echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] proxy bridge process spawned pid=${bridge_pid}" >>"${bridge_log}"
  # Give the bridge a brief window to bind before the wrapped command starts.
  sleep 0.3
  if ! kill -0 "$bridge_pid" 2>/dev/null; then
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] proxy bridge startup failed pid=${bridge_pid}" >>"${bridge_log}"
    echo "error: proxy bridge failed to start (see ${bridge_log})" >&2
    if [ -f "$bridge_log" ]; then
      sed -n '1,120p' "$bridge_log" >&2 || true
    fi
    exit 1
  fi
  echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] proxy bridge ready pid=${bridge_pid}" >>"${bridge_log}"
fi

exec "$@"
