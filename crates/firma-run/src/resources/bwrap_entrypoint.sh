#!/bin/sh
set -eu

bridge_pid=""

cleanup() {
  if [ -n "$bridge_pid" ]; then
    kill "$bridge_pid" || true
  fi
}

trap cleanup EXIT INT TERM

if [ -n "${FIRMA_RUN_PROXY_BRIDGE_UPSTREAM_UDS:-}" ]; then
  "${FIRMA_RUN_SELF_EXE}" __proxy-bridge \
    --listen "${FIRMA_RUN_PROXY_LISTEN_ADDR:-127.0.0.1:18080}" \
    --upstream-uds "${FIRMA_RUN_PROXY_BRIDGE_UPSTREAM_UDS}" &
  bridge_pid="$!"
  # Give the bridge a brief window to bind before the wrapped command starts.
  sleep 0.2
fi

exec "$@"
