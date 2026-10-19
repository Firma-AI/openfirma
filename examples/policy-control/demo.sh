#!/usr/bin/env bash
set -euo pipefail

EXAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$EXAMPLE_DIR/../.." && pwd)"
FIRMA="$ROOT/target/debug/firma"
CONFIG="$EXAMPLE_DIR/.firma/firma.toml"
STATE="$EXAMPLE_DIR/.firma/state"
AGENT_ID="agt_01j0000000e008000000000001"
SESSION_ID="policy-control-session"
TRAFFIC_PID=""

ACTIONS=(
  "filesystem.read"
  "credential.read"
  "code.write"
  "payment.transfer"
  "communication.external.send"
)

run_demo() {
  trap cleanup EXIT
  trap on_signal INT TERM

  start_stack
  start_traffic
  control
}

start_stack() {
  step "Building firma"
  cargo build -q -p firma --manifest-path "$ROOT/Cargo.toml"

  step "Preparing runtime state"
  stop_stack
  prepare_state
  start_fixture

  step "Minting demo capability"
  for action in "${ACTIONS[@]}"; do
    issue_capability "$action"
  done

  step "Starting firma stack"
  "$FIRMA" sidecar start --detach --config "$CONFIG" --state-dir "$STATE"
}

stop_stack() {
  if [[ -x "$FIRMA" ]]; then
    "$FIRMA" sidecar stop --state-dir "$STATE" --timeout 5 >/dev/null 2>&1 || true
  fi
  stop_pidfile "$STATE/fixture.pid"
}

control() {
  cd "$EXAMPLE_DIR"
  cargo run --manifest-path "$ROOT/Cargo.toml" -p firma -- \
    control \
    --config "$CONFIG" \
    --state-dir "$STATE"
}

prepare_state() {
  mkdir -p "$STATE/capabilities" "$STATE/generated-firma-ca"
  : > "$STATE/audit.jsonl"
  touch "$STATE/revocations.txt"

  if [[ ! -f "$STATE/authority.key" ]]; then
    "$FIRMA" authority generate-key --output "$STATE/authority.key"
  fi

  if [[ ! -f "$STATE/audit.key" ]]; then
    openssl genpkey \
      -algorithm EC \
      -pkeyopt ec_paramgen_curve:P-256 \
      -out "$STATE/audit.key" >/dev/null 2>&1
  fi

  rm -f "$STATE"/capabilities/capability-*.toml
}

start_fixture() {
  python3 "$EXAMPLE_DIR/fixture.py" \
    --daemon \
    --host 127.0.0.1 \
    --port 19090 \
    --pid-file "$STATE/fixture.pid" \
    --log-file "$STATE/fixture.log"
}

issue_capability() {
  local action="$1"
  local output="$STATE/capabilities/capability-${action//./-}.toml"

  "$FIRMA" authority --config "$CONFIG" issue \
    --agent-id "$AGENT_ID" \
    --session-id "$SESSION_ID" \
    --action "$action" \
    --resource-scope "*" \
    --ttl-seconds 3600 \
    --output "$output"
}

start_traffic() {
  : > "$STATE/traffic.log"
  (
    sleep 1
    cd "$EXAMPLE_DIR"
    exec env PYTHONDONTWRITEBYTECODE=1 \
      python3 -m agent operations --loop --interval 2 --delay 0.1
  ) > "$STATE/traffic.log" 2>&1 &
  TRAFFIC_PID="$!"
}

cleanup() {
  if [[ -n "${TRAFFIC_PID:-}" ]]; then
    kill "$TRAFFIC_PID" >/dev/null 2>&1 || true
    wait "$TRAFFIC_PID" >/dev/null 2>&1 || true
    TRAFFIC_PID=""
  fi
  stop_stack
}

on_signal() {
  cleanup
  trap - EXIT
  exit 130
}

stop_pidfile() {
  local pidfile="$1"
  local pid

  [[ -f "$pidfile" ]] || return 0
  pid="$(<"$pidfile")"

  if [[ "$pid" =~ ^[0-9]+$ ]]; then
    kill -TERM "-$pid" >/dev/null 2>&1 || kill "$pid" >/dev/null 2>&1 || true
  fi
  rm -f "$pidfile"
}

step() {
  printf '[INFO] %s\n' "$1"
}

usage() {
  printf 'usage: %s [run|start|control|stop]\n' "$0" >&2
}

case "${1:-run}" in
  run)
    run_demo
    ;;
  start)
    start_stack
    ;;
  control)
    control
    ;;
  stop)
    stop_stack
    ;;
  *)
    usage
    exit 2
    ;;
esac
