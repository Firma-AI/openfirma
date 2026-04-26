#!/usr/bin/env bash
set -euo pipefail

ok() { printf '[ok] %s\n' "$1"; }
warn() { printf '[warn] %s\n' "$1"; }
fail() { printf '[fail] %s\n' "$1" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  scripts/e2e-firma-run.sh [--cmd "<shell command>"] [--keep-artifacts]

Description:
  End-to-end local harness for FIR-61 runtime plumbing.
  It:
    1) boots a local firma-sidecar with temporary config,
    2) runs a sandboxed command via firma run,
    3) asserts sidecar audit events were emitted,
    4) verifies fail-closed behavior when sidecar is down.

Options:
  --cmd "<command>"   Command executed inside sandbox (default: HTTP smoke request)
  --keep-artifacts    Keep temp files/logs for debugging
  -h, --help          Show this help

Examples:
  scripts/e2e-firma-run.sh
  scripts/e2e-firma-run.sh --cmd "cd example_agents/agents_sdk_py && uv run python -m agent.main"
EOF
}

require_command() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || fail "required command not found: $cmd"
}

http_ok() {
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsS "$url" >/dev/null 2>&1
    return $?
  fi

  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY' "$url" >/dev/null 2>&1
import sys
import urllib.request

urllib.request.urlopen(sys.argv[1], timeout=1.5).read()
PY
    return $?
  fi

  return 1
}

wait_for_health() {
  local addr="$1"
  local attempts=80

  for _ in $(seq 1 "$attempts"); do
    if http_ok "http://${addr}/healthz"; then
      return 0
    fi
    sleep 0.25
  done

  return 1
}

stop_sidecar() {
  if [[ -n "${SIDECAR_PID:-}" ]] && kill -0 "$SIDECAR_PID" >/dev/null 2>&1; then
    kill "$SIDECAR_PID" >/dev/null 2>&1 || true
    wait "$SIDECAR_PID" >/dev/null 2>&1 || true
  fi
  SIDECAR_PID=""
}

KEEP_ARTIFACTS=0
USER_CMD=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cmd)
      shift
      [[ $# -gt 0 ]] || fail "--cmd requires a value"
      USER_CMD="$1"
      ;;
    --keep-artifacts)
      KEEP_ARTIFACTS=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
  shift
done

if [[ "$(uname -s)" != "Linux" ]]; then
  fail "this E2E harness is Linux-only (FIR-61 scope)"
fi

require_command cargo
require_command bwrap

WORKDIR="$(mktemp -d /tmp/firma-run-e2e.XXXXXX)"
SIDECAR_PID=""
SIDECAR_PORT="$((RANDOM % 5000 + 18080))"
HEALTH_PORT="$((RANDOM % 5000 + 23080))"
HEALTH_ADDR="127.0.0.1:${HEALTH_PORT}"

SIDECAR_CONFIG="${WORKDIR}/sidecar.toml"
MAPPING_RULES="${WORKDIR}/mapping-rules.toml"
AUDIT_FILE="${WORKDIR}/audit.jsonl"
SIDECAR_LOG="${WORKDIR}/sidecar.log"
RUN_STDOUT="${WORKDIR}/run.stdout.log"
RUN_STDERR="${WORKDIR}/run.stderr.log"
FAIL_STDERR="${WORKDIR}/fail-closed.stderr.log"
AUDIT_KEY="${WORKDIR}/audit-key.pem"

cleanup() {
  stop_sidecar
  if [[ "$KEEP_ARTIFACTS" -eq 1 ]]; then
    warn "keeping artifacts in ${WORKDIR}"
    return
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

cat >"$AUDIT_KEY" <<'EOF'
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgS+9b9zHd22EAeg9M
bXfQcvk+kh+UDhxsRkIm8BsBd4ihRANCAARrNl5iPKSasLwfIihEcv8BeQsqAXMl
3wlh7RZmOnI0E3wNCaMKd3B7Sd/fXknJ0WmI6BsrvfidxQEAYvsndbvx
-----END PRIVATE KEY-----
EOF

cat >"$MAPPING_RULES" <<'EOF'
[[rules]]
method = "GET"
host = "never.match.local"
path = "/"
action_class = "communication.external.send"
EOF

cat >"$SIDECAR_CONFIG" <<EOF
[interceptor]
mode = "http_proxy"
listen_addr = "127.0.0.1:${SIDECAR_PORT}"
drain_timeout_secs = 5

[mapping]
rules_path = "${MAPPING_RULES}"
default_protected = false

[audit]
sink = "file"
file_path = "${AUDIT_FILE}"
signing_key_path = "${AUDIT_KEY}"

[log]
level = "info"
EOF

if [[ -n "$USER_CMD" ]]; then
  SANDBOX_CMD=(/bin/sh -lc "$USER_CMD")
else
  if command -v curl >/dev/null 2>&1; then
    SANDBOX_CMD=(curl -fsS --max-time 20 http://httpbin.org/get)
  elif command -v python3 >/dev/null 2>&1; then
    SANDBOX_CMD=(python3 -c 'import urllib.request; print(urllib.request.urlopen("http://httpbin.org/get", timeout=20).read().decode())')
  else
    fail "no default HTTP client found (need curl or python3), or pass --cmd"
  fi
fi

ok "starting local sidecar on 127.0.0.1:${SIDECAR_PORT}"
cargo run -p firma-sidecar -- -c "$SIDECAR_CONFIG" --health-bind-addr "$HEALTH_ADDR" -l info >"$SIDECAR_LOG" 2>&1 &
SIDECAR_PID=$!

if ! wait_for_health "$HEALTH_ADDR"; then
  sed -n '1,200p' "$SIDECAR_LOG" >&2 || true
  fail "sidecar failed health check at ${HEALTH_ADDR}"
fi
ok "sidecar is healthy"

ok "running sandboxed command through firma run"
cargo run -p firma-run -- run \
  --profile generic \
  --sidecar-endpoint "tcp://127.0.0.1:${SIDECAR_PORT}" \
  -- "${SANDBOX_CMD[@]}" >"$RUN_STDOUT" 2>"$RUN_STDERR"

if [[ ! -s "$AUDIT_FILE" ]]; then
  sed -n '1,200p' "$SIDECAR_LOG" >&2 || true
  fail "no audit events were written to ${AUDIT_FILE}"
fi

if ! grep -q '"decision":1' "$AUDIT_FILE"; then
  fail "audit file has no ALLOW decision events"
fi

if ! grep -Eq '"dispatch_status":[1-9][0-9]*' "$AUDIT_FILE"; then
  fail "audit file has no dispatched response status"
fi
ok "audit sink recorded sandboxed traffic"

ok "verifying fail-closed when sidecar is unavailable"
stop_sidecar

set +e
cargo run -p firma-run -- run \
  --profile generic \
  --sidecar-endpoint "tcp://127.0.0.1:${SIDECAR_PORT}" \
  -- "${SANDBOX_CMD[@]}" >/dev/null 2>"$FAIL_STDERR"
STATUS=$?
set -e

if [[ "$STATUS" -eq 0 ]]; then
  fail "expected non-zero exit when sidecar is down, got 0"
fi

if ! grep -Eq "unreachable|sidecar|backend error" "$FAIL_STDERR"; then
  warn "fail-closed command failed as expected but stderr had no sidecar keyword"
fi

ok "fail-closed behavior verified (exit=${STATUS})"
ok "E2E complete"
if [[ "$KEEP_ARTIFACTS" -eq 1 ]]; then
  ok "artifacts: ${WORKDIR}"
fi
