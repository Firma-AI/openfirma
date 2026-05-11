#!/usr/bin/env bash
set -euo pipefail

fail() { printf '[fail] %s\n' "$1" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
SRC="${ROOT_DIR}/spikes/firma-run/fir-111/unotify-prototype/seccomp_unotify_runner.c"
BUILD_DIR="${ROOT_DIR}/target/fir-111-unotify"
BIN="${BUILD_DIR}/seccomp_unotify_runner"

WORKLOAD=""
INNER_LOOPS=120
PROFILE="generic"
SIDECAR_ENDPOINT=""
FAILURE_MODE="none"
FIRMA_BIN="target/debug/firma"
POLICY_MODE="${FIR_UNOTIFY_POLICY_MODE:-allow-all}"
SLOW_DELAY_MS="${FIR_UNOTIFY_SLOW_DELAY_MS:-5}"
SLOW_MAX_NOTIFS="${FIR_UNOTIFY_SLOW_MAX_NOTIFS:-1}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workload)
      shift
      [[ $# -gt 0 ]] || fail "--workload requires a value"
      WORKLOAD="$1"
      ;;
    --inner-loops)
      shift
      [[ $# -gt 0 ]] || fail "--inner-loops requires a value"
      INNER_LOOPS="$1"
      ;;
    --profile)
      shift
      [[ $# -gt 0 ]] || fail "--profile requires a value"
      PROFILE="$1"
      ;;
    --sidecar-endpoint)
      shift
      [[ $# -gt 0 ]] || fail "--sidecar-endpoint requires a value"
      SIDECAR_ENDPOINT="$1"
      ;;
    --failure-mode)
      shift
      [[ $# -gt 0 ]] || fail "--failure-mode requires a value"
      FAILURE_MODE="$1"
      ;;
    --firma-bin)
      shift
      [[ $# -gt 0 ]] || fail "--firma-bin requires a value"
      FIRMA_BIN="$1"
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
  shift
done

[[ -n "$WORKLOAD" ]] || fail "missing --workload"
[[ -n "$SIDECAR_ENDPOINT" ]] || fail "missing --sidecar-endpoint"
[[ -x "$FIRMA_BIN" ]] || fail "firma binary is not executable: $FIRMA_BIN"
[[ -f "$SRC" ]] || fail "missing seccomp-unotify prototype source: $SRC"

mkdir -p "$BUILD_DIR"

if [[ ! -x "$BIN" || "$SRC" -nt "$BIN" ]]; then
  cc -O2 -Wall -Wextra -std=c11 "$SRC" -o "$BIN"
fi

exec "$BIN" \
  --failure-mode "$FAILURE_MODE" \
  --policy "$POLICY_MODE" \
  --slow-delay-ms "$SLOW_DELAY_MS" \
  --slow-max-notifs "$SLOW_MAX_NOTIFS" \
  -- \
  /usr/bin/env FIR_SPIKE_INNER_LOOPS="$INNER_LOOPS" \
  "$FIRMA_BIN" run \
    --profile "$PROFILE" \
    --sidecar-endpoint "$SIDECAR_ENDPOINT" \
    -- /bin/sh "$WORKLOAD"
