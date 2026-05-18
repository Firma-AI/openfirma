#!/usr/bin/env bash
set -euo pipefail

ok() { printf '[ok] %s\n' "$1"; }
warn() { printf '[warn] %s\n' "$1"; }
fail() { printf '[fail] %s\n' "$1" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  spikes/firma-run/fir-111/run.sh [options]

Options:
  --mode <baseline|seccomp-static|unotify-prototype>   Benchmark mode (default: baseline)
  --failure-mode <none|startup-unavailable|mid-session-crash|slow-notifier>
                                                     Inject failure mode (unotify-prototype only)
  --unotify-runner <path>                            Required in unotify-prototype mode
  --firma-bin <path>                                 Path to built `firma` binary (default: target/debug/firma)
  --profile <name>                                      firma run profile (default: generic)
  --iterations <n>                                      Number of samples (default: 20)
  --inner-loops <n>                                     Workload inner loops (default: 120)
  --workload <path>                                     Workload script path
  --output-dir <path>                                   Output directory (default: $FIR_SPIKE_OUTPUT_DIR/<ts> or <repo>/.spike-output/<ts>)
  --seccomp-bpf-path <absolute path>                    Required in seccomp-static mode
  -h, --help                                            Show this help
EOF
}

require_command() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || fail "required command not found: $cmd"
}

wait_for_port() {
  local host="$1"
  local port="$2"
  local attempts=80
  local i

  for i in $(seq 1 "$attempts"); do
    if python3 - <<'PY' "$host" "$port" >/dev/null 2>&1
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(0.2)
try:
    s.connect((host, port))
finally:
    s.close()
PY
    then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

MODE="baseline"
PROFILE="generic"
ITERATIONS=20
INNER_LOOPS=120
SECCOMP_BPF_PATH=""
UNOTIFY_RUNNER=""
FAILURE_MODE="none"
FIRMA_BIN="target/debug/firma"
OUTPUT_DIR=""
WORKLOAD=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      shift
      [[ $# -gt 0 ]] || fail "--mode requires a value"
      MODE="$1"
      ;;
    --profile)
      shift
      [[ $# -gt 0 ]] || fail "--profile requires a value"
      PROFILE="$1"
      ;;
    --firma-bin)
      shift
      [[ $# -gt 0 ]] || fail "--firma-bin requires a value"
      FIRMA_BIN="$1"
      ;;
    --failure-mode)
      shift
      [[ $# -gt 0 ]] || fail "--failure-mode requires a value"
      FAILURE_MODE="$1"
      ;;
    --unotify-runner)
      shift
      [[ $# -gt 0 ]] || fail "--unotify-runner requires a value"
      UNOTIFY_RUNNER="$1"
      ;;
    --iterations)
      shift
      [[ $# -gt 0 ]] || fail "--iterations requires a value"
      ITERATIONS="$1"
      ;;
    --inner-loops)
      shift
      [[ $# -gt 0 ]] || fail "--inner-loops requires a value"
      INNER_LOOPS="$1"
      ;;
    --workload)
      shift
      [[ $# -gt 0 ]] || fail "--workload requires a value"
      WORKLOAD="$1"
      ;;
    --output-dir)
      shift
      [[ $# -gt 0 ]] || fail "--output-dir requires a value"
      OUTPUT_DIR="$1"
      ;;
    --seccomp-bpf-path)
      shift
      [[ $# -gt 0 ]] || fail "--seccomp-bpf-path requires a value"
      SECCOMP_BPF_PATH="$1"
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

case "$MODE" in
  baseline|seccomp-static|unotify-prototype) ;;
  *) fail "unsupported mode: $MODE" ;;
esac

case "$FAILURE_MODE" in
  none|startup-unavailable|mid-session-crash|slow-notifier) ;;
  *) fail "unsupported --failure-mode: $FAILURE_MODE" ;;
esac

if [[ "$MODE" != "unotify-prototype" && "$FAILURE_MODE" != "none" ]]; then
  warn "--failure-mode is only used in unotify-prototype mode; ignoring in $MODE mode"
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  fail "this spike harness is Linux-only"
fi

require_command bwrap
require_command python3

if [[ -z "$WORKLOAD" ]]; then
  WORKLOAD="spikes/firma-run/fir-111/workloads/shell-heavy.sh"
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

[[ -f "$WORKLOAD" ]] || fail "workload script not found: $WORKLOAD"

if [[ "$MODE" == "seccomp-static" ]]; then
  [[ -n "$SECCOMP_BPF_PATH" ]] || fail "--seccomp-bpf-path is required in seccomp-static mode"
  [[ -f "$SECCOMP_BPF_PATH" ]] || fail "seccomp file not found: $SECCOMP_BPF_PATH"
  if [[ "$SECCOMP_BPF_PATH" != /* ]]; then
    fail "seccomp path must be absolute in seccomp-static mode"
  fi
fi

if [[ "$MODE" == "unotify-prototype" ]]; then
  [[ -n "$UNOTIFY_RUNNER" ]] || fail "--unotify-runner is required in unotify-prototype mode"
  [[ -x "$UNOTIFY_RUNNER" ]] || fail "unotify runner is not executable: $UNOTIFY_RUNNER"
fi

if ! [[ "$ITERATIONS" =~ ^[0-9]+$ ]] || [[ "$ITERATIONS" -lt 1 ]]; then
  fail "--iterations must be a positive integer"
fi
if ! [[ "$INNER_LOOPS" =~ ^[0-9]+$ ]] || [[ "$INNER_LOOPS" -lt 1 ]]; then
  fail "--inner-loops must be a positive integer"
fi

if [[ -z "$OUTPUT_DIR" ]]; then
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  output_root="${FIR_SPIKE_OUTPUT_DIR:-${ROOT_DIR}/.spike-output}"
  OUTPUT_DIR="${output_root}/${ts}-${MODE}"
fi

mkdir -p "$OUTPUT_DIR/logs"

STATS_FILE="$OUTPUT_DIR/elapsed_ms.txt"
RESULTS_FILE="$OUTPUT_DIR/results.jsonl"
SUMMARY_FILE="$OUTPUT_DIR/summary.txt"
RUN_CONFIG_FILE="$OUTPUT_DIR/firma-run.spike.toml"
SIDE_SERVER_LOG="$OUTPUT_DIR/mock-sidecar.log"

if [[ ! -x "$FIRMA_BIN" ]]; then
  require_command cargo
  ok "building firma binary for spike runs"
  cargo build -p firma >/dev/null
fi
[[ -x "$FIRMA_BIN" ]] || fail "firma binary is not executable: $FIRMA_BIN"

SIDE_PORT="$((RANDOM % 10000 + 20000))"
SIDE_PID=""

cleanup() {
  if [[ -n "$SIDE_PID" ]] && kill -0 "$SIDE_PID" >/dev/null 2>&1; then
    kill "$SIDE_PID" >/dev/null 2>&1 || true
    wait "$SIDE_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

ok "starting mock sidecar endpoint at 127.0.0.1:${SIDE_PORT}"
python3 -m http.server --bind 127.0.0.1 "${SIDE_PORT}" >"$SIDE_SERVER_LOG" 2>&1 &
SIDE_PID="$!"

if ! wait_for_port "127.0.0.1" "$SIDE_PORT"; then
  sed -n '1,120p' "$SIDE_SERVER_LOG" >&2 || true
  fail "mock sidecar endpoint failed to start on 127.0.0.1:${SIDE_PORT}"
fi

if [[ "$MODE" == "seccomp-static" ]]; then
  cat >"$RUN_CONFIG_FILE" <<EOF
[profiles.${PROFILE}]
backend = "bwrap"
seccomp_bpf_path = '${SECCOMP_BPF_PATH}'
EOF
fi

printf '' >"$STATS_FILE"
printf '' >"$RESULTS_FILE"

ok "running ${ITERATIONS} iterations mode=${MODE} profile=${PROFILE}"

for i in $(seq 1 "$ITERATIONS"); do
  stdout_log="$OUTPUT_DIR/logs/iter-${i}.stdout.log"
  stderr_log="$OUTPUT_DIR/logs/iter-${i}.stderr.log"

  run_cmd=("$FIRMA_BIN" run --profile "$PROFILE")
  if [[ "$MODE" == "unotify-prototype" ]]; then
    run_cmd=("$UNOTIFY_RUNNER")
    run_cmd+=(--firma-bin "$FIRMA_BIN")
    run_cmd+=(--workload "$WORKLOAD")
    run_cmd+=(--inner-loops "$INNER_LOOPS")
    run_cmd+=(--failure-mode "$FAILURE_MODE")
    run_cmd+=(--profile "$PROFILE")
    run_cmd+=(--sidecar-endpoint "tcp://127.0.0.1:${SIDE_PORT}")
  else
    run_cmd+=(--sidecar-endpoint "tcp://127.0.0.1:${SIDE_PORT}")
    if [[ "$MODE" == "seccomp-static" ]]; then
      run_cmd+=(--config "$RUN_CONFIG_FILE")
    fi
    run_cmd+=(-- /bin/sh "$WORKLOAD")
  fi

  start_ns="$(date +%s%N)"
  set +e
  if [[ "$MODE" == "unotify-prototype" ]]; then
    "${run_cmd[@]}" >"$stdout_log" 2>"$stderr_log"
  else
    FIR_SPIKE_INNER_LOOPS="$INNER_LOOPS" "${run_cmd[@]}" >"$stdout_log" 2>"$stderr_log"
  fi
  status=$?
  set -e
  end_ns="$(date +%s%N)"

  elapsed_ms="$(awk -v s="$start_ns" -v e="$end_ns" 'BEGIN { printf "%.3f", (e-s)/1000000 }')"
  printf '%s\n' "$elapsed_ms" >>"$STATS_FILE"
  printf '{"iteration":%s,"mode":"%s","profile":"%s","elapsed_ms":%s,"exit_code":%s,"stdout_log":"%s","stderr_log":"%s"}\n' \
    "$i" "$MODE" "$PROFILE" "$elapsed_ms" "$status" "$stdout_log" "$stderr_log" >>"$RESULTS_FILE"

  if [[ "$status" -eq 0 ]]; then
    ok "iter=${i} elapsed_ms=${elapsed_ms}"
  else
    warn "iter=${i} exit=${status} elapsed_ms=${elapsed_ms}"
  fi
done

count="$(wc -l <"$STATS_FILE" | tr -d ' ')"
successes="$(awk -F'"exit_code":' '{if (NF>1) {split($2, a, ","); if (a[1] == 0) ok++}} END {print ok+0}' "$RESULTS_FILE")"
failures="$((count - successes))"

avg_ms="$(awk '{sum+=$1} END {if (NR>0) printf "%.3f", sum/NR; else print "0.000"}' "$STATS_FILE")"
sum_ms="$(awk '{sum+=$1} END {if (NR>0) printf "%.3f", sum; else print "0.000"}' "$STATS_FILE")"
min_ms="$(sort -n "$STATS_FILE" | head -n 1)"
max_ms="$(sort -n "$STATS_FILE" | tail -n 1)"
p50_ms="$(sort -n "$STATS_FILE" | awk '{a[NR]=$1} END {if (NR==0) {print "0.000"; exit} idx=int((NR+1)/2); printf "%.3f", a[idx]}')"
p95_ms="$(sort -n "$STATS_FILE" | awk '{a[NR]=$1} END {if (NR==0) {print "0.000"; exit} idx=int((NR*95+99)/100); if (idx<1) idx=1; if (idx>NR) idx=NR; printf "%.3f", a[idx]}')"
p99_ms="$(sort -n "$STATS_FILE" | awk '{a[NR]=$1} END {if (NR==0) {print "0.000"; exit} idx=int((NR*99+99)/100); if (idx<1) idx=1; if (idx>NR) idx=NR; printf "%.3f", a[idx]}')"
iter_per_sec="$(awk -v c="$count" -v total="$sum_ms" 'BEGIN {if (total <= 0) print "0.000"; else printf "%.3f", (c*1000.0)/total}')"
work_units_per_sec="$(awk -v c="$count" -v loops="$INNER_LOOPS" -v total="$sum_ms" 'BEGIN {if (total <= 0) print "0.000"; else printf "%.3f", (c*loops*1000.0)/total}')"

{
  printf 'fir-111 spike summary\n'
  printf 'mode=%s\n' "$MODE"
  printf 'profile=%s\n' "$PROFILE"
  printf 'iterations=%s\n' "$ITERATIONS"
  printf 'inner_loops=%s\n' "$INNER_LOOPS"
  printf 'failure_mode=%s\n' "$FAILURE_MODE"
  printf 'seccomp_bpf_path=%s\n' "${SECCOMP_BPF_PATH:-<none>}"
  printf 'unotify_runner=%s\n' "${UNOTIFY_RUNNER:-<none>}"
  printf 'count=%s\n' "$count"
  printf 'successes=%s\n' "$successes"
  printf 'failures=%s\n' "$failures"
  printf 'total_ms=%s\n' "$sum_ms"
  printf 'min_ms=%s\n' "$min_ms"
  printf 'avg_ms=%s\n' "$avg_ms"
  printf 'p50_ms=%s\n' "$p50_ms"
  printf 'p95_ms=%s\n' "$p95_ms"
  printf 'p99_ms=%s\n' "$p99_ms"
  printf 'max_ms=%s\n' "$max_ms"
  printf 'iterations_per_sec=%s\n' "$iter_per_sec"
  printf 'work_units_per_sec=%s\n' "$work_units_per_sec"
  printf 'results_jsonl=%s\n' "$RESULTS_FILE"
} >"$SUMMARY_FILE"

ok "summary written to $SUMMARY_FILE"
ok "samples written to $RESULTS_FILE"
