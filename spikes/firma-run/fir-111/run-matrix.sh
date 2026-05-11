#!/usr/bin/env bash
set -euo pipefail

ok() { printf '[ok] %s\n' "$1"; }
warn() { printf '[warn] %s\n' "$1"; }
fail() { printf '[fail] %s\n' "$1" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  spikes/firma-run/fir-111/run-matrix.sh [options]

Options:
  --output-dir <path>            Matrix output dir (default: $FIR_SPIKE_OUTPUT_DIR/matrix-<ts> or <repo>/.spike-output/matrix-<ts>)
  --profile <name>               firma run profile (default: generic)
  --iterations <n>               iterations per scenario (default: 20)
  --inner-loops <n>              workload inner loops (default: 120)
  --workload <path>              workload script
  --seccomp-bpf-path <path>      Enable seccomp-static scenario
  --unotify-runner <path>        Enable unotify-prototype scenarios (default: adapters/unotify-runner-firma.sh when executable)
EOF
}

OUTPUT_DIR=""
PROFILE="generic"
ITERATIONS=20
INNER_LOOPS=120
WORKLOAD=""
SECCOMP_BPF_PATH=""
UNOTIFY_RUNNER=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      shift
      [[ $# -gt 0 ]] || fail "--output-dir requires a value"
      OUTPUT_DIR="$1"
      ;;
    --profile)
      shift
      [[ $# -gt 0 ]] || fail "--profile requires a value"
      PROFILE="$1"
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
    --seccomp-bpf-path)
      shift
      [[ $# -gt 0 ]] || fail "--seccomp-bpf-path requires a value"
      SECCOMP_BPF_PATH="$1"
      ;;
    --unotify-runner)
      shift
      [[ $# -gt 0 ]] || fail "--unotify-runner requires a value"
      UNOTIFY_RUNNER="$1"
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

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

if [[ -z "$UNOTIFY_RUNNER" ]]; then
  default_unotify_runner="spikes/firma-run/fir-111/adapters/unotify-runner-firma.sh"
  if [[ -x "$default_unotify_runner" ]]; then
    UNOTIFY_RUNNER="$default_unotify_runner"
  fi
fi

if [[ -z "$OUTPUT_DIR" ]]; then
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  output_root="${FIR_SPIKE_OUTPUT_DIR:-${ROOT_DIR}/.spike-output}"
  OUTPUT_DIR="${output_root}/matrix-${ts}"
fi
mkdir -p "$OUTPUT_DIR"

PROBE_OUT="$OUTPUT_DIR/kernel-seccomp-probe.txt"
INDEX_TSV="$OUTPUT_DIR/runs.tsv"
MATRIX_MD="$OUTPUT_DIR/matrix-summary.md"

run_case() {
  local case_id="$1"
  shift
  local case_dir="$OUTPUT_DIR/$case_id"
  mkdir -p "$case_dir"
  ok "running case=$case_id"
  spikes/firma-run/fir-111/run.sh "$@" --output-dir "$case_dir"
  printf '%s\t%s\n' "$case_id" "$case_dir" >>"$INDEX_TSV"
}

read_summary_field() {
  local file="$1"
  local key="$2"
  awk -F= -v k="$key" '$1==k {print $2}' "$file" | tail -n 1
}

ok "probing kernel seccomp capabilities"
spikes/firma-run/fir-111/probe-kernel-seccomp.sh --format text >"$PROBE_OUT"

printf '' >"$INDEX_TSV"

base_args=(--mode baseline --profile "$PROFILE" --iterations "$ITERATIONS" --inner-loops "$INNER_LOOPS")
if [[ -n "$WORKLOAD" ]]; then
  base_args+=(--workload "$WORKLOAD")
fi
run_case "baseline" "${base_args[@]}"

if [[ -n "$SECCOMP_BPF_PATH" ]]; then
  static_args=(--mode seccomp-static --profile "$PROFILE" --iterations "$ITERATIONS" --inner-loops "$INNER_LOOPS" --seccomp-bpf-path "$SECCOMP_BPF_PATH")
  if [[ -n "$WORKLOAD" ]]; then
    static_args+=(--workload "$WORKLOAD")
  fi
  run_case "seccomp-static" "${static_args[@]}"
else
  warn "seccomp-static scenario skipped (no --seccomp-bpf-path provided)"
fi

if [[ -n "$UNOTIFY_RUNNER" ]]; then
  unotify_args=(--mode unotify-prototype --profile "$PROFILE" --iterations "$ITERATIONS" --inner-loops "$INNER_LOOPS" --unotify-runner "$UNOTIFY_RUNNER")
  if [[ -n "$WORKLOAD" ]]; then
    unotify_args+=(--workload "$WORKLOAD")
  fi

  run_case "unotify-none" "${unotify_args[@]}" --failure-mode none
  run_case "unotify-startup-unavailable" "${unotify_args[@]}" --failure-mode startup-unavailable
  run_case "unotify-mid-session-crash" "${unotify_args[@]}" --failure-mode mid-session-crash
  run_case "unotify-slow-notifier" "${unotify_args[@]}" --failure-mode slow-notifier
else
  warn "unotify scenarios skipped (no --unotify-runner provided)"
fi

{
  printf '# FIR-111 Matrix Summary\n\n'
  printf 'Output dir: `%s`\n\n' "$OUTPUT_DIR"
  printf '## Kernel Probe\n\n'
  printf '```\n'
  cat "$PROBE_OUT"
  printf '```\n\n'
  printf '## Scenario Results\n\n'
  printf '| Scenario | Successes | Failures | p50 ms | p95 ms | p99 ms | avg ms | iter/s | work-units/s | Notes |\n'
  printf '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n'
  while IFS=$'\t' read -r case_id case_dir; do
    summary="$case_dir/summary.txt"
    successes="$(read_summary_field "$summary" successes)"
    failures="$(read_summary_field "$summary" failures)"
    p50="$(read_summary_field "$summary" p50_ms)"
    p95="$(read_summary_field "$summary" p95_ms)"
    p99="$(read_summary_field "$summary" p99_ms)"
    avg="$(read_summary_field "$summary" avg_ms)"
    iterps="$(read_summary_field "$summary" iterations_per_sec)"
    workps="$(read_summary_field "$summary" work_units_per_sec)"
    printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | `%s` |\n' \
      "$case_id" "$successes" "$failures" "$p50" "$p95" "$p99" "$avg" "$iterps" "$workps" "$case_dir"
  done <"$INDEX_TSV"
  printf '\n'
  printf 'Raw run index: `%s`\n' "$INDEX_TSV"
} >"$MATRIX_MD"

ok "matrix summary written to $MATRIX_MD"
