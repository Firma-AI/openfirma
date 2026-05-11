#!/usr/bin/env bash
set -euo pipefail

fail() { printf '[fail] %s\n' "$1" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  spikes/firma-run/fir-111/generate-decision-memo-input.sh \
    --matrix-dir <path> \
    --out <path>
EOF
}

MATRIX_DIR=""
OUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --matrix-dir)
      shift
      [[ $# -gt 0 ]] || fail "--matrix-dir requires a value"
      MATRIX_DIR="$1"
      ;;
    --out)
      shift
      [[ $# -gt 0 ]] || fail "--out requires a value"
      OUT="$1"
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

[[ -n "$MATRIX_DIR" ]] || fail "missing --matrix-dir"
[[ -n "$OUT" ]] || fail "missing --out"

INDEX_TSV="$MATRIX_DIR/runs.tsv"
[[ -f "$INDEX_TSV" ]] || fail "missing matrix run index: $INDEX_TSV"

field() {
  local file="$1"
  local key="$2"
  awk -F= -v k="$key" '$1==k {print $2}' "$file" | tail -n 1
}

{
  printf '# FIR-111 Decision Memo Input\n\n'
  printf 'Generated: %s UTC\n\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'Matrix directory: `%s`\n\n' "$MATRIX_DIR"
  printf '## Benchmark Table\n\n'
  printf '| Scenario | Mode | p50 ms | p95 ms | p99 ms | avg ms | iter/s | work-units/s | successes | failures |\n'
  printf '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n'

  while IFS=$'\t' read -r case_id case_dir; do
    summary="$case_dir/summary.txt"
    mode="$(field "$summary" mode)"
    p50="$(field "$summary" p50_ms)"
    p95="$(field "$summary" p95_ms)"
    p99="$(field "$summary" p99_ms)"
    avg="$(field "$summary" avg_ms)"
    iterps="$(field "$summary" iterations_per_sec)"
    workps="$(field "$summary" work_units_per_sec)"
    successes="$(field "$summary" successes)"
    failures="$(field "$summary" failures)"
    printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
      "$case_id" "$mode" "$p50" "$p95" "$p99" "$avg" "$iterps" "$workps" "$successes" "$failures"
  done <"$INDEX_TSV"

  printf '\n'
  printf '## Failure-Mode Classification\n\n'
  printf '| Scenario | Expected behavior | Observed signal |\n'
  printf '| --- | --- | --- |\n'
  while IFS=$'\t' read -r case_id case_dir; do
    summary="$case_dir/summary.txt"
    successes="$(field "$summary" successes)"
    failures="$(field "$summary" failures)"
    expected="n/a"
    observed="n/a"
    case "$case_id" in
      unotify-startup-unavailable|unotify-mid-session-crash)
        expected="fail-closed"
        if [[ "${failures:-0}" != "0" ]]; then
          observed="non-zero exits observed"
        else
          observed="all-zero exits (check)"
        fi
        ;;
      unotify-slow-notifier)
        expected="bounded delay, no hang"
        if [[ "${failures:-0}" == "0" ]] && [[ "${successes:-0}" != "0" ]]; then
          observed="completed with zero exits"
        else
          observed="non-zero exits observed"
        fi
        ;;
      *)
        expected="normal execution"
        observed="not a failure-mode scenario"
        ;;
    esac
    printf '| %s | %s | %s |\n' "$case_id" "$expected" "$observed"
  done <"$INDEX_TSV"
} >"$OUT"

printf '[ok] decision memo input generated: %s\n' "$OUT"
