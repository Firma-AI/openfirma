#!/usr/bin/env bash
set -euo pipefail

fail() { printf '[fail] %s\n' "$1" >&2; exit 1; }
ok() { printf '[ok] %s\n' "$1"; }

usage() {
  cat <<'EOF'
Usage:
  spikes/firma-run/fir-111/generate-static-seccomp-bpf.sh \
    --output <absolute-path> \
    [--mode allow-all|deny-openat]

Generates a raw seccomp cBPF file for bwrap --seccomp.
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
SRC="${ROOT_DIR}/spikes/firma-run/fir-111/unotify-prototype/gen_static_seccomp_bpf.c"
BUILD_DIR="${ROOT_DIR}/target/fir-111-unotify"
BIN="${BUILD_DIR}/gen_static_seccomp_bpf"

OUTPUT=""
MODE="allow-all"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      shift
      [[ $# -gt 0 ]] || fail "--output requires a value"
      OUTPUT="$1"
      ;;
    --mode)
      shift
      [[ $# -gt 0 ]] || fail "--mode requires a value"
      MODE="$1"
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

[[ -n "$OUTPUT" ]] || fail "missing --output"
[[ "$OUTPUT" = /* ]] || fail "--output must be an absolute path"
[[ "$MODE" == "allow-all" || "$MODE" == "deny-openat" ]] || fail "unsupported --mode: $MODE"

mkdir -p "$BUILD_DIR"
cc -O2 -Wall -Wextra -std=c11 "$SRC" -o "$BIN"

mkdir -p "$(dirname "$OUTPUT")"
"$BIN" --output "$OUTPUT" --mode "$MODE"

ok "generated seccomp bpf: $OUTPUT (mode=$MODE)"
