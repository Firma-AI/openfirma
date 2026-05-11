#!/usr/bin/env bash
set -euo pipefail

ok() { printf '[ok] %s\n' "$1"; }
fail() { printf '[fail] %s\n' "$1" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  scripts/seccomp/check-managed-compatibility.sh [--format text|kv]

Checks local host compatibility for managed static seccomp runtime.
EOF
}

FORMAT="text"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --format)
      shift
      [[ $# -gt 0 ]] || fail "--format requires a value"
      FORMAT="$1"
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

[[ "$(uname -s)" == "Linux" ]] || fail "managed seccomp is supported only on Linux"

arch="$(uname -m)"
case "$arch" in
  x86_64|aarch64) ;;
  *)
    fail "unsupported architecture for managed seccomp: $arch (supported: x86_64, aarch64)"
    ;;
esac

command -v bwrap >/dev/null 2>&1 || fail "bubblewrap (bwrap) is required"
bwrap --version >/dev/null 2>&1 || fail "bwrap is not executable"

kernel_release="$(uname -r)"
kernel_base="${kernel_release%%-*}"
kernel_major="${kernel_base%%.*}"
rest="${kernel_base#*.}"
kernel_minor="${rest%%.*}"
if [[ -z "${kernel_major:-}" || -z "${kernel_minor:-}" ]]; then
  fail "unable to parse kernel release: $kernel_release"
fi
if ! [[ "$kernel_major" =~ ^[0-9]+$ && "$kernel_minor" =~ ^[0-9]+$ ]]; then
  fail "unexpected kernel version components: $kernel_release"
fi
# Require kernel >= 4.14 for stable SECCOMP_RET_KILL_PROCESS semantics.
if (( kernel_major < 4 || (kernel_major == 4 && kernel_minor < 14) )); then
  fail "kernel $kernel_release is unsupported; require >= 4.14"
fi

actions_avail_file="/proc/sys/kernel/seccomp/actions_avail"
[[ -r "$actions_avail_file" ]] || fail "cannot read $actions_avail_file"
actions_avail="$(cat "$actions_avail_file")"
for action in kill_process errno allow; do
  if ! grep -Eq "(^|[[:space:]])${action}($|[[:space:]])" <<<"$actions_avail"; then
    fail "seccomp action '${action}' not available (actions_avail: $actions_avail)"
  fi
done

case "$FORMAT" in
  text)
    ok "managed seccomp compatibility check passed"
    printf 'kernel_release=%s\n' "$kernel_release"
    printf 'arch=%s\n' "$arch"
    printf 'actions_avail=%s\n' "$actions_avail"
    ;;
  kv)
    printf 'compatible=true\n'
    printf 'kernel_release=%s\n' "$kernel_release"
    printf 'arch=%s\n' "$arch"
    printf 'actions_avail=%s\n' "$actions_avail"
    ;;
  *)
    fail "unsupported --format value: $FORMAT"
    ;;
esac
