#!/usr/bin/env bash
set -euo pipefail

ok() { printf '[ok] %s\n' "$1"; }
warn() { printf '[warn] %s\n' "$1"; }
fail() { printf '[fail] %s\n' "$1"; exit 1; }

uname_s="$(uname -s)"
case "$uname_s" in
  Linux) ok "host OS is Linux" ;;
  Darwin) warn "host OS is macOS (runtime backend not yet implemented)" ;;
  MINGW*|MSYS*|CYGWIN*) warn "host OS is Windows-like (runtime backend not yet implemented)" ;;
  *) warn "unrecognized host OS: $uname_s" ;;
esac

if command -v bwrap >/dev/null 2>&1; then
  ok "bubblewrap found: $(command -v bwrap)"
else
  warn "bubblewrap not found in PATH"
fi

if [[ -f /proc/sys/user/max_user_namespaces ]]; then
  ns_val="$(cat /proc/sys/user/max_user_namespaces || echo 0)"
  if [[ "$ns_val" -gt 0 ]]; then
    ok "user namespaces enabled (max_user_namespaces=$ns_val)"
  else
    warn "user namespaces appear disabled (max_user_namespaces=$ns_val)"
  fi
fi

if command -v firma-sidecar >/dev/null 2>&1; then
  ok "firma-sidecar binary found"
else
  warn "firma-sidecar binary not found in PATH"
fi

ok "preflight completed"
