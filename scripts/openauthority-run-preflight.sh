#!/usr/bin/env bash
set -euo pipefail

ok() { printf '[ok] %s\n' "$1"; }
warn() { printf '[warn] %s\n' "$1"; }
fail() { printf '[fail] %s\n' "$1"; exit 1; }

uname_s="$(uname -s)"
case "$uname_s" in
  Linux) ok "host OS is Linux (default backend: bwrap)" ;;
  Darwin) ok "host OS is macOS (default backend: vz)" ;;
  MINGW*|MSYS*|CYGWIN*) ok "host OS is Windows-like (default backend: wsl2)" ;;
  *) warn "unrecognized host OS: $uname_s" ;;
esac

case "$uname_s" in
  Linux)
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
    ;;
  Darwin)
    if command -v sandbox-exec >/dev/null 2>&1; then
      ok "sandbox-exec found: $(command -v sandbox-exec)"
    else
      warn "sandbox-exec not found in PATH"
    fi
    ;;
  MINGW*|MSYS*|CYGWIN*)
    if command -v wsl.exe >/dev/null 2>&1; then
      ok "wsl.exe found: $(command -v wsl.exe)"
    else
      warn "wsl.exe not found in PATH"
    fi
    ;;
esac

if command -v opensidecar >/dev/null 2>&1; then
  ok "opensidecar binary found"
else
  warn "opensidecar binary not found in PATH"
fi

ok "preflight completed"
