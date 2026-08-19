#!/usr/bin/env bash
# Layer 3 (filesystem) sandbox acceptance test for the generic-agent profile.
#
# Runs two probes through `firma run` against the stack started by run.sh.
# Start the stack first:
#   bash examples/generic-agent/run.sh
#
# Then in another terminal:
#   bash examples/generic-agent/verify-layer3.sh
#
# Acceptance:
#   1. preflight: sandbox HOME differs from host HOME (bwrap active).
#   2. positive:  `echo ok > <workspace>/probe.txt` exits 0 and file appears.
#   3. negative:  `echo bad >> ~/.ssh/authorized_keys` exits non-zero (denied
#      because HOME is redirected to a fresh runtime dir and the host
#      ~/.ssh is masked by tmpfs).
#
# Linux-only. Requires: cargo, bwrap.
# Optional env overrides:
#   SIDECAR_ENDPOINT   default: tcp://127.0.0.1:7474
#   AUTHORITY_URL      default: http://127.0.0.1:50051
set -euo pipefail

# Unix socket paths have a 108-char limit. Nix-shell sets TMPDIR to a deep
# path that busts this limit; force a short base so firma-run socket paths fit.
export TMPDIR=/tmp

pass() { printf '[pass] %s\n' "$1"; }
fail() { printf '[fail] %s\n' "$1" >&2; exit 1; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

if [[ "$(uname -s)" != "Linux" ]]; then
  fail "Layer 3 verification is Linux-only (bwrap backend)"
fi
command -v cargo  >/dev/null 2>&1 || fail "cargo not found"
command -v bwrap  >/dev/null 2>&1 || fail "bwrap not found"

CFG_SRC="$ROOT_DIR/examples/generic-agent/firma.toml"
[[ -f "$CFG_SRC" ]] || fail "missing $CFG_SRC"

echo "building firma..."
( cd "$ROOT_DIR" && cargo build -q -p firma )
FIRMA_BIN="$ROOT_DIR/target/debug/firma"
[[ -x "$FIRMA_BIN" ]] || fail "firma binary not built at $FIRMA_BIN"

SIDECAR_ENDPOINT="${SIDECAR_ENDPOINT:-tcp://127.0.0.1:7474}"
AUTHORITY_URL="${AUTHORITY_URL:-http://127.0.0.1:50051}"

WORKDIR="$(mktemp -d /tmp/firma-l3.XXXXXX)"
WORKSPACE="$WORKDIR/workspace"
mkdir -p "$WORKSPACE"
trap 'rm -rf "$WORKDIR"' EXIT INT TERM

HOST_HOME="$HOME"

run_in_sandbox() {
  ( cd "$WORKSPACE" && "$FIRMA_BIN" run \
      --profile generic \
      --config "$CFG_SRC" \
      --sidecar external \
      --sidecar-endpoint "$SIDECAR_ENDPOINT" \
      --authority "$AUTHORITY_URL" \
      -- /bin/sh -lc "$1" )
}

# Safety preflight: verify HOME was actually redirected inside the sandbox.
# If sandbox setup failed and firma-run ran unsandboxed, HOME would still
# equal the host home — in that case every "negative" probe below would write
# to real user files. Abort rather than risk that.
SANDBOX_HOME="$(run_in_sandbox 'printf "%s" "$HOME"')" \
  || fail "sandbox preflight: firma run failed to start"
if [[ "$SANDBOX_HOME" == "$HOST_HOME" ]]; then
  fail "sandbox preflight: HOME not redirected (got $SANDBOX_HOME) — bwrap setup failed, aborting to protect real user files"
fi
pass "sandbox HOME redirected ($HOST_HOME → $SANDBOX_HOME)"

# Positive: write inside the workspace.
PROBE="$WORKSPACE/probe.txt"
if run_in_sandbox "echo ok > '$PROBE'" >/dev/null 2>"$WORKDIR/pos.stderr"; then
  [[ -s "$PROBE" ]] || { cat "$WORKDIR/pos.stderr" >&2; fail "workspace write reported success but $PROBE is empty/missing"; }
  pass "workspace write succeeds ($PROBE)"
else
  cat "$WORKDIR/pos.stderr" >&2
  fail "workspace write was blocked but should be allowed"
fi

# Negative: write to ~/.ssh/authorized_keys. Inside the sandbox HOME points
# at the per-run runtime dir so ~/.ssh does not exist; the host ~/.ssh is
# also masked by tmpfs.
set +e
run_in_sandbox 'echo bad >> "$HOME/.ssh/authorized_keys"' \
  >/dev/null 2>"$WORKDIR/neg.stderr"
NEG_STATUS=$?
set -e
if [[ "$NEG_STATUS" -eq 0 ]]; then
  cat "$WORKDIR/neg.stderr" >&2
  fail "write to ~/.ssh/authorized_keys unexpectedly succeeded"
fi
pass "write to ~/.ssh/authorized_keys denied (exit=${NEG_STATUS})"

echo
echo "Layer 3 sandbox verified."
