# shellcheck shell=bash
# Shared helpers for the FIR-411 boundary spike. Sourced by every demo and
# break-out script. Throwaway proof-of-concept, not product code.

set -euo pipefail

# --- Layout ------------------------------------------------------------------

SPIKE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
REPO_ROOT="$(cd "$SPIKE_DIR/../../.." && pwd -P)"
RUNTIME_DIR="$SPIKE_DIR/.runtime"
CONFIG_FILE="$SPIKE_DIR/firma.toml"

# firma binary: prefer an explicit override, then debug, then release.
FIRMA_BIN="${FIRMA_BIN:-}"
if [[ -z "$FIRMA_BIN" ]]; then
  if [[ -x "$REPO_ROOT/target/debug/firma" ]]; then
    FIRMA_BIN="$REPO_ROOT/target/debug/firma"
  elif [[ -x "$REPO_ROOT/target/release/firma" ]]; then
    FIRMA_BIN="$REPO_ROOT/target/release/firma"
  else
    echo "firma binary not found; run 'cargo build -p firma' first" >&2
    exit 1
  fi
fi

# --- Demo constants ----------------------------------------------------------

APPROVED_HOST="approved-api.localhost"
EXFIL_HOST="exfil-sink.localhost"
APPROVED_PORT="${APPROVED_PORT:-8081}"
EXFIL_PORT="${EXFIL_PORT:-8082}"

# The placeholder the agent holds; the real token never enters the box.
export APPROVED_API_PLACEHOLDER="PLACEHOLDER-TOKEN"
export APPROVED_API_REAL_TOKEN="${APPROVED_API_REAL_TOKEN:-real-secret-do-not-leak}"
export EXFIL_SINK_LOG="${EXFIL_SINK_LOG:-$RUNTIME_DIR/exfil-sink.log}"

# A fake secret file the scoped-read demo tries to exfiltrate.
FAKE_SECRET_FILE="$HOME/.aws/credentials"

# --- Fake services -----------------------------------------------------------

APPROVED_PID=""
EXFIL_PID=""

start_servers() {
  mkdir -p "$RUNTIME_DIR"
  python3 "$SPIKE_DIR/servers/approved-api.py" "$APPROVED_PORT" \
    >"$RUNTIME_DIR/approved-api.out" 2>&1 &
  APPROVED_PID=$!
  python3 "$SPIKE_DIR/servers/exfil-sink.py" "$EXFIL_PORT" \
    >"$RUNTIME_DIR/exfil-sink.out" 2>&1 &
  EXFIL_PID=$!
  # Give the listeners a moment to bind.
  for _ in $(seq 1 20); do
    if grep -q listening "$RUNTIME_DIR/approved-api.out" 2>/dev/null \
      && grep -q listening "$RUNTIME_DIR/exfil-sink.out" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
}

stop_servers() {
  [[ -n "$APPROVED_PID" ]] && kill "$APPROVED_PID" 2>/dev/null || true
  [[ -n "$EXFIL_PID" ]] && kill "$EXFIL_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}

exfil_hits() {
  # Count HTTP hits recorded by the sink (each captured leak is one line).
  [[ -f "$EXFIL_SINK_LOG" ]] && wc -l <"$EXFIL_SINK_LOG" | tr -d ' ' || echo 0
}

# --- Runners -----------------------------------------------------------------

# Run a payload script directly on the host (no boundary).
run_bare() {
  local payload="$1"
  bash "$payload" || true
}

# Run a payload script inside the firma box (structural boundary + sidecar).
run_boxed() {
  local payload="$1"
  timeout 120 "$FIRMA_BIN" run \
    --config "$CONFIG_FILE" \
    --authority local \
    --sidecar local \
    -- /usr/bin/env bash "$payload" || true
}

# --- Reporting ---------------------------------------------------------------

hr() { printf '%.0s─' {1..72}; echo; }

banner() {
  hr
  echo "  $1"
  hr
}

# Read the newest sidecar audit log (per-run path lives under state dir).
latest_audit_denies() {
  local audit="$RUNTIME_DIR/audit.jsonl"
  [[ -f "$audit" ]] || return 0
  grep -c '"decision":"deny"' "$audit" 2>/dev/null || echo 0
}

# Break-out result ledger. Each attempt appends one row consumed by the finding.
BREAKOUT_RESULTS="${BREAKOUT_RESULTS:-$RUNTIME_DIR/breakout-results.tsv}"

record_result() {
  # record_result <id> <surface> <result> <defeats-hypothesis?>
  mkdir -p "$RUNTIME_DIR"
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >>"$BREAKOUT_RESULTS"
  echo "[RESULT] $1: $3 ($2)"
}
