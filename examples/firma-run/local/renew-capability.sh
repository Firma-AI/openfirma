#!/usr/bin/env bash
set -euo pipefail

ok() { printf '[ok] %s\n' "$1"; }
warn() { printf '[warn] %s\n' "$1"; }
fail() { printf '[fail] %s\n' "$1"; exit 1; }

AUTHORITY_CONFIG="${AUTHORITY_CONFIG:-.local/firma.toml}"
AGENT_ID="${AGENT_ID:-example-agent}"
SESSION_ID="${SESSION_ID:-${FIRMA_RUN_SESSION_ID:-demo-session}}"
ACTION="${ACTION:-communication.external.send}"
RESOURCE_SCOPE="${RESOURCE_SCOPE:-*}"
TTL_SECONDS="${TTL_SECONDS:-3600}"
OUTPUT_PATH="${OUTPUT_PATH:-.local/capability-chatgpt.toml}"
OUTPUT_PATH="${OUTPUT_PATH:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --authority-config) AUTHORITY_CONFIG="$2"; shift 2 ;;
    --agent-id) AGENT_ID="$2"; shift 2 ;;
    --session-id) SESSION_ID="$2"; shift 2 ;;
    --action) ACTION="$2"; shift 2 ;;
    --resource-scope) RESOURCE_SCOPE="$2"; shift 2 ;;
    --ttl-seconds) TTL_SECONDS="$2"; shift 2 ;;
    --output) OUTPUT_PATH="$2"; shift 2 ;;
    -h|--help)
      cat <<'EOF'
Usage: examples/firma-run/local/renew-capability.sh [options]

Options:
  --authority-config <path>  Unified firma.toml with an [authority] table (default: .local/firma.toml)
  --agent-id <id>            Agent id (default: example-agent)
  --session-id <id>          Session id (default: FIRMA_RUN_SESSION_ID or demo-session)
  --action <action>          Requested action (default: communication.external.send)
  --resource-scope <scope>   Resource scope (default: *)
  --ttl-seconds <n>          Token TTL in seconds (default: 3600)
  --output <path>            Output capability seed path (required)
EOF
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

if ! command -v cargo >/dev/null 2>&1; then
  fail "cargo is required"
fi

[[ -n "$SESSION_ID" ]] || fail "session id must not be empty"
[[ -n "$OUTPUT_PATH" ]] || fail "--output is required (example: --output .local/capability-codex.toml)"

ok "issuing capability token (agent=$AGENT_ID session=$SESSION_ID ttl=${TTL_SECONDS}s)"
cargo run -p firma -- authority --config "$AUTHORITY_CONFIG" issue \
  --agent-id "$AGENT_ID" \
  --session-id "$SESSION_ID" \
  --action "$ACTION" \
  --resource-scope "$RESOURCE_SCOPE" \
  --ttl-seconds "$TTL_SECONDS" \
  --output "$OUTPUT_PATH"

ok "capability written: $OUTPUT_PATH"
warn "if sidecar uses capability_seed, restart sidecar to reload the renewed token"
