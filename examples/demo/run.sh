#!/usr/bin/env bash
# Firma OSS — release demo orchestrator.
#
# Usage:
#   examples/demo/run.sh hero   # default; LLM-driven scripted Python agent
#   examples/demo/run.sh repl   # interactive Python agent REPL
#   examples/demo/run.sh ci     # deterministic Rust client (CI gate)
#
# Boots the Mini Authority and the sidecar, pre-issues a capability
# seed for `demo-agent`/`demo-session`, and dispatches the chosen
# driver. Cleans up child processes on EXIT/INT/TERM.

set -euo pipefail

MODE="${1:-hero}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEMO="$ROOT/examples/demo"
LOG_DIR="$DEMO/logs"
TARGET_DIR="$ROOT/target/release"
LOOPBACK_HOST="127.0.0.1"

mkdir -p "$LOG_DIR"

if [[ -f "$DEMO/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$DEMO/.env"
  set +a
fi

AUTH_PID=""
SIDE_PID=""
FIX_PID=""

cleanup() {
  trap - INT TERM EXIT
  for pid in "$FIX_PID" "$SIDE_PID" "$AUTH_PID"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

# ── Helpers ──────────────────────────────────────────────────────────────────

# Bounded retry loop. Polls `nc -z host port` every 200 ms up to 15 s.
poll_tcp() {
  local host="$1"
  local port="$2"
  local label="${3:-$host:$port}"
  local deadline=$((SECONDS + 15))
  while (( SECONDS < deadline )); do
    if nc -z "$host" "$port" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  echo "[demo] timed out waiting for $label" >&2
  return 1
}

# Poll a demo TCP endpoint on IPv4 loopback. The demo services bind IPv4
# literals, so readiness must not depend on how the host resolves localhost.
poll_tcp_loopback() {
  local port="$1"
  local label="${2:-loopback:$port}"
  poll_tcp "$LOOPBACK_HOST" "$port" "$label"
}

# Poll an HTTP endpoint for a 2xx response.
poll_http() {
  local url="$1"
  local label="${2:-$url}"
  local deadline=$((SECONDS + 15))
  while (( SECONDS < deadline )); do
    if curl -sf "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  echo "[demo] timed out waiting for $label" >&2
  return 1
}

ensure_authority_key() {
  local key="$DEMO/firma-authority.key"
  local pub="$DEMO/firma-authority.pub"
  if [[ -f "$key" && -f "$pub" ]]; then
    return
  fi
  echo "[demo] generating authority signing key"
  (cd "$DEMO" && "$TARGET_DIR/firma" authority generate-key --output firma-authority.key)
}

ensure_authority_tls() {
  local ca_cert="$DEMO/authority-ca.crt"
  local ca_key="$DEMO/authority-ca.key"
  local cert="$DEMO/authority.crt"
  local key="$DEMO/authority.key"
  if [[ -f "$ca_cert" && -f "$ca_key" && -f "$cert" && -f "$key" ]]; then
    return
  fi
  echo "[demo] bootstrapping authority transport TLS material"
  (cd "$DEMO" && "$TARGET_DIR/firma" authority init-tls --out-dir . --host "$LOOPBACK_HOST" --host localhost)
}

ensure_audit_key() {
  local key="$DEMO/audit.key"
  if [[ -f "$key" ]]; then
    return
  fi
  echo "[demo] generating audit ECDSA P-256 signing key"
  if ! command -v openssl >/dev/null 2>&1; then
    echo "[demo] openssl required to bootstrap audit.key (install or pre-stage the file)" >&2
    return 1
  fi
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$key" >/dev/null 2>&1
}

ensure_capability_seed() {
  local seed="$DEMO/capabilities/capability-demo-agent.toml"
  # Always re-issue. The seed is a short-lived PASETO token and the
  # file-exists check used to silently re-use an expired token from
  # a previous demo run, surfacing as Stage 1 "token expired" denies
  # on the next invocation.
  mkdir -p "$DEMO/capabilities"
  echo "[demo] issuing capability seed for demo-agent / demo-session"
  (cd "$ROOT" && "$TARGET_DIR/firma" authority \
    --config "$DEMO/firma.toml" \
    issue \
      --agent-id agt_01j0000000e008000000000001 \
      --session-id demo-session \
      --action communication.external.send \
      --resource-scope '*' \
      --ttl-seconds 3600 \
      --output "$seed")
}

ensure_revocations_file() {
  local rev="$DEMO/revocations.txt"
  [[ -f "$rev" ]] || : > "$rev"
}

# ── Build ────────────────────────────────────────────────────────────────────

echo "[demo] building release binaries"
(cd "$ROOT" && cargo build --release \
  -p firma -p firma-demo-fixture)

mkdir -p "$DEMO/firma-ca"
ensure_revocations_file
ensure_authority_key
ensure_authority_tls
ensure_audit_key

# ── Authority ────────────────────────────────────────────────────────────────

echo "[demo] starting firma authority"
(cd "$ROOT" && exec "$TARGET_DIR/firma" authority --config "$DEMO/firma.toml" \
    >"$LOG_DIR/authority.log" 2>&1) &
AUTH_PID=$!
poll_tcp_loopback 50051 "authority gRPC :50051"

ensure_capability_seed

# ── Sidecar ──────────────────────────────────────────────────────────────────

echo "[demo] starting firma sidecar (log-filter=debug)"
(cd "$ROOT" && FIRMA_STATE_DIR="$DEMO" exec "$TARGET_DIR/firma" --log-filter debug sidecar \
    --config "$DEMO/firma.toml" \
    >"$LOG_DIR/sidecar.log" 2>&1) &
SIDE_PID=$!
poll_http "http://$LOOPBACK_HOST:9000/healthz" "sidecar /healthz"
poll_tcp "$LOOPBACK_HOST" 7474 "sidecar HTTP proxy :7474"
# Wait for the authority policy bundle stream to push the first
# bundle so Stage 2 readiness flips. /healthz is liveness only and
# doesn't surface this state yet.
sleep 1

# ── Driver dispatch ──────────────────────────────────────────────────────────

case "$MODE" in
  hero)
    echo "[demo] installing Python agent deps (uv sync, no proxy)"
    (cd "$ROOT/examples/agents/agents_sdk_py" && just install)
    CA_BUNDLE="$DEMO/firma-ca/firma-ca.crt"
    echo "[demo] dispatching scripted Python hero agent (CA=$CA_BUNDLE)"
    (cd "$ROOT/examples/agents/agents_sdk_py" && \
        HTTPS_PROXY=http://$LOOPBACK_HOST:7474 \
        HTTP_PROXY=http://$LOOPBACK_HOST:7474 \
        SSL_CERT_FILE="$CA_BUNDLE" \
        REQUESTS_CA_BUNDLE="$CA_BUNDLE" \
        FIRMA_SESSION_ID=demo-session \
        FIRMA_SIDECAR_AUDIT_LOG="$LOG_DIR/sidecar.log" \
        just demo-scripted)
    ;;
  repl)
    echo "[demo] installing Python agent deps (uv sync, no proxy)"
    (cd "$ROOT/examples/agents/agents_sdk_py" && just install)
    CA_BUNDLE="$DEMO/firma-ca/firma-ca.crt"
    echo "[demo] dispatching interactive Python REPL (CA=$CA_BUNDLE)"
    (cd "$ROOT/examples/agents/agents_sdk_py" && \
        HTTPS_PROXY=http://$LOOPBACK_HOST:7474 \
        HTTP_PROXY=http://$LOOPBACK_HOST:7474 \
        SSL_CERT_FILE="$CA_BUNDLE" \
        REQUESTS_CA_BUNDLE="$CA_BUNDLE" \
        FIRMA_SESSION_ID=demo-session \
        just run)
    ;;
  ci)
    echo "[demo] starting firma-demo-fixture"
    "$TARGET_DIR/firma-demo-fixture" --listen-addr "$LOOPBACK_HOST:9100" \
        >"$LOG_DIR/fixture.log" 2>&1 &
    FIX_PID=$!
    poll_http "http://$LOOPBACK_HOST:9100/_ping" "fixture /_ping"
    "$TARGET_DIR/firma-demo-fixture-client" \
        --proxy "http://$LOOPBACK_HOST:7474" \
        --target "http://$LOOPBACK_HOST:9100"
    ;;
  *)
    echo "[demo] unknown mode '$MODE'; expected hero|repl|ci" >&2
    exit 2
    ;;
esac
