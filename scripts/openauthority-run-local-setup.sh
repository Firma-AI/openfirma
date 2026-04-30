#!/usr/bin/env bash
set -euo pipefail

ok() { printf '[ok] %s\n' "$1"; }
warn() { printf '[warn] %s\n' "$1"; }
fail() { printf '[fail] %s\n' "$1" >&2; exit 1; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL_DIR="${ROOT_DIR}/.local"
EXAMPLES_DIR="${ROOT_DIR}/docs/examples/openauthority-run"

MAPPING_SRC="${EXAMPLES_DIR}/mapping-rules.local.example.toml"
SIDECAR_SRC="${EXAMPLES_DIR}/openauthority_sidecar.local.example.toml"
MAPPING_DST="${LOCAL_DIR}/mapping-rules.toml"
SIDECAR_DST="${LOCAL_DIR}/openauthority_sidecar.local.toml"
AUDIT_KEY_DST="${LOCAL_DIR}/audit-key.pem"

mkdir -p "$LOCAL_DIR"
ok "ensured local runtime directory: $LOCAL_DIR"

if [[ ! -f "$MAPPING_DST" ]]; then
  cp "$MAPPING_SRC" "$MAPPING_DST"
  ok "created ${MAPPING_DST} from example template"
else
  warn "keeping existing ${MAPPING_DST}"
fi

if [[ ! -f "$SIDECAR_DST" ]]; then
  cp "$SIDECAR_SRC" "$SIDECAR_DST"
  ok "created ${SIDECAR_DST} from example template"
else
  warn "keeping existing ${SIDECAR_DST}"
fi

if [[ ! -f "$AUDIT_KEY_DST" ]]; then
  if command -v openssl >/dev/null 2>&1; then
    openssl genpkey \
      -algorithm EC \
      -pkeyopt ec_paramgen_curve:P-256 \
      -out "$AUDIT_KEY_DST" >/dev/null 2>&1
    chmod 600 "$AUDIT_KEY_DST"
    ok "generated audit signing key at ${AUDIT_KEY_DST}"
  else
    fail "openssl not found; install openssl or create ${AUDIT_KEY_DST} manually"
  fi
else
  chmod 600 "$AUDIT_KEY_DST"
  warn "keeping existing ${AUDIT_KEY_DST}"
fi

cat <<'EOM'

Next steps:
1) Start sidecar:
   cargo run -p opensidecar -- -c .local/openauthority_sidecar.local.toml

2) In a new terminal, run Codex through the wrapper:
   cargo run -p openauthority-run -- run --profile codex -- codex

3) Optional structural E2E smoke:
   scripts/e2e-openauthority-run.sh
EOM
