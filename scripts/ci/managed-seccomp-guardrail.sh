#!/usr/bin/env bash
set -euo pipefail

ok() { printf '[ok] %s\n' "$1"; }
warn() { printf '[warn] %s\n' "$1"; }
fail() { printf '[fail] %s\n' "$1" >&2; exit 1; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

if [[ "$(uname -s)" != "Linux" ]]; then
  fail "managed seccomp guardrail is Linux-only"
fi

command -v python3 >/dev/null 2>&1 || fail "python3 is required"
command -v bwrap >/dev/null 2>&1 || fail "bwrap is required"
command -v cargo >/dev/null 2>&1 || fail "cargo is required"

THRESHOLD_PCT="${MANAGED_SECCOMP_MAX_OVERHEAD_PCT:-3.00}"
ITERATIONS="${MANAGED_SECCOMP_GUARDRAIL_ITERATIONS:-12}"
INNER_LOOPS="${MANAGED_SECCOMP_GUARDRAIL_INNER_LOOPS:-120}"
POLICY_PATH="${MANAGED_SECCOMP_POLICY_PATH:-$ROOT_DIR/crates/firma-run/policies/generic-local-command-v1.toml}"

[[ -f "$POLICY_PATH" ]] || fail "policy file not found: $POLICY_PATH"
if [[ "$POLICY_PATH" != /* ]]; then
  fail "policy path must be absolute: $POLICY_PATH"
fi

SPIKE_ROOT="${FIR_SPIKE_OUTPUT_DIR:-$ROOT_DIR/.spike-output}"
RUN_ID="managed-seccomp-guardrail-$(date -u +%Y%m%dT%H%M%SZ)"
OUT_ROOT="$SPIKE_ROOT/$RUN_ID"
BASELINE_DIR="$OUT_ROOT/baseline"
MANAGED_DIR="$OUT_ROOT/managed"
mkdir -p "$OUT_ROOT/artifacts"

ok "running managed seccomp compatibility check"
scripts/seccomp/check-managed-compatibility.sh --format text | tee "$OUT_ROOT/compatibility.txt" >/dev/null

MANAGED_CONFIG="$OUT_ROOT/firma-run.managed.toml"
cat >"$MANAGED_CONFIG" <<EOF
[profiles.generic]
backend = "bwrap"

[profiles.generic.seccomp_managed]
source_policy_path = '$POLICY_PATH'
artifact_dir = '$OUT_ROOT/artifacts'
verify_checksum = true
EOF

BAD_MISSING_POLICY_CONFIG="$OUT_ROOT/firma-run.missing-policy.toml"
cat >"$BAD_MISSING_POLICY_CONFIG" <<EOF
[profiles.generic]
backend = "bwrap"

[profiles.generic.network]
fail_closed = false

[profiles.generic.seccomp_managed]
source_policy_path = '$OUT_ROOT/does-not-exist.toml'
artifact_dir = '$OUT_ROOT/artifacts'
verify_checksum = true
EOF

ok "building release firma binary"
cargo build -p firma --release >/dev/null

ok "running baseline benchmark"
spikes/firma-run/fir-111/run.sh \
  --mode baseline \
  --firma-bin target/release/firma \
  --profile generic \
  --iterations "$ITERATIONS" \
  --inner-loops "$INNER_LOOPS" \
  --output-dir "$BASELINE_DIR"

ok "running managed seccomp benchmark"
spikes/firma-run/fir-111/run.sh \
  --mode baseline \
  --firma-bin target/release/firma \
  --profile generic \
  --iterations "$ITERATIONS" \
  --inner-loops "$INNER_LOOPS" \
  --run-config "$MANAGED_CONFIG" \
  --output-dir "$MANAGED_DIR"

read_summary_field() {
  local file="$1"
  local key="$2"
  awk -F= -v k="$key" '$1==k {print $2}' "$file" | tail -n 1
}

baseline_summary="$BASELINE_DIR/summary.txt"
managed_summary="$MANAGED_DIR/summary.txt"
[[ -f "$baseline_summary" ]] || fail "missing baseline summary: $baseline_summary"
[[ -f "$managed_summary" ]] || fail "missing managed summary: $managed_summary"

baseline_avg="$(read_summary_field "$baseline_summary" avg_ms)"
managed_avg="$(read_summary_field "$managed_summary" avg_ms)"
overhead_pct="$(awk -v b="$baseline_avg" -v m="$managed_avg" 'BEGIN { if (b <= 0) print "999.000"; else printf "%.3f", ((m-b)*100.0)/b }')"

ok "baseline avg_ms=$baseline_avg managed avg_ms=$managed_avg overhead_pct=$overhead_pct threshold_pct=$THRESHOLD_PCT"
awk -v o="$overhead_pct" -v t="$THRESHOLD_PCT" 'BEGIN { exit (o <= t ? 0 : 1) }' || fail "managed seccomp overhead ${overhead_pct}% exceeds threshold ${THRESHOLD_PCT}%"

ARTIFACT_FILE="$(find "$OUT_ROOT/artifacts" -type f -name policy.bpf | head -n 1 || true)"
METADATA_FILE="$(find "$OUT_ROOT/artifacts" -type f -name policy.metadata.json | head -n 1 || true)"
[[ -n "$ARTIFACT_FILE" && -f "$ARTIFACT_FILE" ]] || fail "managed artifact policy.bpf not generated"
[[ -n "$METADATA_FILE" && -f "$METADATA_FILE" ]] || fail "managed artifact metadata not generated"
ok "artifact generated: $ARTIFACT_FILE"
ok "metadata generated: $METADATA_FILE"
scripts/seccomp/inspect-managed-artifact.sh \
  --artifact "$ARTIFACT_FILE" \
  --metadata "$METADATA_FILE" >/dev/null
ok "artifact integrity inspection passed"

ok "verifying fail-closed on missing policy source"
set +e
target/release/firma run \
  --profile generic \
  --config "$BAD_MISSING_POLICY_CONFIG" \
  --sidecar-endpoint tcp://127.0.0.1:65535 \
  -- /bin/true >/dev/null 2>"$OUT_ROOT/missing-policy.stderr.log"
status=$?
set -e
if [[ "$status" -eq 0 ]]; then
  fail "expected non-zero exit for missing managed seccomp policy source"
fi
if ! grep -q "failed to read managed seccomp policy" "$OUT_ROOT/missing-policy.stderr.log"; then
  warn "missing-policy stderr:"
  sed -n '1,120p' "$OUT_ROOT/missing-policy.stderr.log" >&2 || true
  fail "missing expected fail-closed error message for missing policy source"
fi
ok "missing-policy fail-closed check passed"

ok "running focused seccomp unit tests"
cargo test -p firma-run seccomp::tests -- --nocapture >/dev/null

ok "managed seccomp guardrail passed"
printf 'guardrail_output_dir=%s\n' "$OUT_ROOT"
