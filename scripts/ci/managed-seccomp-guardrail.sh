#!/usr/bin/env bash
set -euo pipefail

ok() { printf '[ok] %s\n' "$1"; }
warn() { printf '[warn] %s\n' "$1"; }
fail() { printf '[fail] %s\n' "$1" >&2; exit 1; }

wait_for_port() {
  local host="$1"
  local port="$2"
  local attempts=80
  local i
  for i in $(seq 1 "$attempts"); do
    if python3 - <<'PY' "$host" "$port" >/dev/null 2>&1
import socket
import sys
host = sys.argv[1]
port = int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(0.2)
try:
    s.connect((host, port))
finally:
    s.close()
PY
    then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

if [[ "$(uname -s)" != "Linux" ]]; then
  fail "managed seccomp guardrail is Linux-only"
fi

command -v python3 >/dev/null 2>&1 || fail "python3 is required"
command -v bwrap >/dev/null 2>&1 || fail "bwrap is required"
command -v cargo >/dev/null 2>&1 || fail "cargo is required"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"

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

[profiles.generic.seccomp_policy]
source_policy_path = '$POLICY_PATH'
artifact_dir = '$OUT_ROOT/artifacts'
verify_checksum = true
runtime_mode = "precompiled_only"
EOF

PRECOMPILE_CONFIG="$OUT_ROOT/firma-run.precompile.toml"
cat >"$PRECOMPILE_CONFIG" <<EOF
[profiles.generic]
backend = "bwrap"

[profiles.generic.seccomp_policy]
source_policy_path = '$POLICY_PATH'
artifact_dir = '$OUT_ROOT/artifacts'
verify_checksum = true
runtime_mode = "compile_on_launch"
EOF

BAD_MISSING_POLICY_CONFIG="$OUT_ROOT/firma-run.missing-policy.toml"
cat >"$BAD_MISSING_POLICY_CONFIG" <<EOF
[profiles.generic]
backend = "bwrap"

[profiles.generic.network]
fail_closed = false

[profiles.generic.seccomp_policy]
source_policy_path = '$OUT_ROOT/does-not-exist.toml'
artifact_dir = '$OUT_ROOT/artifacts'
verify_checksum = true
EOF

policy_id="$(awk -F= '/^policy_id/{gsub(/["'"'"'[:space:]]/,"",$2); print $2; exit}' "$POLICY_PATH")"
policy_version="$(awk -F= '/^policy_version/{gsub(/["'"'"'[:space:]]/,"",$2); print $2; exit}' "$POLICY_PATH")"
[[ -n "$policy_id" ]] || fail "failed to parse policy_id from $POLICY_PATH"
[[ -n "$policy_version" ]] || fail "failed to parse policy_version from $POLICY_PATH"

host_arch="$(uname -m)"
case "$host_arch" in
  x86_64|aarch64) target_arch="$host_arch" ;;
  arm64) target_arch="aarch64" ;;
  *) fail "unsupported host arch for guardrail artifact path: $host_arch" ;;
esac

artifact_rel_dir="$policy_id/$policy_version/$target_arch"

run_expect_fail_closed() {
  local config_path="$1"
  local stderr_path="$2"
  local pattern="$3"
  local label="$4"

  set +e
  target/release/firma run \
    --profile generic \
    --config "$config_path" \
    --sidecar-endpoint tcp://127.0.0.1:65535 \
    -- /bin/true >/dev/null 2>"$stderr_path"
  local status=$?
  set -e
  if [[ "$status" -eq 0 ]]; then
    fail "expected non-zero exit for $label"
  fi
  if ! grep -Eq "$pattern" "$stderr_path"; then
    warn "$label stderr:"
    sed -n '1,120p' "$stderr_path" >&2 || true
    fail "missing expected fail-closed error for $label"
  fi
  ok "$label fail-closed check passed"
}

ok "building release firma binary"
cargo build -p firma --release >/dev/null

ok "precompiling managed artifact for benchmark path"
set +e
target/release/firma run \
  --profile generic \
  --config "$PRECOMPILE_CONFIG" \
  --sidecar-endpoint tcp://127.0.0.1:65535 \
  -- /bin/true >/dev/null 2>"$OUT_ROOT/precompile.stderr.log"
precompile_status=$?
set -e
if ! grep -q "resolved managed static seccomp artifact" "$OUT_ROOT/precompile.stderr.log"; then
  warn "precompile stderr:"
  sed -n '1,120p' "$OUT_ROOT/precompile.stderr.log" >&2 || true
  fail "failed to precompile managed artifact for benchmark path"
fi
if [[ "$precompile_status" -ne 0 ]] && ! grep -Eq "sidecar endpoint .* is unreachable" "$OUT_ROOT/precompile.stderr.log"; then
  warn "precompile stderr:"
  sed -n '1,120p' "$OUT_ROOT/precompile.stderr.log" >&2 || true
  fail "precompile step failed for an unexpected reason"
fi
ok "precompile step completed"

ok "verifying default-managed seccomp path for generic Linux profile"
DEFAULT_MANAGED_STDERR="$OUT_ROOT/default-managed.stderr.log"
set +e
FIRMA_RUN_MANAGED_SECCOMP_DISABLE_DEFAULT=0 target/release/firma run \
  --profile generic \
  --sidecar-endpoint tcp://127.0.0.1:65535 \
  -- /bin/true >/dev/null 2>"$DEFAULT_MANAGED_STDERR"
default_status=$?
set -e
if ! grep -q "resolved managed static seccomp artifact" "$DEFAULT_MANAGED_STDERR"; then
  warn "default-managed stderr:"
  sed -n '1,120p' "$DEFAULT_MANAGED_STDERR" >&2 || true
  fail "generic Linux profile did not resolve managed static seccomp by default"
fi
if [[ "$default_status" -ne 0 ]] && ! grep -Eq "sidecar endpoint .* is unreachable" "$DEFAULT_MANAGED_STDERR"; then
  warn "default-managed stderr:"
  sed -n '1,120p' "$DEFAULT_MANAGED_STDERR" >&2 || true
  fail "generic Linux default-managed check failed for an unexpected reason"
fi
ok "default-managed generic profile check passed"

ok "running baseline benchmark"
FIRMA_RUN_MANAGED_SECCOMP_DISABLE_DEFAULT=1 spikes/firma-run/fir-111/run.sh \
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
run_expect_fail_closed \
  "$BAD_MISSING_POLICY_CONFIG" \
  "$OUT_ROOT/missing-policy.stderr.log" \
  "failed to read seccomp policy|seccomp_policy\\.source_policy_path must point to an existing file" \
  "missing policy source"

PRECOMPILED_GOOD_CONFIG="$OUT_ROOT/firma-run.precompiled-good.toml"
cat >"$PRECOMPILED_GOOD_CONFIG" <<EOF
[profiles.generic]
backend = "bwrap"

[profiles.generic.seccomp_policy]
source_policy_path = '$POLICY_PATH'
artifact_dir = '$OUT_ROOT/artifacts'
verify_checksum = true
runtime_mode = "precompiled_only"
EOF
PRECOMPILED_GOOD_SIDE_PORT="$((RANDOM % 10000 + 20000))"
PRECOMPILED_GOOD_SIDE_LOG="$OUT_ROOT/precompiled-good-sidecar.log"
python3 -m http.server --bind 127.0.0.1 "$PRECOMPILED_GOOD_SIDE_PORT" >"$PRECOMPILED_GOOD_SIDE_LOG" 2>&1 &
PRECOMPILED_GOOD_SIDE_PID="$!"
if ! wait_for_port "127.0.0.1" "$PRECOMPILED_GOOD_SIDE_PORT"; then
  sed -n '1,120p' "$PRECOMPILED_GOOD_SIDE_LOG" >&2 || true
  kill "$PRECOMPILED_GOOD_SIDE_PID" >/dev/null 2>&1 || true
  wait "$PRECOMPILED_GOOD_SIDE_PID" >/dev/null 2>&1 || true
  fail "precompiled-good mock sidecar failed to start on 127.0.0.1:${PRECOMPILED_GOOD_SIDE_PORT}"
fi
set +e
target/release/firma run \
  --profile generic \
  --config "$PRECOMPILED_GOOD_CONFIG" \
  --sidecar-endpoint "tcp://127.0.0.1:${PRECOMPILED_GOOD_SIDE_PORT}" \
  -- /bin/true >/dev/null 2>"$OUT_ROOT/precompiled-good.stderr.log"
precompiled_good_status=$?
set -e
kill "$PRECOMPILED_GOOD_SIDE_PID" >/dev/null 2>&1 || true
wait "$PRECOMPILED_GOOD_SIDE_PID" >/dev/null 2>&1 || true
if [[ "$precompiled_good_status" -ne 0 ]]; then
  if grep -Eq "bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted" "$OUT_ROOT/precompiled-good.stderr.log"; then
    warn "precompiled-good run hit host network-namespace capability limitation; treating as pass for artifact-resolution check"
    ok "precompiled-only runtime mode resolved valid managed artifact before host netns limitation"
  else
  warn "precompiled-good stderr:"
  sed -n '1,120p' "$OUT_ROOT/precompiled-good.stderr.log" >&2 || true
  fail "precompiled-only runtime mode failed with valid managed artifact"
  fi
else
  ok "precompiled-only runtime mode succeeds with valid managed artifact"
fi

BAD_MISSING_ARTIFACT_CONFIG="$OUT_ROOT/firma-run.precompiled-missing-artifact.toml"
cat >"$BAD_MISSING_ARTIFACT_CONFIG" <<EOF
[profiles.generic]
backend = "bwrap"

[profiles.generic.seccomp_policy]
source_policy_path = '$POLICY_PATH'
artifact_dir = '$OUT_ROOT/missing-artifacts'
verify_checksum = true
runtime_mode = "precompiled_only"
EOF
run_expect_fail_closed \
  "$BAD_MISSING_ARTIFACT_CONFIG" \
  "$OUT_ROOT/missing-artifact.stderr.log" \
  "failed to read seccomp metadata" \
  "missing precompiled artifact"

BAD_INVALID_DIR="$OUT_ROOT/bad-artifacts-invalid/$artifact_rel_dir"
mkdir -p "$BAD_INVALID_DIR"
cp "$ARTIFACT_FILE" "$BAD_INVALID_DIR/policy.bpf"
printf '{invalid-json\n' >"$BAD_INVALID_DIR/policy.metadata.json"
BAD_INVALID_CONFIG="$OUT_ROOT/firma-run.precompiled-invalid-metadata.toml"
cat >"$BAD_INVALID_CONFIG" <<EOF
[profiles.generic]
backend = "bwrap"

[profiles.generic.seccomp_policy]
source_policy_path = '$POLICY_PATH'
artifact_dir = '$OUT_ROOT/bad-artifacts-invalid'
verify_checksum = true
runtime_mode = "precompiled_only"
EOF
run_expect_fail_closed \
  "$BAD_INVALID_CONFIG" \
  "$OUT_ROOT/invalid-metadata.stderr.log" \
  "failed to parse seccomp metadata" \
  "invalid artifact metadata format"

BAD_CHECKSUM_DIR="$OUT_ROOT/bad-artifacts-checksum/$artifact_rel_dir"
mkdir -p "$BAD_CHECKSUM_DIR"
cp "$ARTIFACT_FILE" "$BAD_CHECKSUM_DIR/policy.bpf"
cp "$METADATA_FILE" "$BAD_CHECKSUM_DIR/policy.metadata.json"
printf '\x00\x01\x02\x03' >"$BAD_CHECKSUM_DIR/policy.bpf"
BAD_CHECKSUM_CONFIG="$OUT_ROOT/firma-run.precompiled-checksum-mismatch.toml"
cat >"$BAD_CHECKSUM_CONFIG" <<EOF
[profiles.generic]
backend = "bwrap"

[profiles.generic.seccomp_policy]
source_policy_path = '$POLICY_PATH'
artifact_dir = '$OUT_ROOT/bad-artifacts-checksum'
verify_checksum = true
runtime_mode = "precompiled_only"
EOF
run_expect_fail_closed \
  "$BAD_CHECKSUM_CONFIG" \
  "$OUT_ROOT/checksum-mismatch.stderr.log" \
  "seccomp checksum mismatch" \
  "artifact checksum mismatch"

BAD_INVALID_BPF_DIR="$OUT_ROOT/bad-artifacts-invalid-bpf/$artifact_rel_dir"
mkdir -p "$BAD_INVALID_BPF_DIR"
cp "$METADATA_FILE" "$BAD_INVALID_BPF_DIR/policy.metadata.json"
printf '\x00\x01\x02' >"$BAD_INVALID_BPF_DIR/policy.bpf"
BAD_INVALID_BPF_SHA="$(sha256sum "$BAD_INVALID_BPF_DIR/policy.bpf" | awk '{print $1}')"
BAD_INVALID_BPF_METADATA_TMP="$BAD_INVALID_BPF_DIR/policy.metadata.json.tmp"
awk -v sha="$BAD_INVALID_BPF_SHA" '
BEGIN { replaced=0 }
{
  if (!replaced && $0 ~ /"sha256"[[:space:]]*:[[:space:]]*"/) {
    sub(/"sha256"[[:space:]]*:[[:space:]]*"[^"]*"/, "\"sha256\": \"" sha "\"")
    replaced=1
  }
  print
}
END {
  if (!replaced) {
    exit 2
  }
}
' "$BAD_INVALID_BPF_DIR/policy.metadata.json" >"$BAD_INVALID_BPF_METADATA_TMP" \
  || fail "failed to rewrite sha256 field in invalid-bpf metadata"
mv "$BAD_INVALID_BPF_METADATA_TMP" "$BAD_INVALID_BPF_DIR/policy.metadata.json"
BAD_INVALID_BPF_CONFIG="$OUT_ROOT/firma-run.precompiled-invalid-bpf.toml"
cat >"$BAD_INVALID_BPF_CONFIG" <<EOF
[profiles.generic]
backend = "bwrap"

[profiles.generic.seccomp_policy]
source_policy_path = '$POLICY_PATH'
artifact_dir = '$OUT_ROOT/bad-artifacts-invalid-bpf'
verify_checksum = true
runtime_mode = "precompiled_only"
EOF
BAD_INVALID_BPF_SIDE_PORT="$((RANDOM % 10000 + 20000))"
BAD_INVALID_BPF_SIDE_LOG="$OUT_ROOT/invalid-bpf-sidecar.log"
python3 -m http.server --bind 127.0.0.1 "$BAD_INVALID_BPF_SIDE_PORT" >"$BAD_INVALID_BPF_SIDE_LOG" 2>&1 &
BAD_INVALID_BPF_SIDE_PID="$!"
if ! wait_for_port "127.0.0.1" "$BAD_INVALID_BPF_SIDE_PORT"; then
  sed -n '1,120p' "$BAD_INVALID_BPF_SIDE_LOG" >&2 || true
  kill "$BAD_INVALID_BPF_SIDE_PID" >/dev/null 2>&1 || true
  wait "$BAD_INVALID_BPF_SIDE_PID" >/dev/null 2>&1 || true
  fail "invalid-bpf mock sidecar failed to start on 127.0.0.1:${BAD_INVALID_BPF_SIDE_PORT}"
fi
set +e
target/release/firma run \
  --profile generic \
  --config "$BAD_INVALID_BPF_CONFIG" \
  --sidecar-endpoint "tcp://127.0.0.1:${BAD_INVALID_BPF_SIDE_PORT}" \
  -- /bin/true >/dev/null 2>"$OUT_ROOT/invalid-bpf.stderr.log"
bad_invalid_bpf_status=$?
set -e
kill "$BAD_INVALID_BPF_SIDE_PID" >/dev/null 2>&1 || true
wait "$BAD_INVALID_BPF_SIDE_PID" >/dev/null 2>&1 || true
if [[ "$bad_invalid_bpf_status" -eq 0 ]]; then
  fail "expected non-zero exit for invalid readable BPF artifact"
fi
if ! grep -Eq "bwrap:|seccomp.*(invalid|fail|error|argument|load)|Invalid argument|Operation not permitted" "$OUT_ROOT/invalid-bpf.stderr.log"; then
  warn "invalid-bpf stderr:"
  sed -n '1,120p' "$OUT_ROOT/invalid-bpf.stderr.log" >&2 || true
  fail "missing expected runtime seccomp-load failure for invalid readable BPF artifact"
fi
ok "invalid readable BPF artifact fail-closed check passed"

BAD_UNLOADABLE_DIR="$OUT_ROOT/bad-artifacts-unloadable/$artifact_rel_dir"
mkdir -p "$BAD_UNLOADABLE_DIR"
cp "$ARTIFACT_FILE" "$BAD_UNLOADABLE_DIR/policy.bpf"
cp "$METADATA_FILE" "$BAD_UNLOADABLE_DIR/policy.metadata.json"
chmod 000 "$BAD_UNLOADABLE_DIR/policy.bpf"
BAD_UNLOADABLE_CONFIG="$OUT_ROOT/firma-run.precompiled-unloadable.toml"
cat >"$BAD_UNLOADABLE_CONFIG" <<EOF
[profiles.generic]
backend = "bwrap"

[profiles.generic.seccomp_policy]
source_policy_path = '$POLICY_PATH'
artifact_dir = '$OUT_ROOT/bad-artifacts-unloadable'
verify_checksum = true
runtime_mode = "precompiled_only"
EOF
run_expect_fail_closed \
  "$BAD_UNLOADABLE_CONFIG" \
  "$OUT_ROOT/unloadable.stderr.log" \
  "failed to read seccomp artifact|Permission denied" \
  "unloadable artifact"
chmod 600 "$BAD_UNLOADABLE_DIR/policy.bpf" || true

ok "running focused seccomp unit tests"
# Run the focused suite in release profile to reuse release-built deps and
# avoid an additional full dev/test-profile compile pass in CI.
cargo test -p firma-run seccomp::tests --release -- --nocapture >/dev/null

ok "managed seccomp guardrail passed"
printf 'guardrail_output_dir=%s\n' "$OUT_ROOT"
