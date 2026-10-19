#!/usr/bin/env bash
set -euo pipefail
umask 077

ok() { printf '[ok] %s\n' "$1"; }
fail() { printf '[fail] %s\n' "$1" >&2; exit 1; }
usage() {
  cat <<'EOF'
Usage: examples/firma-run/e2e/run.sh [--profile <name>] [--cmd "<command>"]
       [--https-check] [--claude-acceptance] [--keep-artifacts]

Starts a temporary Authority, Sidecar and controlled HTTP destination, provisions
a session capability, runs a sandboxed command, checks audit/dispatch evidence,
and verifies fail-closed behavior when the Sidecar stops. Linux with bwrap only.
The default command uses the controlled destination; --cmd must make an outbound
call to produce audit evidence. --claude-acceptance also checks filesystem guards.
EOF
}

PROFILE=generic
USER_CMD=""
HTTPS_CHECK=0
CLAUDE_ACCEPTANCE=0
KEEP_ARTIFACTS=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile|--cmd)
      option="$1"; shift
      [[ $# -gt 0 ]] || fail "$option requires a value"
      if [[ "$option" == --profile ]]; then PROFILE="$1"; else USER_CMD="$1"; fi
      ;;
    --https-check) HTTPS_CHECK=1 ;;
    --claude-acceptance) CLAUDE_ACCEPTANCE=1; PROFILE=claude-code ;;
    --keep-artifacts) KEEP_ARTIFACTS=1 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
  shift
done
[[ "$(uname -s)" == Linux ]] || fail "this harness requires Linux"
for command in cargo bwrap curl python3 openssl timeout; do
  command -v "$command" >/dev/null || fail "required command not found: $command"
done
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/firma-run-e2e.XXXXXX")"
AUTHORITY_PID=""
SIDECAR_PID=""
PROBE_PID=""
stop_process() {
  local pid="$1"
  [[ -n "$pid" ]] || return 0
  kill "$pid" 2>/dev/null || true
  for _ in $(seq 1 50); do
    if ! kill -0 "$pid" 2>/dev/null; then break; fi
    sleep 0.1
  done
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}
cleanup() {
  stop_process "$SIDECAR_PID"
  stop_process "$AUTHORITY_PID"
  stop_process "$PROBE_PID"
  if [[ "$KEEP_ARTIFACTS" -eq 1 ]]; then
    printf 'Artifacts: %s\n' "$WORKDIR"
  else
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM
export FIRMA_STATE_DIR="$WORKDIR/state"
export FIRMA_RUN_SESSION_ID="sess_shell_smoke_$$"
export NO_COLOR=1
export NO_PROXY=""
export no_proxy=""
mkdir -p "$FIRMA_STATE_DIR/capabilities" "$WORKDIR/policies" "$WORKDIR/issuance" "$WORKDIR/mappings" \
  "$WORKDIR/fake-home/.ssh"

cargo build --manifest-path "$ROOT_DIR/crates/firma/Cargo.toml" -p firma
target="$(cargo metadata --manifest-path "$ROOT_DIR/crates/firma/Cargo.toml" --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
FIRMA_BIN="$target/debug/firma"
AUTHORITY_KEY="$FIRMA_STATE_DIR/authority.key"
AUDIT_KEY="$FIRMA_STATE_DIR/audit.key"
CAPABILITY="$FIRMA_STATE_DIR/capabilities/smoke.toml"
CONFIG="$WORKDIR/firma.toml"
AUDIT="$WORKDIR/audit.jsonl"
"$FIRMA_BIN" authority generate-key --output "$AUTHORITY_KEY" >/dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$AUDIT_KEY" 2>/dev/null
printf 'permit(principal, action, resource);\n' >"$WORKDIR/issuance/permit.cedar"
if [[ "$CLAUDE_ACCEPTANCE" -eq 1 ]]; then
  printf 'forbid(principal, action, resource);\n' >"$WORKDIR/policies/policy.cedar"
else
  printf 'permit(principal, action, resource);\n' >"$WORKDIR/policies/policy.cedar"
fi
# The Authority watches each mapping file's directory; keep it free of written artifacts.
MAPPING_RULES="$WORKDIR/mappings/mapping-rules.toml"
printf '[[rules]]\nhost = "*"\naction_class = "communication.external.send"\n' >"$MAPPING_RULES"
MOUNTS="mounts = [{ source = \"$ROOT_DIR\", target = \"$ROOT_DIR\", read_only = false }]"
if [[ "$HTTPS_CHECK" -eq 1 ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
    -addext 'subjectAltName=IP:127.0.0.1' -keyout "$WORKDIR/probe.key" -out "$WORKDIR/probe.crt" 2>/dev/null
  # Only the public certificate enters the guest, never the control-plane keys.
  MOUNTS="mounts = [{ source = \"$ROOT_DIR\", target = \"$ROOT_DIR\", read_only = false }, { source = \"$WORKDIR/probe.crt\", target = \"$WORKDIR/probe.crt\", read_only = true }]"
fi
cat >"$CONFIG" <<EOF
[authority]
listen_addr = "127.0.0.1:0"
policy_dir = "$WORKDIR/policies"
issuance_policy_dir = "$WORKDIR/issuance"
mapping_rules_paths = ["$MAPPING_RULES"]
key_file = "$AUTHORITY_KEY"
revocation_file = "$WORKDIR/revocations.txt"

[sidecar.interceptor]
mode = "http_proxy"
listen_addr = "127.0.0.1:0"
[sidecar.interceptor.https_mitm]
bypass_hosts = ["*"]
[sidecar.authority]
url = "http://127.0.0.1:0"
agent_id = "agt_01j0000000e008000000000001"
public_key_path = "$FIRMA_STATE_DIR/authority.pub"
[sidecar.capability_seed]
paths = ["$CAPABILITY"]
[sidecar.audit]
sink = "file"
file_path = "$AUDIT"
signing_key_path = "$AUDIT_KEY"

[run]
profile = "$PROFILE"
[run.profiles."$PROFILE"]
backend = "bwrap"
$MOUNTS
[run.profiles."$PROFILE".capability]
source = { kind = "file", path = "$CAPABILITY" }
public_key_path = "$FIRMA_STATE_DIR/authority.pub"
EOF
cat >"$WORKDIR/issuance.toml" <<EOF
[authority]
policy_dir = "$WORKDIR/issuance"
mapping_rules_paths = ["$MAPPING_RULES"]
key_file = "$AUTHORITY_KEY"
EOF
"$FIRMA_BIN" authority --no-tls --config "$WORKDIR/issuance.toml" issue \
  --agent-id agt_01j0000000e008000000000001 --session-id "$FIRMA_RUN_SESSION_ID" \
  --action communication.external.send --resource-scope '*' --ttl-seconds 3600 \
  --output "$CAPABILITY" >/dev/null

wait_report() {
  local report="$1" pid="$2" log="$3" deadline=$((SECONDS + 20))
  while [[ ! -s "$report" ]]; do
    if ! kill -0 "$pid" 2>/dev/null || [[ "$SECONDS" -ge "$deadline" ]]; then
      cat "$log" >&2
      fail "component did not publish readiness"
    fi
    sleep 0.05
  done
  python3 -c 'import sys,tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["endpoint"])' "$report"
}
"$FIRMA_BIN" authority --no-tls --config "$CONFIG" --startup-report "$WORKDIR/authority.ready" >"$WORKDIR/authority.log" 2>&1 &
AUTHORITY_PID=$!
AUTHORITY_ADDR="$(wait_report "$WORKDIR/authority.ready" "$AUTHORITY_PID" "$WORKDIR/authority.log")"
# Only the logical Authority URL changes; the Sidecar still binds an ephemeral port.
sed -i "s|url = \"http://127.0.0.1:0\"|url = \"http://$AUTHORITY_ADDR\"|" "$CONFIG"
"$FIRMA_BIN" sidecar --config "$CONFIG" --health-bind-addr 127.0.0.1:0 --startup-report "$WORKDIR/sidecar.ready" >"$WORKDIR/sidecar.log" 2>&1 &
SIDECAR_PID=$!
SIDECAR_ADDR="$(wait_report "$WORKDIR/sidecar.ready" "$SIDECAR_PID" "$WORKDIR/sidecar.log")"
ok "Authority and Sidecar hydrated"

python3 - "$WORKDIR" "$HTTPS_CHECK" <<'PY' >"$WORKDIR/probe.log" 2>&1 &
import http.server, pathlib, ssl, sys
root = pathlib.Path(sys.argv[1])
class Probe(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with (root / "probe.requests").open("a") as captured:
            captured.write(self.path + "\n")
        self.send_response(200)
        self.send_header("Content-Length", "9")
        self.end_headers()
        self.wfile.write(b"smoke-ok\n")
server = http.server.HTTPServer(("127.0.0.1", 0), Probe)
if sys.argv[2] == "1":
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / "probe.crt", root / "probe.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
(root / "probe.ready").write_text(f"127.0.0.1:{server.server_port}")
server.serve_forever()
PY
PROBE_PID=$!
deadline=$((SECONDS + 10))
while [[ ! -s "$WORKDIR/probe.ready" ]]; do
  kill -0 "$PROBE_PID" 2>/dev/null || fail "probe exited"
  [[ "$SECONDS" -lt "$deadline" ]] || fail "probe startup timed out"
  sleep 0.05
done
scheme=http
[[ "$HTTPS_CHECK" -eq 0 ]] || scheme=https
URL="$scheme://$(<"$WORKDIR/probe.ready")/smoke-$$"
DEFAULT_CMD=0
if [[ -z "$USER_CMD" ]]; then
  DEFAULT_CMD=1
  USER_CMD="printf 'HTTP ATTEMPT\\n'; curl --fail-with-body --silent --show-error --max-time 10"
  [[ "$HTTPS_CHECK" -eq 0 ]] || USER_CMD+=" --cacert '$WORKDIR/probe.crt'"
  USER_CMD+=" '$URL'"
fi
run() {
  timeout --kill-after=5s 120s "$FIRMA_BIN" run --config "$CONFIG" --profile "$PROFILE" \
    --authority "http://$AUTHORITY_ADDR" --sidecar "tcp://$SIDECAR_ADDR" -- "$@"
}
if [[ "$CLAUDE_ACCEPTANCE" -eq 1 ]]; then
  if run /bin/sh -c "$USER_CMD" >"$WORKDIR/run.stdout" 2>"$WORKDIR/run.stderr"; then
    fail "forbid policy admitted the request"
  fi
  [[ ! -s "$WORKDIR/probe.requests" ]] || fail "denied request reached the probe"
  if [[ "$DEFAULT_CMD" -eq 1 ]]; then
    grep -qx 'HTTP ATTEMPT' "$WORKDIR/run.stdout" || fail "sandboxed command did not run"
  fi
  printf 'VERY_SECRET_TEST_KEY\n' >"$WORKDIR/fake-home/.ssh/id_rsa"
  export HOME="$WORKDIR/fake-home"
  for command in 'echo blocked >/etc/firma-run-claude-probe' 'cat ~/.ssh/id_rsa'; do
    if run /bin/sh -c "$command" >"$WORKDIR/guard.stdout" 2>"$WORKDIR/guard.stderr"; then
      fail "filesystem guard admitted: $command"
    fi
  done
  expected=deny
else
  run /bin/sh -c "$USER_CMD" >"$WORKDIR/run.stdout" 2>"$WORKDIR/run.stderr" || {
    cat "$WORKDIR/run.stderr" >&2; fail "governed command failed";
  }
  if [[ "$DEFAULT_CMD" -eq 1 ]]; then
    grep -qx 'HTTP ATTEMPT' "$WORKDIR/run.stdout" || fail "sandboxed command did not run"
  fi
  if [[ "$USER_CMD" == *"$URL"* ]]; then
    grep -q "/smoke-$$" "$WORKDIR/probe.requests" || fail "request did not reach controlled destination"
  fi
  expected=allow
fi
python3 - "$AUDIT" "$expected" <<'PY'
import json, sys
events = [json.loads(line) for line in open(sys.argv[1])]
expected = {"allow": 1, "deny": 2}[sys.argv[2]]
assert any(event["decision"] == expected and event["signature"] for event in events), events
PY
ok "dispatch and audit decision verified"
stop_process "$SIDECAR_PID"
SIDECAR_PID=""
if run /bin/sh -c "$USER_CMD" >"$WORKDIR/stopped.stdout" 2>"$WORKDIR/stopped.stderr"; then
  fail "run succeeded with an unavailable Sidecar"
fi
grep -q "sidecar endpoint .* is unreachable" "$WORKDIR/stopped.stderr" || {
  cat "$WORKDIR/stopped.stderr" >&2; fail "run did not report the unreachable Sidecar";
}
! grep -q 'HTTP ATTEMPT' "$WORKDIR/stopped.stdout" || fail "command ran without a Sidecar"
ok "unavailable Sidecar fails closed"
