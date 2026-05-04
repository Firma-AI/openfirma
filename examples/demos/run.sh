#!/usr/bin/env bash
# Direct terminal runner for the demos. Skips the TUI — boots authority +
# sidecar in the background, runs the agent in the foreground, streams all
# logs to stderr so you can see them inline.
#
# Usage:
#   examples/demos/run.sh demo0 [--prompt TEXT] [--no-build]
#
# Run from the repo root. Stop everything with Ctrl-C.
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <demo-dir> [--prompt TEXT] [--no-build]" >&2
    exit 2
fi

demo="$1"; shift
prompt="Run the three tasks from your instructions and report each outcome."
build=1
while [[ $# -gt 0 ]]; do
    case "$1" in
        --prompt) prompt="$2"; shift 2 ;;
        --no-build) build=0; shift ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
demos_dir="$repo_root/examples/demos"
demo_dir="$demos_dir/$demo"
[[ -d "$demo_dir" ]] || { echo "demo not found: $demo_dir" >&2; exit 1; }

runtime_dir="$demo_dir/.runtime"
mkdir -p "$runtime_dir"

authority_key="$runtime_dir/authority.key"
audit_key="$runtime_dir/audit.key"
ca_dir="$runtime_dir/generated-firma-ca"
ca_cert="$ca_dir/firma-ca.crt"

# 1. Build (once, unless --no-build).
if [[ $build -eq 1 ]]; then
    cargo build -p firma-authority -p firma-sidecar
fi

# 2. Provision authority key if absent.
if [[ ! -f "$authority_key" ]]; then
    cargo run -q -p firma-authority -- generate-key --output "$authority_key"
fi

# 3. Audit key — must exist. The TUI ships an embedded PEM. For run.sh we
# require it to already be in place (the TUI has been run at least once,
# or it was committed). Bail out with a clear hint otherwise.
if [[ ! -f "$audit_key" ]]; then
    echo "missing $audit_key — run the TUI once to provision the embedded demo audit key, or copy one in." >&2
    exit 1
fi

# 4. Sidecar regenerates CA material on every boot. Remove stale cert.
rm -f "$ca_dir/firma-ca.crt" "$ca_dir/firma-ca.key"
mkdir -p "$ca_dir"

# 5. Reset audit log so the run is observable from scratch.
: > "$runtime_dir/audit.jsonl"

# 6. Boot authority + sidecar in background. Trap to clean up.
log_dir="$runtime_dir"
authority_log="$log_dir/authority.log"
sidecar_log="$log_dir/sidecar.log"

cargo run -q -p firma-authority -- --config "$demo_dir/authority.toml" \
    >"$authority_log" 2>&1 &
authority_pid=$!

# Wait for authority to listen on 127.0.0.1:50051.
listen_addr="$(awk -F'=' '/^listen_addr/ {gsub(/[" ]/,"",$2); print $2}' "$demo_dir/authority.toml")"
host="${listen_addr%:*}"; port="${listen_addr##*:}"
for _ in $(seq 1 60); do
    if nc -z "$host" "$port" 2>/dev/null; then break; fi
    sleep 0.5
done

FIRMA_SIDECAR_LOG_LEVEL="${FIRMA_SIDECAR_LOG_LEVEL:-info}" \
cargo run -q -p firma-sidecar -- --config-file "$demo_dir/sidecar.toml" \
    >"$sidecar_log" 2>&1 &
sidecar_pid=$!

cleanup() {
    kill "$sidecar_pid" "$authority_pid" 2>/dev/null || true
    wait "$sidecar_pid" "$authority_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Wait for CA material.
for _ in $(seq 1 120); do
    if [[ -f "$ca_cert" && -f "$ca_dir/firma-ca.key" ]]; then break; fi
    sleep 0.5
done
[[ -f "$ca_cert" ]] || { echo "sidecar never produced CA material; see $sidecar_log" >&2; exit 1; }

# 7. Read the session_id from sidecar.toml so the agent's tool client
#    can attach `x-firma-session-id` and Stage 1 (capability validation)
#    can match the pre-flight token.
session_id="$(awk -F'=' '/^session_id/ {gsub(/[" ]/,"",$2); print $2; exit}' "$demo_dir/sidecar.toml")"

# 8. Build a combined CA bundle. Setting SSL_CERT_FILE=firma-ca.crt alone
#    replaces system trust, so the OpenAI SDK (which talks to a real cert
#    on api.openai.com via NO_PROXY) can't verify. Concatenate certifi's
#    public bundle with the demo's MITM CA so both work in one process.
certifi_bundle="$(cd "$demos_dir" && uv run --quiet python -c 'import certifi; print(certifi.where())')"
combined_ca="$runtime_dir/combined-ca.pem"
cat "$certifi_bundle" "$ca_cert" > "$combined_ca"

# 9. Run the agent in the foreground so the user sees its output directly.
#    api.openai.com is in NO_PROXY: the agent's own LLM traffic is not
#    a demo subject and bypassing the proxy keeps the OpenAI SDK out of
#    Stage 1 capability validation.
cd "$demos_dir"
HTTP_PROXY="http://127.0.0.1:8080" \
HTTPS_PROXY="http://127.0.0.1:8080" \
NO_PROXY="localhost,127.0.0.1,0.0.0.0,::1,api.openai.com" \
SSL_CERT_FILE="$combined_ca" \
FIRMA_SESSION_ID="$session_id" \
FIRMA_DEMO_PROMPT="$prompt" \
uv run "$demo/agent.py"

echo
echo "--- audit log: $runtime_dir/audit.jsonl ---"
cat "$runtime_dir/audit.jsonl"
