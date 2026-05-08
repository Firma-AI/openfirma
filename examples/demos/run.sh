#!/usr/bin/env bash
# Direct terminal runner for the demos. Skips the TUI — boots authority +
# sidecar in the background, runs the demo script in the foreground.
#
# Usage:
#   examples/demos/run.sh demo0 [--no-build] [--no-script]
#
# Run from the repo root. Stop everything with Ctrl-C.
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <demo-dir> [--no-build] [--no-script]" >&2
    exit 2
fi

demo="$1"; shift
build=1
run_script=1
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-build) build=0; shift ;;
        --no-script|--no-agent) run_script=0; shift ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
demos_dir="$repo_root/examples/demos"
demo_dir="$demos_dir/$demo"
[[ -d "$demo_dir" ]] || { echo "demo not found: $demo_dir" >&2; exit 1; }

# Source .env so the sidecar inherits demo credentials (e.g. GITHUB_TOKEN
# for demo2's [credentials.github] block). Values in .env override prior
# shell exports — shape demo behaviour from this single file.
if [[ -f "$demos_dir/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "$demos_dir/.env"
    set +a
fi

runtime_dir="$demo_dir/.runtime"
mkdir -p "$runtime_dir"

authority_key="$runtime_dir/authority.key"
audit_key="$runtime_dir/audit.key"
ca_dir="$runtime_dir/generated-firma-ca"
ca_cert="$ca_dir/firma-ca.crt"

# 1. Build (once, unless --no-build).
if [[ $build -eq 1 ]]; then
    cargo build -p firma
fi

# 2. Provision authority key if absent.
if [[ ! -f "$authority_key" ]]; then
    cargo run -q -p firma -- authority generate-key --output "$authority_key"
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

cargo run -q -p firma -- authority --config "$demo_dir/authority.toml" \
    >"$authority_log" 2>&1 &
authority_pid=$!

# Wait for authority to listen on 127.0.0.1:50051.
listen_addr="$(awk -F'=' '/^listen_addr/ {gsub(/[" ]/,"",$2); print $2}' "$demo_dir/authority.toml")"
host="${listen_addr%:*}"; port="${listen_addr##*:}"
for _ in $(seq 1 60); do
    if nc -z "$host" "$port" 2>/dev/null; then break; fi
    sleep 0.5
done

cargo run -q -p firma -- --log-filter "${FIRMA_SIDECAR_LOG_LEVEL:-info}" sidecar --config-file "$demo_dir/sidecar.toml" \
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

# Give the sidecar a moment to finish the initial revocation sync before
# the first request lands. Without this, the first call races the cache
# and is denied with RevocationCacheNotReady.
sleep 2

# 7. Read session_id from sidecar.toml so the script can attach
#    `x-firma-session-id` and Stage 1 (capability validation) can match
#    the pre-flight token.
session_id="$(awk -F'=' '/^session_id/ {gsub(/[" ]/,"",$2); print $2; exit}' "$demo_dir/sidecar.toml")"

if [[ $run_script -eq 0 ]]; then
    echo "skipping demo script (--no-script). Sidecar + authority running; Ctrl-C to stop." >&2
    wait "$sidecar_pid" "$authority_pid"
    exit 0
fi

# 8. Pre-sync Python deps before exporting the proxy. `uv run` would
#    otherwise try to fetch hatchling/etc. through the sidecar, which has
#    no policy for pypi.org and denies the request.
(cd "$demos_dir" && uv sync --quiet)

# 9. Run the demo script in the foreground so the user sees its output
#    directly. Every outbound HTTP call is routed through the sidecar.
cd "$demos_dir"
HTTP_PROXY="http://127.0.0.1:8080" \
HTTPS_PROXY="http://127.0.0.1:8080" \
NO_PROXY="localhost,127.0.0.1,0.0.0.0,::1,pypi.org,files.pythonhosted.org" \
SSL_CERT_FILE="$ca_cert" \
REQUESTS_CA_BUNDLE="$ca_cert" \
FIRMA_SESSION_ID="$session_id" \
uv run --offline "$demo/agent.py"

echo
echo "--- audit log: $runtime_dir/audit.jsonl ---"
cat "$runtime_dir/audit.jsonl"
