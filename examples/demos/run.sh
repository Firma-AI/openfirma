#!/usr/bin/env bash
# Direct terminal runner for the demos. Skips the TUI — boots authority +
# sidecar in the background via `firma sidecar start --detach`, runs the demo
# script in the foreground, then tears everything down on exit.
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

firma() {
    cargo run -q -p firma -- "$@"
}

# 1. Build (once, unless --no-build).
if [[ $build -eq 1 ]]; then
    cargo build -p firma
fi

# 2. Provision authority key if absent. (Demo-specific; firma sidecar start
#    does not own key material.)
if [[ ! -f "$authority_key" ]]; then
    firma authority generate-key --output "$authority_key"
fi

# 3. Audit key — must exist. The TUI ships an embedded PEM. For run.sh we
#    require it to already be in place (the TUI has been run at least once,
#    or it was committed). Bail out with a clear hint otherwise.
if [[ ! -f "$audit_key" ]]; then
    echo "missing $audit_key — run the TUI once to provision the embedded demo audit key, or copy one in." >&2
    exit 1
fi

# 4. Sidecar regenerates CA material on every boot. Remove stale cert so the
#    sidecar produces fresh material on `sidecar start`.
rm -f "$ca_dir/firma-ca.crt" "$ca_dir/firma-ca.key"
mkdir -p "$ca_dir"

# 5. Reset audit log so the run is observable from scratch.
: > "$runtime_dir/audit.jsonl"

# 6. Start the sidecar daemon (detached) from this demo's unified `firma.toml`.
#    `start` blocks until both authority and sidecar are listening and CA
#    material is on disk, then forks a supervisor and returns. On any error,
#    `start` tears down what it spawned and exits non-zero — fail-closed.
firma sidecar start --detach --state-dir "$runtime_dir" --config "$demo_dir/firma.toml"

cleanup() {
    firma sidecar stop --state-dir "$runtime_dir" --timeout 10 || true
}
trap cleanup EXIT INT TERM

# Give the sidecar a moment to finish the initial revocation sync before
# the first request lands. Without this, the first call races the cache
# and is denied with RevocationCacheNotReady.
sleep 2

if [[ $run_script -eq 0 ]]; then
    echo "skipping demo script (--no-script). Tailing audit log; Ctrl-C to stop." >&2
    exec firma monitor --state-dir "$runtime_dir" --source audit
fi

# 8. Pre-sync Python deps before exporting the proxy. `uv run` would
#    otherwise try to fetch hatchling/etc. through the sidecar, which has
#    no policy for pypi.org and denies the request.
(cd "$demos_dir" && uv sync --quiet)

# 10. Run the demo script in the foreground so the user sees its output
#     directly. Every outbound HTTP call is routed through the sidecar.
cd "$demos_dir"
HTTP_PROXY="http://127.0.0.1:8080" \
HTTPS_PROXY="http://127.0.0.1:8080" \
NO_PROXY="localhost,127.0.0.1,0.0.0.0,::1,pypi.org,files.pythonhosted.org" \
SSL_CERT_FILE="$ca_cert" \
REQUESTS_CA_BUNDLE="$ca_cert" \
uv run --offline "$demo/agent.py"

echo
echo "--- audit log: $runtime_dir/audit.jsonl ---"
cat "$runtime_dir/audit.jsonl"
