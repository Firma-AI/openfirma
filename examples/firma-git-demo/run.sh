#!/usr/bin/env bash
# GitHub HTTPS git demo for FIR-413.
#
# Required environment:
#   FIRMA_GIT_DEMO_GITHUB_TOKEN  GitHub PAT with read/write access to the test repo
#   FIRMA_GIT_DEMO_REPO          GitHub repository in owner/repo form

set -euo pipefail

MODE="${1:-ci}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TEMPLATE_DIR="$SCRIPT_DIR/config"
TARGET_DIR="$ROOT/target/release"
LOOPBACK_HOST="127.0.0.1"
AUTHORITY_ADDR="$LOOPBACK_HOST:50151"
SIDECAR_PROXY_ADDR="$LOOPBACK_HOST:7575"
SIDECAR_HEALTH_ADDR="$LOOPBACK_HOST:9101"
HEADER_BRIDGE_ADDR="$LOOPBACK_HOST:7676"
AGENT_ID="agt_01j0000000e008000000000001"
SESSION_ID="firma-git-demo-session"
RUN_SUFFIX="${GITHUB_RUN_ID:-local-$(date -u +%Y%m%d%H%M%S)-$RANDOM}"
ALLOWED_BRANCH="firma-git-demo-allowed-$RUN_SUFFIX"
DENIED_BRANCH="main"

AUTH_PID=""
SIDE_PID=""
BRIDGE_PID=""
STATE_DIR=""
WORKTREE=""

dump_diagnostics() {
  if [[ -z "$STATE_DIR" || ! -d "$STATE_DIR/logs" ]]; then
    return
  fi
  echo "[git-demo] diagnostics: $STATE_DIR/logs" >&2
  for log in "$STATE_DIR/logs/sidecar.log" "$STATE_DIR/logs/authority.log"; do
    if [[ -s "$log" ]]; then
      echo "[git-demo] --- ${log##*/} tail ---" >&2
      tail -n 120 "$log" >&2 || true
    fi
  done
}

usage() {
  cat <<EOF
Usage: examples/firma-git-demo/run.sh [ci]

Runs the FIR-413 GitHub HTTPS git demo against FIRMA_GIT_DEMO_REPO.
Missing FIRMA_GIT_DEMO_GITHUB_TOKEN or FIRMA_GIT_DEMO_REPO causes a clean skip.
EOF
}

cleanup() {
  local status=$?
  trap - INT TERM EXIT
  if (( status != 0 )); then
    dump_diagnostics
  fi
  if [[ -n "$STATE_DIR" && -f "$STATE_DIR/remote-cleanup-branch" ]]; then
    local cleanup_branch
    cleanup_branch="$(< "$STATE_DIR/remote-cleanup-branch")"
    if [[ -n "$cleanup_branch" ]]; then
      github_api_delete_ref "heads/$cleanup_branch"
    fi
  fi
  for pid in "$BRIDGE_PID" "$SIDE_PID" "$AUTH_PID"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  wait 2>/dev/null || true
  if [[ -n "$WORKTREE" && -d "$WORKTREE" ]]; then
    rm -rf "$WORKTREE"
  fi
  if [[ -n "$STATE_DIR" && -d "$STATE_DIR" && -z "${FIRMA_GIT_DEMO_KEEP_STATE:-}" ]]; then
    rm -rf "$STATE_DIR"
  elif [[ -n "$STATE_DIR" && -d "$STATE_DIR" ]]; then
    echo "[git-demo] preserved state: $STATE_DIR" >&2
  fi
}
trap cleanup INT TERM EXIT

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[git-demo] missing required command: $cmd" >&2
    exit 1
  fi
}

poll_tcp() {
  local host="$1"
  local port="$2"
  local label="${3:-$host:$port}"
  local deadline=$((SECONDS + 20))
  while (( SECONDS < deadline )); do
    if nc -z "$host" "$port" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  echo "[git-demo] timed out waiting for $label" >&2
  return 1
}

poll_http() {
  local url="$1"
  local label="${2:-$url}"
  local deadline=$((SECONDS + 20))
  while (( SECONDS < deadline )); do
    if curl -sf "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  echo "[git-demo] timed out waiting for $label" >&2
  return 1
}

poll_file() {
  local path="$1"
  local label="${2:-$path}"
  local deadline=$((SECONDS + 20))
  while (( SECONDS < deadline )); do
    if [[ -r "$path" ]]; then
      return 0
    fi
    sleep 0.2
  done
  echo "[git-demo] timed out waiting for $label" >&2
  return 1
}

skip_if_unconfigured() {
  if [[ -z "${FIRMA_GIT_DEMO_GITHUB_TOKEN:-}" ]]; then
    echo "[git-demo] skipping: FIRMA_GIT_DEMO_GITHUB_TOKEN is not set"
    exit 0
  fi
  if [[ -z "${FIRMA_GIT_DEMO_REPO:-}" ]]; then
    echo "[git-demo] skipping: FIRMA_GIT_DEMO_REPO is not set"
    exit 0
  fi
}

validate_repo_slug() {
  if [[ ! "$FIRMA_GIT_DEMO_REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
    echo "[git-demo] FIRMA_GIT_DEMO_REPO must be owner/repo" >&2
    exit 2
  fi
}

github_api_delete_ref() {
  local ref="$1"
  curl -fsS --noproxy '*' \
    -X DELETE \
    -H "Authorization: Bearer $FIRMA_GIT_DEMO_GITHUB_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com/repos/$FIRMA_GIT_DEMO_REPO/git/refs/$ref" \
    >/dev/null 2>&1 || true
}

github_api_restore_branch() {
  local branch="$1"
  local sha="$2"
  if [[ -z "$sha" ]]; then
    return
  fi
  curl -fsS --noproxy '*' \
    -X PATCH \
    -H "Authorization: Bearer $FIRMA_GIT_DEMO_GITHUB_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com/repos/$FIRMA_GIT_DEMO_REPO/git/refs/heads/$branch" \
    -d "{\"sha\":\"$sha\",\"force\":true}" \
    >/dev/null 2>&1 || true
}

github_api_create_ref_if_missing() {
  local ref="$1"
  local sha="$2"
  if curl -fsS --noproxy '*' \
    -H "Authorization: Bearer $FIRMA_GIT_DEMO_GITHUB_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com/repos/$FIRMA_GIT_DEMO_REPO/git/refs/$ref" \
    >/dev/null 2>&1; then
    return
  fi
  curl -fsS --noproxy '*' \
    -X POST \
    -H "Authorization: Bearer $FIRMA_GIT_DEMO_GITHUB_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com/repos/$FIRMA_GIT_DEMO_REPO/git/refs" \
    -d "{\"ref\":\"refs/$ref\",\"sha\":\"$sha\"}" \
    >/dev/null
}

render_template() {
  local source="$1"
  local destination="$2"
  shift 2
  python3 - "$source" "$destination" "$@" <<'PY'
from pathlib import Path
import re
import sys

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
args = sys.argv[3:]
if len(args) % 2 != 0:
    raise SystemExit("template replacements must be key/value pairs")

content = source.read_text(encoding="utf-8")
for index in range(0, len(args), 2):
    content = content.replace("{{" + args[index] + "}}", args[index + 1])

unresolved = sorted(set(re.findall(r"\{\{[A-Z0-9_]+\}\}", content)))
if unresolved:
    raise SystemExit(f"unresolved template placeholders in {source}: {', '.join(unresolved)}")

destination.write_text(content, encoding="utf-8")
PY
}

write_runtime_files() {
  local owner="${FIRMA_GIT_DEMO_REPO%%/*}"
  local repo="${FIRMA_GIT_DEMO_REPO#*/}"

  mkdir -p \
    "$STATE_DIR/capabilities" \
    "$STATE_DIR/policies" \
    "$STATE_DIR/issuance-policies" \
    "$STATE_DIR/firma-ca" \
    "$STATE_DIR/logs"
  : > "$STATE_DIR/revocations.txt"

  cp "$TEMPLATE_DIR/issuance.cedar" "$STATE_DIR/issuance-policies/issuance.cedar"
  render_template "$TEMPLATE_DIR/git-demo.cedar.tmpl" "$STATE_DIR/policies/git-demo.cedar" \
    AGENT_ID "$AGENT_ID" \
    ALLOWED_BRANCH "$ALLOWED_BRANCH" \
    OWNER "$owner" \
    REPO "$repo"
  render_template "$TEMPLATE_DIR/firma.toml.tmpl" "$STATE_DIR/firma.toml" \
    AUTHORITY_ADDR "$AUTHORITY_ADDR" \
    ROOT "$ROOT" \
    SIDECAR_PROXY_ADDR "$SIDECAR_PROXY_ADDR" \
    STATE_DIR "$STATE_DIR"
  render_template "$TEMPLATE_DIR/firma-issue.toml.tmpl" "$STATE_DIR/firma-issue.toml" \
    AUTHORITY_ADDR "$AUTHORITY_ADDR"
}

bootstrap_keys() {
  echo "[git-demo] generating runtime keys"
  (cd "$STATE_DIR" && "$TARGET_DIR/firma" authority generate-key --output firma-authority.key)
  (cd "$STATE_DIR" && "$TARGET_DIR/firma" authority init-tls \
    --out-dir . \
    --host "$LOOPBACK_HOST" \
    --host localhost)
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$STATE_DIR/audit.key" >/dev/null 2>&1
}

issue_capability_seed() {
  echo "[git-demo] issuing capability seed"
  (cd "$ROOT" && "$TARGET_DIR/firma" authority \
    --config "$STATE_DIR/firma-issue.toml" \
    issue \
      --agent-id "$AGENT_ID" \
      --session-id "$SESSION_ID" \
      --action code.read \
      --action code.write \
      --action code.destructive \
      --resource-scope 'github.com' \
      --ttl-seconds 3600 \
      --output "$STATE_DIR/capabilities/capability-git-demo.toml")
}

git_via_firma() {
  env -u FIRMA_GIT_DEMO_GITHUB_TOKEN \
    GIT_TERMINAL_PROMPT=0 \
    GIT_SSL_CAINFO="$STATE_DIR/firma-ca/firma-ca.crt" \
    HTTP_PROXY="http://$HEADER_BRIDGE_ADDR" \
    HTTPS_PROXY="http://$HEADER_BRIDGE_ADDR" \
    NO_PROXY="" \
    git "$@"
}

start_header_bridge() {
  echo "[git-demo] starting attribution bridge"
  python3 "$SCRIPT_DIR/header_bridge.py" \
    "$HEADER_BRIDGE_ADDR" \
    "$SIDECAR_PROXY_ADDR" \
    "$SESSION_ID" &
  BRIDGE_PID=$!
  poll_tcp "$LOOPBACK_HOST" "7676" "attribution bridge :7676"
}

start_services() {
  echo "[git-demo] starting firma authority"
  (cd "$ROOT" && exec "$TARGET_DIR/firma" authority --config "$STATE_DIR/firma.toml" \
    >"$STATE_DIR/logs/authority.log" 2>&1) &
  AUTH_PID=$!
  poll_tcp "$LOOPBACK_HOST" "50151" "authority gRPC :50151"

  issue_capability_seed

  echo "[git-demo] starting firma sidecar"
  (cd "$ROOT" && FIRMA_STATE_DIR="$STATE_DIR" exec "$TARGET_DIR/firma" --log-filter debug sidecar \
    --config "$STATE_DIR/firma.toml" \
    --health-bind-addr "$SIDECAR_HEALTH_ADDR" \
    >"$STATE_DIR/logs/sidecar.log" 2>&1) &
  SIDE_PID=$!
  poll_http "http://$SIDECAR_HEALTH_ADDR/healthz" "sidecar /healthz"
  poll_tcp "$LOOPBACK_HOST" "7575" "sidecar HTTP proxy :7575"
  poll_file "$STATE_DIR/firma-ca/firma-ca.crt" "sidecar MITM CA"
  start_header_bridge
  sleep 1
}

run_git_demo() {
  local remote_url="https://github.com/$FIRMA_GIT_DEMO_REPO"
  local denied_original_sha=""

  WORKTREE="$(mktemp -d "${TMPDIR:-/tmp}/firma-git-demo-worktree.XXXXXX")"
  github_api_delete_ref "heads/$ALLOWED_BRANCH"

  echo "[git-demo] cloning $FIRMA_GIT_DEMO_REPO through firma"
  git_via_firma clone "$remote_url" "$WORKTREE/repo"

  (
    cd "$WORKTREE/repo"
    git config user.name "Firma Git Demo"
    git config user.email "firma-git-demo@example.invalid"

    git checkout -B "$ALLOWED_BRANCH"
    {
      echo "firma-git-demo"
      date -u +"%Y-%m-%dT%H:%M:%SZ"
      printf "run=%s\n" "$RANDOM"
    } > firma-git-demo.txt
    git add firma-git-demo.txt
    git commit -m "Update firma git demo fixture"

    echo "[git-demo] pushing allowed branch refs/heads/$ALLOWED_BRANCH"
    git_via_firma push -f origin "HEAD:refs/heads/$ALLOWED_BRANCH"
    printf "%s" "$ALLOWED_BRANCH" > "$STATE_DIR/remote-cleanup-branch"

    github_api_create_ref_if_missing "heads/$DENIED_BRANCH" "$(git rev-parse HEAD)"
    {
      echo "denied-main-update"
      date -u +"%Y-%m-%dT%H:%M:%SZ"
      printf "run=%s\n" "$RANDOM"
    } >> firma-git-demo.txt
    git add firma-git-demo.txt
    git commit -m "Attempt denied firma git demo update"

    denied_original_sha="$(git_via_firma ls-remote origin "refs/heads/$DENIED_BRANCH" | awk '{print $1}')"
    if [[ -z "$denied_original_sha" ]]; then
      echo "[git-demo] skipping denied main push: refs/heads/$DENIED_BRANCH does not exist"
    else
      echo "[git-demo] verifying denied push to refs/heads/$DENIED_BRANCH"
      if git_via_firma push \
        --force-with-lease="refs/heads/$DENIED_BRANCH:$denied_original_sha" \
        origin "HEAD:refs/heads/$DENIED_BRANCH"; then
        github_api_restore_branch "$DENIED_BRANCH" "$denied_original_sha"
        echo "[git-demo] expected push to refs/heads/$DENIED_BRANCH to be denied" >&2
        exit 1
      fi
    fi

    echo "[git-demo] verifying denied deletion of refs/heads/$ALLOWED_BRANCH"
    if git_via_firma push origin ":refs/heads/$ALLOWED_BRANCH"; then
      echo "[git-demo] expected deletion of refs/heads/$ALLOWED_BRANCH to be denied" >&2
      exit 1
    fi
  )

  github_api_delete_ref "heads/$ALLOWED_BRANCH"
  rm -f "$STATE_DIR/remote-cleanup-branch"

  local sidecar_log="$STATE_DIR/logs/sidecar.log"
  grep -q '"action":"code.write".*"decision":2' "$sidecar_log" || {
    echo "[git-demo] missing sidecar DENY audit for code.write" >&2
    exit 1
  }
  grep -q '"action":"code.destructive".*"decision":2' "$sidecar_log" || {
    echo "[git-demo] missing sidecar DENY audit for code.destructive" >&2
    exit 1
  }
  echo "[git-demo] completed successfully"
  echo "[git-demo] logs: $STATE_DIR/logs"
}

case "$MODE" in
  ci)
    skip_if_unconfigured
    validate_repo_slug
    require_cmd cargo
    require_cmd curl
    require_cmd git
    require_cmd nc
    require_cmd openssl
    require_cmd python3

    echo "[git-demo] building release firma binary"
    (cd "$ROOT" && cargo build --release -p firma)

    STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/firma-git-demo-state.XXXXXX")"
    write_runtime_files
    bootstrap_keys
    start_services
    run_git_demo
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    echo "[git-demo] unknown mode '$MODE'; expected ci" >&2
    exit 2
    ;;
esac
