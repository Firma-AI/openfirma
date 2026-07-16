#!/usr/bin/env bash
# Demo 3 — Scoped secret read denied.
#
# The agent tries to read a credential file under ~/.aws.
#
#   bare:  the file is right there and its contents are read.
#   boxed: the generic profile tmpfs-masks ~/.aws (and the other sensitive home
#          subpaths), so the directory is empty inside the box — the file is
#          simply not there to read.
#
# Limit (see plan): this works only for the hardcoded masked suffix list
# (~/.ssh, ~/.aws, ~/.azure, ~/.kube, ~/.gnupg, ~/.config[/gcloud]). An
# arbitrary out-of-scope secret path in a bound directory is still readable.
# This demo does not fix that; it documents the boundary.
#
# Safety: this never touches an existing ~/.aws/credentials. It writes a
# uniquely named fake file and removes it (and ~/.aws if it created it) on exit.

source "$(dirname "$0")/../lib/common.sh"

FAKE_DIR="$HOME/.aws"
FAKE_FILE="$FAKE_DIR/firma-spike-fake-credential"
CREATED_DIR=0

cleanup() {
  rm -f "$FAKE_FILE"
  [[ "$CREATED_DIR" -eq 1 ]] && rmdir "$FAKE_DIR" 2>/dev/null || true
}
trap cleanup EXIT

if [[ ! -d "$FAKE_DIR" ]]; then
  mkdir -p "$FAKE_DIR"
  CREATED_DIR=1
fi
if [[ -e "$FAKE_FILE" ]]; then
  echo "refusing to overwrite existing $FAKE_FILE" >&2
  exit 1
fi
printf 'aws_secret_access_key = FIR411-FAKE-SECRET-DO-NOT-LEAK\n' >"$FAKE_FILE"

PAYLOAD="$RUNTIME_DIR/demo3-payload.sh"
cat >"$PAYLOAD" <<PAYLOAD_EOF
#!/usr/bin/env bash
set -uo pipefail
TARGET="$FAKE_FILE"
echo "[agent] attempting to read scoped secret: \$TARGET"
if [[ -r "\$TARGET" ]]; then
  echo "[agent] READ secret -> \$(cat "\$TARGET")"
else
  echo "[agent] secret NOT present (masked/absent)"
fi
PAYLOAD_EOF

cd "$SPIKE_DIR"

banner "DEMO 3 — bare (no boundary)"
run_bare "$PAYLOAD"
echo "[result] expect the fake secret to be READ above (LEAK)"

banner "DEMO 3 — boxed (firma run)"
run_boxed "$PAYLOAD"
echo "[result] expect the secret to be MASKED/absent above (DENIED)"
