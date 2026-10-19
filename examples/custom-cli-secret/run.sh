#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EXAMPLE_DIR="$REPO_ROOT/examples/custom-cli-secret"
CLIENT_OUTPUT="$EXAMPLE_DIR/.runtime/client-output.log"
cd "$REPO_ROOT"

if [[ "$(uname -s)" != "Linux" ]]; then
  printf 'ERROR: this example requires the Linux bwrap backend\n' >&2
  exit 1
fi

command -v bwrap >/dev/null 2>&1 || {
  printf 'ERROR: bwrap is required\n' >&2
  exit 1
}
for command_name in cargo install rustc; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'ERROR: %s is required\n' "$command_name" >&2
    exit 1
  }
done

mkdir -p "$EXAMPLE_DIR/.runtime"
touch "$EXAMPLE_DIR/.runtime/revocations.txt"

printf 'Building firma and the secret shim...\n'
cargo build -q -p firma --bin firma
WORKSPACE_ROOT="$(dirname "$(cargo locate-project --workspace --message-format plain)")"
FIRMA_BIN="$WORKSPACE_ROOT/target/debug/firma"

HOST_TARGET=""
while IFS= read -r line; do
  if [[ "$line" == "host: "* ]]; then
    HOST_TARGET="${line#host: }"
  fi
done < <(rustc -vV)
case "$HOST_TARGET" in
  x86_64-unknown-linux-gnu | aarch64-unknown-linux-gnu)
    SHIM_TARGET="${HOST_TARGET%-gnu}-musl"
    ;;
  x86_64-unknown-linux-musl | aarch64-unknown-linux-musl)
    SHIM_TARGET="$HOST_TARGET"
    ;;
  *)
    printf 'ERROR: unsupported Linux Rust host target: %s\n' "$HOST_TARGET" >&2
    exit 1
    ;;
esac

RUSTFLAGS_ENV="CARGO_TARGET_${HOST_TARGET^^}_RUSTFLAGS"
RUSTFLAGS_ENV="${RUSTFLAGS_ENV//-/_}"
env "$RUSTFLAGS_ENV=-C target-feature=+crt-static" \
  cargo build -q --target "$HOST_TARGET" -p firma --bin firma-secret-shim
install -Dm755 \
  "$WORKSPACE_ROOT/target/$HOST_TARGET/debug/firma-secret-shim" \
  "$WORKSPACE_ROOT/target/debug/libexec/openfirma/secret-shims/$SHIM_TARGET/firma-secret-shim"

printf 'Running the custom CLI provider example...\n'
rm -f "$CLIENT_OUTPUT"
PATH="$EXAMPLE_DIR:$PATH" "$FIRMA_BIN" run \
  --profile generic \
  --config "$EXAMPLE_DIR/firma.toml" \
  -- bash "$EXAMPLE_DIR/client.sh" | tee "$CLIENT_OUTPUT"

client_output="$(<"$CLIENT_OUTPUT")"
if [[ "$client_output" == *"local-cli-secret"* ]]; then
  printf 'ERROR: sandboxed client output contained the plaintext secret\n' >&2
  exit 1
fi
printf 'PASS: plaintext stayed outside the sandboxed client.\n'
