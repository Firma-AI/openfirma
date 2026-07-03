#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Ad-hoc sign firma-vz-runner for local Apple Virtualization.framework testing.

Usage:
  scripts/macos-vz/sign-vz-runner-dev.sh [SOURCE_RUNNER] [OUT_RUNNER]

Defaults:
  SOURCE_RUNNER  target/debug/firma-vz-runner
  OUT_RUNNER     target/macos-vz-runner-dev/firma-vz-runner

Environment:
  CODESIGN_IDENTITY              Signing identity. Default: - (ad-hoc).
  FIRMA_VZ_RUNNER_ENTITLEMENTS   Entitlements plist to use.
EOF
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  usage
  exit 0
fi

if [ "$(uname -s)" != "Darwin" ]; then
  echo "firma-vz-runner signing is macOS-only" >&2
  exit 1
fi

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)"
source_runner="${1:-"$repo_root/target/debug/firma-vz-runner"}"
out_runner="${2:-"$repo_root/target/macos-vz-runner-dev/firma-vz-runner"}"
entitlements="${FIRMA_VZ_RUNNER_ENTITLEMENTS:-"$repo_root/scripts/macos-vz/firma-vz-runner.dev.entitlements"}"
identity="${CODESIGN_IDENTITY:--}"

if [ ! -x "$source_runner" ]; then
  echo "source runner is missing or not executable: $source_runner" >&2
  echo "build it first with: cargo build -p firma-vz-runner" >&2
  exit 1
fi
if [ ! -f "$entitlements" ]; then
  echo "entitlements file is missing: $entitlements" >&2
  exit 1
fi
if ! command -v codesign >/dev/null 2>&1; then
  echo "codesign is required on macOS" >&2
  exit 1
fi

mkdir -p "$(dirname -- "$out_runner")"
if [ "$(cd "$(dirname -- "$source_runner")" && pwd -P)/$(basename -- "$source_runner")" != \
     "$(cd "$(dirname -- "$out_runner")" && pwd -P)/$(basename -- "$out_runner")" ]; then
  cp "$source_runner" "$out_runner"
fi
chmod 0755 "$out_runner"

codesign --force --sign "$identity" --entitlements "$entitlements" "$out_runner"
codesign --verify --strict --verbose=2 "$out_runner"
codesign -d --entitlements :- "$out_runner" \
  > "$out_runner.entitlements.plist" \
  2> "$out_runner.codesign.txt"

cat <<EOF
signed firma-vz-runner:
  source:       $source_runner
  output:       $out_runner
  entitlements: $out_runner.entitlements.plist
  identity:     $identity
EOF
