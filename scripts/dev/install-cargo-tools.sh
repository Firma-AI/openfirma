#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=../../tool-versions.env
. "$ROOT/tool-versions.env"

if ! cargo binstall --help >/dev/null 2>&1; then
  curl -L --proto '=https' --tlsv1.2 -sSf \
    https://raw.githubusercontent.com/cargo-bins/cargo-binstall/ead08b90bd7b2e6d81963fb9cf0b7239f66d5db4/install-from-binstall-release.sh |
    BINSTALL_VERSION="$CARGO_BINSTALL_VERSION" bash
fi

if ! command -v cargo-doc-md >/dev/null 2>&1; then
  cargo binstall -y --locked cargo-doc-md@"$CARGO_DOC_MD_VERSION"
fi

if ! command -v cargo-audit >/dev/null 2>&1; then
  cargo binstall -y --locked cargo-audit@"$CARGO_AUDIT_VERSION"
fi

if ! command -v cargo-deny >/dev/null 2>&1; then
  cargo binstall -y --locked cargo-deny@"$CARGO_DENY_VERSION"
fi

if ! command -v cargo-nextest >/dev/null 2>&1; then
  cargo binstall -y --locked cargo-nextest@"$CARGO_NEXTEST_VERSION"
fi

if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
  cargo binstall -y --locked cargo-llvm-cov@"$CARGO_LLVM_COV_VERSION"
fi

if ! command -v dist >/dev/null 2>&1; then
  cargo binstall -y --locked cargo-dist@"$CARGO_DIST_VERSION"
fi
