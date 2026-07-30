#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

command -v cargo >/dev/null 2>&1 || {
  echo "cargo not found - install rustup from https://rustup.rs"
  exit 1
}

command -v node >/dev/null 2>&1 || {
  echo "node not found - install Node.js >= 20.19 (e.g. via nvm or 'brew install node')"
  exit 1
}

command -v corepack >/dev/null 2>&1 || {
  echo "corepack not found - ships with Node.js >= 16.10; if missing, run 'npm i -g corepack'"
  exit 1
}

# shellcheck source=../../tool-versions.env
. "$ROOT/tool-versions.env"

if ! command -v uv >/dev/null 2>&1; then
  echo "Installing uv..."
  curl -LsSf "https://astral.sh/uv/${UV_VERSION}/install.sh" | sh
fi

if ! command -v protoc >/dev/null 2>&1; then
  echo "Installing protoc..."
  if [ "$(uname)" = "Darwin" ]; then
    command -v brew >/dev/null 2>&1 || {
      echo "Homebrew not found - install from https://brew.sh, then re-run 'just install'"
      exit 1
    }
    brew install protobuf
  elif command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update && sudo apt-get install -y protobuf-compiler
  else
    echo "Please install protoc for your platform and re-run 'just install'"
    exit 1
  fi
fi

if ! command -v dprint >/dev/null 2>&1; then
  echo "Installing dprint..."
  curl -fsSL https://dprint.dev/install.sh | sh -s "$DPRINT_VERSION"
fi

corepack enable >/dev/null 2>&1 || echo "warning: 'corepack enable' failed; you may need to run it with sudo"
