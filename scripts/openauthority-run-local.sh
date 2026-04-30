#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 -- <command> [args...]"
  exit 1
fi

if [[ $1 == "--" ]]; then
  shift
fi

cargo run -p openauthority-run -- run -- "$@"
