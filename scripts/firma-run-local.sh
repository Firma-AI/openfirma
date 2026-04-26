#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 -- <command> [args...]"
  exit 1
fi

cargo run -p firma-run -- run -- "$@"
