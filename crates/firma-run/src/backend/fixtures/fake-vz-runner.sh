#!/bin/sh
set -eu

if [ "${1:-}" = "--supported-contract-version" ]; then
  printf '2\n'
  exit 0
fi

printf '%s\n%s\n' "$1" "$2" > "__FIRMA_ARGS_CAPTURE__"
cp "$2" "__FIRMA_CONTRACT_COPY__"
