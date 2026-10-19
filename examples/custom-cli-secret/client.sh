#!/usr/bin/env bash
set -euo pipefail

output="$(mock-secret-cli secret get)"

if [[ ! "$output" =~ \"value\":\"fsp_[a-z0-9]+\" ]]; then
  printf 'ERROR: expected a Firma secret placeholder, got: %s\n' "$output" >&2
  exit 1
fi

printf 'Mock CLI response seen by the sandboxed client:\n%s\n' "$output"
printf 'PASS: the sandboxed client received a Firma placeholder.\n'
