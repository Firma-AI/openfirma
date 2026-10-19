#!/usr/bin/env bash
set -euo pipefail

vault_response="$(curl --fail --silent http://127.0.0.1:18081/v1/secret)"
if [[ ! "$vault_response" =~ \"value\":\"(fsp_[a-z0-9]+)\" ]]; then
  printf 'ERROR: expected a Firma secret placeholder, got: %s\n' "$vault_response" >&2
  exit 1
fi
placeholder="${BASH_REMATCH[1]}"

echo_response="$(curl --fail --silent \
  -H 'Content-Type: application/json' \
  --data "{\"secret\":\"$placeholder\"}" \
  http://127.0.0.1:18081/v1/echo)"
if [[ "$echo_response" != *"$placeholder"* ]]; then
  printf 'ERROR: echoed response did not preserve the placeholder: %s\n' "$echo_response" >&2
  exit 1
fi

printf 'Mock vault response seen by the sandboxed client:\n%s\n' "$vault_response"
printf 'Masked echo response seen by the sandboxed client:\n%s\n' "$echo_response"
printf 'PASS: client responses preserved the Firma placeholder.\n'
