#!/bin/sh
set -eu

printf '%s\n%s\n' "$1" "$2" > "__FIRMA_ARGS_CAPTURE__"
cp "$2" "__FIRMA_CONTRACT_COPY__"
