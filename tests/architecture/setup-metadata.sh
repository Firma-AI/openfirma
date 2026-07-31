#!/usr/bin/env bash
# Precompute `cargo metadata` once for all architecture tests.
set -euo pipefail

metadata_path="$(dirname "$NEXTEST_ENV")/architecture-metadata.json"

cargo metadata --all-features --format-version 1 > "$metadata_path"
printf 'FIRMA_ARCHITECTURE_METADATA=%s\n' "$metadata_path" >> "$NEXTEST_ENV"
