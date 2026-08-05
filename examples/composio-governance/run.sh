#!/usr/bin/env sh

set -eu

cargo test \
  -p firma-sidecar \
  --test integration \
  composio_mock_tls_demo_covers_enforcement_outcomes \
  -- \
  --nocapture
