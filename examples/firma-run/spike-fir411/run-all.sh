#!/usr/bin/env bash
# Run the whole FIR-411 spike: three demos, five break-out attempts, and the
# latency probe. Prints a break-out results table at the end.
#
# Prereq: cargo build -p firma  (and python3 + bwrap on PATH).

source "$(dirname "$0")/lib/common.sh"

rm -f "$BREAKOUT_RESULTS"

for demo in "$SPIKE_DIR"/demos/demo*.sh; do
  bash "$demo" 2>&1 | grep -vE \
    '^\[INFO\]|bubblewrap|network enforcement proof|seccomp|egress guard started|sidecar (started|stopped)|authority (started|stopped)|loaded firma|starting firma|resolved managed'
  echo
done

for probe in "$SPIKE_DIR"/breakout/b*.sh; do
  bash "$probe" 2>&1 | grep -vE \
    '^\[INFO\]|bubblewrap|network enforcement proof|seccomp|egress guard started|sidecar (started|stopped)|authority (started|stopped)|loaded firma|starting firma|resolved managed'
  echo
done

bash "$SPIKE_DIR/bench-latency.sh" 2>&1 | grep -vE \
  '^\[INFO\]|bubblewrap|network enforcement proof|seccomp|egress guard started|sidecar (started|stopped)|authority (started|stopped)|loaded firma|starting firma|resolved managed'

banner "BREAK-OUT RESULTS"
if [[ -f "$BREAKOUT_RESULTS" ]]; then
  printf '%-4s  %-20s  %-24s  %s\n' "id" "surface" "result" "defeats-hypothesis"
  hr
  while IFS=$'\t' read -r id surface result defeats; do
    printf '%-4s  %-20s  %-24s  %s\n' "$id" "$surface" "$result" "$defeats"
  done <"$BREAKOUT_RESULTS"
fi
