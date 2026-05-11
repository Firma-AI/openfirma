#!/usr/bin/env sh
set -eu

# Shell-heavy syscall workload:
# - high process spawn churn
# - metadata/file reads
# - deterministic exit code

loops="${FIR_SPIKE_INNER_LOOPS:-120}"
i=0

while [ "$i" -lt "$loops" ]; do
  /bin/true
  /bin/echo "$i" >/dev/null
  /bin/ls -1 >/dev/null 2>&1
  stat . >/dev/null 2>&1 || true
  /bin/cat /etc/hosts >/dev/null 2>&1 || true
  i=$((i + 1))
done

exit 0
