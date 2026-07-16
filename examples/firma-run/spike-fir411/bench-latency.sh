#!/usr/bin/env bash
# Latency probe for the finding.
#
# Two numbers:
#   1. Per-action overhead — N approved-api calls timed inside one session,
#      bare (direct to the server) vs boxed (through the sidecar: proxy bridge +
#      normalizer + capability validation + Cedar + connector). The delta is the
#      sidecar's per-request cost, isolated from process startup.
#   2. Cold-start overhead — wall-clock for `firma run -- /bin/true`, i.e. the
#      one-time cost of standing up authority + sidecar + bwrap + seccomp.

source "$(dirname "$0")/../spike-fir411/lib/common.sh"

N="${N:-30}"

TIMER="$RUNTIME_DIR/bench-payload.sh"
cat >"$TIMER" <<PAYLOAD_EOF
#!/usr/bin/env bash
set -uo pipefail
N=$N
start=\$(date +%s.%N)
ok=0
for _ in \$(seq 1 \$N); do
  code=\$(curl -s -o /dev/null -w '%{http_code}' -m 8 \
    "http://approved-api.localhost:8081/data" || echo 000)
  [[ "\$code" == "200" ]] && ok=\$((ok+1))
done
end=\$(date +%s.%N)
awk -v s="\$start" -v e="\$end" -v n=\$N -v ok=\$ok \
  'BEGIN { printf "requests=%d ok=%d total=%.3fs per_call=%.1fms\n", n, ok, e-s, (e-s)/n*1000 }'
PAYLOAD_EOF

cd "$SPIKE_DIR"
start_servers
trap stop_servers EXIT

banner "LATENCY — per-action (N=$N)"
echo -n "bare  (direct):  "; run_bare "$TIMER"
echo -n "boxed (sidecar): "; run_boxed "$TIMER" 2>/dev/null | grep -E 'requests='

banner "LATENCY — cold start of the boxed stack"
cold_payload="$RUNTIME_DIR/bench-true.sh"
echo 'true' >"$cold_payload"
t0=$(date +%s.%N)
run_boxed "$cold_payload" >/dev/null 2>&1
t1=$(date +%s.%N)
awk -v s="$t0" -v e="$t1" 'BEGIN { printf "firma run -- true cold start: %.2fs\n", e-s }'
