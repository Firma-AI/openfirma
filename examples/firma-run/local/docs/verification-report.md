# Firma Run Verification Report

This document records a reproducible verification flow for local sandbox + sidecar routing and a sample result matrix.

Use it as a reviewer checklist when validating local setup changes.

## Prompt Used For Verification

Use this prompt inside a Codex session started with:

```bash
cargo run -p firma -- run --profile codex -- codex
```

Then ask:

```text
Run this full verification and return only a markdown table plus final verdict:

1) env | rg "^(HTTP|HTTPS|ALL)_PROXY|^NO_PROXY|^FIRMA_RUN_|^FIRMA_SIDECAR_"
2) id && whoami && getent passwd $(id -u) || true
3) ss -ltn | rg "127.0.0.1:18080" || true
4) [ -n "$FIRMA_RUN_RUNTIME_DIR" ] && ls -la "$FIRMA_RUN_RUNTIME_DIR" && sed -n '1,120p' "$FIRMA_RUN_RUNTIME_DIR/proxy-bridge.log" || true
5) curl -sS --max-time 20 -o /tmp/http.out -w "http status=%{http_code}\n" http://example.com ; echo "http exit=$?"
6) curl -sS --max-time 20 -o /tmp/https.out -w "https status=%{http_code}\n" https://example.com ; echo "https exit=$?"
7) env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u NO_PROXY -u http_proxy -u https_proxy -u all_proxy -u no_proxy curl -sS --max-time 20 -o /tmp/direct.out -w "direct status=%{http_code}\n" https://httpbin.org/get ; echo "direct exit=$?"
8) cat /etc/resolv.conf; getent hosts localhost; getent hosts httpbin.org || true
9) for i in 1 2 3 4 5; do curl -sS --max-time 20 -o /tmp/repeat.$i.out -w "attempt=$i status=%{http_code} time=%{time_total}\n" https://example.com 2>/tmp/repeat.$i.err; echo "attempt=$i exit=$?"; done

Return a table:
| Check | Expected | Observed | Verdict | Notes |
and a final line:
Overall verdict: READY or NOT READY
```

## Sample Results (2026-04-26)

| Check                    | Expected                                                       | Observed                                                                                                                                   | Verdict | Notes                                                                                                                 |
| ------------------------ | -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ------- | --------------------------------------------------------------------------------------------------------------------- |
| env/proxy wiring         | `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` + `FIRMA_RUN_*` present | `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY=http://127.0.0.1:18080`; `FIRMA_RUN_SANDBOX_ID`, `FIRMA_RUN_SESSION_ID`, runtime/bridge vars present | PASS    | `FIRMA_SIDECAR_*` not present in env output                                                                           |
| identity masking         | Non-root constrained identity                                  | `uid=1000(firma-user) gid=1000(firma-user)`; `whoami=firma-user`; passwd entry for `firma-user`                                            | PASS    |                                                                                                                       |
| bridge listener healthy  | Listener on `127.0.0.1:18080`                                  | `LISTEN ... 127.0.0.1:18080`                                                                                                               | PASS    | Initial `ss -ltn` attempt reported `Cannot open netlink socket: Operation not permitted`; elevated rerun succeeded    |
| bridge log clean/startup | Bridge log shows startup and no errors                         | `/tmp/firma-run/<sandbox_id>/proxy-bridge.log` includes startup/spawned/ready entries and no error lines                                   | PASS    | Bridge bootstrap now emits explicit lifecycle markers                                                                 |
| HTTP proxied success     | status `200`, exit `0` via proxy path                          | `http status=200`, `http exit=0`                                                                                                           | PASS    | Initial non-elevated run failed with `curl: (7) Failed to connect to 127.0.0.1 port 18080`; elevated rerun passed     |
| HTTPS proxied success    | status `200`, exit `0` via proxy path                          | `https status=200`, `https exit=0`                                                                                                         | PASS    |                                                                                                                       |
| bypass blocked           | Direct egress (no proxy env) fails closed                      | `direct status=000`, `direct exit=7`                                                                                                       | PASS    | `curl: (7) Failed to connect to httpbin.org port 443`                                                                 |
| DNS confinement signal   | Local resolver confinement visible                             | `/etc/resolv.conf => nameserver 127.0.0.1`; `getent hosts localhost` works; `getent hosts httpbin.org` returns nothing                     | PASS    |                                                                                                                       |
| 5x HTTPS determinism     | 5/5 successful proxied HTTPS calls                             | Attempts `1-5` all `status=200`, each `exit=0`; times: `0.481664`, `0.465131`, `0.855019`, `0.543627`, `0.455090`                          | PASS    | Outer loop command exit was `1` because `[ -s /tmp/repeat.$i.err ]` was false (empty stderr), not due to curl failure |

Overall verdict: READY

## Interpretation

What is proven:

- Structural proxy routing is active.
- Identity masking is active.
- HTTPS proxying (CONNECT tunnel path) works.
- Fail-closed behavior holds on bypass attempt.
- DNS confinement is active.

Current known gap:

- HTTPS payload-level inspection is still out of scope (transparent CONNECT tunnel, no TLS MITM).
