# Local Testing Guide

This guide shows how to test `firma run` locally without committing local secrets/config.

For agent-specific strict-mode setups (separate Codex and Claude samples),
see:

- `examples/firma-run/local/docs/codex-claude-local-setup.md`
- `examples/firma-run/local/docs/ready-to-work-setup.md` (quick onboarding cookbook)

Verification reference:

- `examples/firma-run/local/docs/verification-report.md` contains a full reproducible checklist and an example PASS/FAIL matrix from a successful run.

Latest verification snapshot (2026-04-26):

| Check                    | Expected                                                       | Observed                                                                                                                                   | Verdict | Notes                                                                                                                 |
| ------------------------ | -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ------- | --------------------------------------------------------------------------------------------------------------------- |
| env/proxy wiring         | `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` + `FIRMA_RUN_*` present | `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY=http://127.0.0.1:18080`; `FIRMA_RUN_SANDBOX_ID`, `FIRMA_RUN_SESSION_ID`, runtime/bridge vars present | PASS    | `FIRMA_SIDECAR_*` not present in env output                                                                           |
| identity masking         | Non-root constrained identity                                  | `uid=1000(firma-user) gid=1000(firma-user)`; `whoami=firma-user`; passwd entry for `firma-user`                                            | PASS    |                                                                                                                       |
| bridge listener healthy  | Listener on `127.0.0.1:18080`                                  | `LISTEN ... 127.0.0.1:18080`                                                                                                               | PASS    | Initial `ss -ltn` attempt reported `Cannot open netlink socket: Operation not permitted`; elevated rerun succeeded    |
| bridge log clean/startup | Bridge log shows startup and no errors                         | `/tmp/firma-run/<sandbox_id>/proxy-bridge.log` exists and includes startup/ready entries                                                   | PASS    | If entries are missing, inspect `bwrap_entrypoint.sh` bridge bootstrap path                                           |
| HTTP proxied success     | status `200`, exit `0` via proxy path                          | `http status=200`, `http exit=0`                                                                                                           | PASS    |                                                                                                                       |
| HTTPS proxied success    | status `200`, exit `0` via proxy path                          | `https status=200`, `https exit=0`                                                                                                         | PASS    |                                                                                                                       |
| bypass blocked           | Direct egress (no proxy env) fails closed                      | `direct status=000`, `direct exit=7`                                                                                                       | PASS    | `curl: (7) Failed to connect to httpbin.org port 443`                                                                 |
| DNS confinement signal   | Local resolver confinement visible                             | `/etc/resolv.conf => nameserver 127.0.0.1`; `getent hosts localhost` works; `getent hosts httpbin.org` returns nothing                     | PASS    |                                                                                                                       |
| 5x HTTPS determinism     | 5/5 successful proxied HTTPS calls                             | Attempts `1-5` all `status=200`, each `exit=0`; times: `0.481664`, `0.465131`, `0.855019`, `0.543627`, `0.455090`                          | PASS    | Outer loop command exit was `1` because `[ -s /tmp/repeat.$i.err ]` was false (empty stderr), not due to curl failure |

Overall verdict: READY

## Why this guide

`firma run` local testing needs a sidecar config, mapping rules, and an audit signing key. Those are machine-local artifacts and should not be committed.

The repo now reserves `/.local/` for this purpose and ignores it in git.

## One-time bootstrap

From repo root:

```bash
examples/firma-run/local/setup.sh
```

Optional diagnostics/observability bootstrap (stricter guard defaults, richer MITM visibility for key agent hosts):

```bash
examples/firma-run/local/setup.sh --observability
```

PowerShell (Windows only):

```powershell
pwsh ./examples/firma-run/local/setup.ps1
```

PowerShell observability mode:

```powershell
pwsh ./examples/firma-run/local/setup.ps1 --observability
```

The script creates:

- `.local/mapping-rules.toml`
- `.local/firma.toml`
- `.local/audit-key.pem`

Templates used:

- `examples/firma-run/local/assets/mapping-rules.local.example.toml`
- `examples/firma-run/local/assets/firma.local.example.toml`
- `examples/firma-run/local/assets/firma.local.observability.example.toml` (opt-in diagnostics profile)

## Environment Variables

`firma run` supports the following environment variables to customize addresses and avoid port conflicts:

- `FIRMA_SIDECAR_ENDPOINT`: Sidecar endpoint (default: `tcp://127.0.0.1:8080`)
- `FIRMA_PROXY_LISTEN_ADDR`: Proxy bridge listen address (default: `127.0.0.1:18080`)
- `FIRMA_SIDECAR_CA_CERT_PATH`: Explicit path to sidecar MITM CA cert (preferred override)
- `FIRMA_SIDECAR_CA_DIR`: Directory containing `firma-ca.crt` (fallback override)
- `FIRMA_RUN_SESSION_ID`: Optional stable session id override (useful when capability tokens are session-bound)
- `FIRMA_RUN_SANDBOX_ID`: Reserved for Firma to propagate its generated UUIDv7
  identity to child processes. Unset it before invoking `firma run`.
- `FIRMA_RUN_REQUIRE_SESSION_ID`: If `true|1|yes|on`, `firma run` fails fast unless `FIRMA_RUN_SESSION_ID` is set

Discover the generated sandbox ID with `firma sidecar status --json`, from the
run marker's `metadata.toml`, or from the `sandbox_id` field in audit events.

Example:

```bash
export FIRMA_SIDECAR_ENDPOINT=tcp://127.0.0.1:9090
export FIRMA_PROXY_LISTEN_ADDR=127.0.0.1:18181
cargo run -p firma -- run -- "your command"
```

Strict capability workflow (session-bound tokens, legacy operator path):

```bash
export FIRMA_RUN_SESSION_ID=demo-session
export FIRMA_RUN_REQUIRE_SESSION_ID=true
cargo run -p firma -- run --profile codex -- codex
```

This prevents late `TokenInvalid` denials caused by runtime-generated session
ids drifting from pre-issued capability seed session ids. In the automatic
`firma run` mint flow, `FIRMA_RUN_SESSION_ID` is still honoured and passed to
the Authority as the session id for the live-minted capability.

When a sidecar MITM CA certificate is detected, `firma run` automatically exports trust env vars for common runtimes:

- `FIRMA_SIDECAR_CA_CERT_PATH`
- `REQUESTS_CA_BUNDLE`
- `SSL_CERT_FILE`
- `CURL_CA_BUNDLE`
- `NODE_EXTRA_CA_CERTS`
- `GIT_SSL_CAINFO`

This prevents `UnknownCA` failures for managed HTTPS MITM targets.

## Run sidecar + codex

Terminal A:

```bash
cargo run -p firma -- sidecar -c .local/firma.toml
```

When sidecar starts in `http_proxy` mode, it now prints an explicit routing
hint. If you run clients outside `firma run`, ensure proxy env vars point to
the sidecar listener (`127.0.0.1:8080` by default).

Terminal B:

```bash
cargo run -p firma -- run --profile codex -- codex
```

Startup should include:

- `applied executable wrapper defaults for governed execution`

If that line is missing, the session may not be running with codex wrapper-default
governance arguments.

Codex wrapper-default policy (now default for `--profile codex`):

- `--sandbox workspace-write`
- `--ask-for-approval never`
- `--config sandbox_workspace_write.network_access=true`

This keeps tool-initiated commands inside the governed sandbox path by default
instead of escalating outside.

Override example (`firma.toml`):

```toml
[run.profiles.codex.executable_policies.codex]
enforce_wrapper_defaults = true
sandbox_mode = "workspace-write"
approval_policy = "never"

[run.profiles.codex.executable_policies.codex.config_overrides]
"sandbox_workspace_write.network_access" = "true"
```

Disable wrapper argument injection for codex (if needed):

```toml
[run.profiles.codex.executable_policies.codex]
enforce_wrapper_defaults = false
```

PowerShell helper wrapper:

```powershell
pwsh ./examples/firma-run/local/run.ps1 -- codex
```

Capability token renewal helper — **legacy operator path** (pre-provisioned seed
tokens; superseded by automatic `firma run` mint):

```bash
examples/firma-run/local/renew-capability.sh --session-id "$FIRMA_RUN_SESSION_ID"
```

PowerShell:

```powershell
pwsh ./examples/firma-run/local/renew-capability.ps1 -SessionId $env:FIRMA_RUN_SESSION_ID
```

Identity default:

- `firma run` defaults to sandbox identity masking mode (`sandbox_user`).
- Inside the sandbox, username/group labels are presented as `firma-user` while preserving host UID/GID compatibility for mounted workspace writes.

Compatibility override:

```bash
cargo run -p firma -- run --profile codex --preserve-host-user -- codex
```

Config override (`firma.toml`):

```toml
[run.profiles.codex]
identity_mode = "host_user"
```

Backend defaults by host OS:

- Linux: `bwrap`
- macOS: `vz`
- Windows: `wsl2`

Network-confinement defaults are backend-aware:

- `bwrap`: `enforce_network_namespace=true` (structural confinement path)
- `vz`/`wsl2`: `enforce_network_namespace=false` (proxy-mediated path)

`claude-code` profile platform posture:

- Linux + `bwrap`: full structural confinement target.
- macOS (`vz`): anticipated support path now includes `sandbox-exec` profile
  deny rules for common sensitive paths and runtime-home isolation; guarantees
  remain weaker than Linux `bwrap` structural confinement.
- Windows (`wsl2`): compatibility mode (same policy/audit path, reduced
  confinement guarantees compared to Linux `bwrap`).

If you explicitly set `enforce_network_namespace=true` with a non-`bwrap`
backend, `firma run` now fails at config validation with a clear error.

Built-in runtime profiles:

- `generic` (default)
- `codex`
- `claude-code`

Managed seccomp layer (Linux `bwrap`):

`firma-run` can compile managed policy input into seccomp cBPF and pass the
generated filter to `bwrap` (`--seccomp`) for additional syscall restriction.

Example:

```toml
[profiles.claude-code]
backend = "bwrap"

[profiles.claude-code.seccomp_policy]
source_policy_path = "/absolute/path/to/policy.toml"
artifact_dir = "/absolute/path/to/seccomp-artifacts"
verify_checksum = true
```

Notes:

- `seccomp_policy` is supported only with backend `bwrap`.
- policy and artifact paths must be absolute.
- generated artifact format must match `bwrap --seccomp` expectations (compiled cBPF).

Manual backend override example:

```bash
cargo run -p firma -- run --backend vz --profile codex -- codex
```

## Run the local E2E harness

```bash
examples/firma-run/e2e/run.sh
```

Note: `examples/firma-run/e2e/run.sh` is Linux-only by design because it validates
the structural `bwrap` confinement path.

HTTPS CONNECT scenario:

```bash
examples/firma-run/e2e/run.sh --https-check
```

Claude-code profile smoke:

```bash
examples/firma-run/e2e/run.sh --profile claude-code
```

Claude-code shell acceptance suite (Linux-only, unified harness):

```bash
examples/firma-run/e2e/run.sh --claude-acceptance
```

This suite currently validates:

- shell-originated network attempts are intercepted and denied when policy is protected-by-default,
- child-process shellouts (`wget`) are intercepted under the same path,
- `claude-code` profile filesystem hardening blocks writes outside the working directory,
- masked sensitive paths (for example `~/.ssh`) are not readable inside sandbox.

Custom command example:

```bash
examples/firma-run/e2e/run.sh --cmd 'cd examples/agents/agents_sdk_py && curl -fsS --max-time 20 http://httpbin.org/get -o /dev/null'
```

Keep artifacts:

```bash
examples/firma-run/e2e/run.sh --keep-artifacts
```

## Preflight checks

Bash:

```bash
examples/firma-run/local/preflight.sh
```

PowerShell (macOS/Linux/Windows):
PowerShell (Windows only):

```powershell
pwsh ./examples/firma-run/local/preflight.ps1
```

## Git safety rules

- `/.local/` is ignored by git.
- `.env` is ignored by git.
- Keep real API keys only in local files or local shell env.

## HTTPS behavior (current)

Sidecar supports both HTTPS modes:

1. TLS MITM mode (default for configured `intercept_hosts`): sidecar decrypts,
   normalizes, and enforces HTTPS requests at L7 (method/path/action class).
2. CONNECT tunnel mode (fallback for hosts outside `intercept_hosts` or explicit
   `bypass_hosts`): sidecar enforces/audits on `host:port`.

Important operational note:

- MITM requires agent trust for the sidecar CA (`firma-ca.crt`); if trust is
  not propagated into the runtime, TLS clients will fail handshake by design.
- For hosts in `strict_hosts`, MITM failures are fail-closed (no direct egress).

If proxied calls fail with `Failed to connect to 127.0.0.1:18080`, inspect bridge startup diagnostics:

```bash
ls -la /tmp/firma-run/<sandbox_id>/
sed -n '1,200p' /tmp/firma-run/<sandbox_id>/proxy-bridge.log
```

Bridge liveness is now fail-closed during runtime:

- if the sandbox-local proxy bridge exits unexpectedly after startup,
  `firma run` terminates the wrapped agent process and prints a clear
  fail-closed error instead of continuing with a degraded session.

If DNS confinement behaves unexpectedly, inspect the sandbox-local DNS stub:

```bash
sed -n '1,200p' /tmp/firma-run/<sandbox_id>/dns-stub.log
```

If commands fail with `Failed to connect to 127.0.0.1:18080`:

- inspect `/tmp/firma-run/<sandbox_id>/proxy-bridge.log`,
- recent bridge diagnostics now include an explicit pre-sidecar mediation hint
  when the bridge cannot reach the host-side sidecar adapter.

If sidecar shows no request logs for a failed command:

- failure likely happened before sidecar mediation (for example command executed
  outside `firma run`, missing proxy env in that process, or local bridge path issue),
- sidecar can only log traffic that actually reaches its listener.

In structural `bwrap` mode, `/etc/resolv.conf` points at `127.0.0.1`.
The V1 DNS path intentionally refuses direct resolver queries when the stub can
bind port 53. In unprivileged bwrap mode, low-port bind may fail; the wrapper
continues with the same localhost resolver fail-closed behavior. Proxied
HTTP/HTTPS traffic still carries hostnames through the sidecar path.

## CONNECT implementation note

Why this exists:

1. Pingora defaults to rejecting CONNECT with `405 Method Not Allowed` unless CONNECT proxying is explicitly enabled.
2. In E2E runs, enabling that switch still yielded `502 Bad Gateway` for real HTTPS CONNECT targets in our flow.

What was changed:

1. Sidecar now handles CONNECT tunnel lifecycle explicitly in the HTTP interceptor runtime.
2. The handshake (`host:port`) is still enforced and audited before tunnel establishment.
3. Optional TLS MITM interception is available for configured hosts.
