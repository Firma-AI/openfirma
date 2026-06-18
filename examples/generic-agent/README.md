# Generic agent — baseline policy bundle

Reference Cedar / mapping / sidecar configuration for running a generic
LLM agent (Claude Code or comparable) under Firma. Use as a starting
template; copy and narrow per deployment profile.

## Run

```bash
# Interactive mode — starts stack, prints smoke-test commands, waits for Ctrl+C.
bash examples/generic-agent/run.sh

# Agent mode — wraps <command> with firma run (Layer 3 bwrap + L1/L4 policy).
bash examples/generic-agent/run.sh -- <command> [args...]
# e.g.
bash examples/generic-agent/run.sh -- claude --dangerously-skip-permissions
```

Builds `firma`, `firma-authority`, and `firma-sidecar`, generates keys on first
boot into `.runtime/`, starts both services, then either runs the agent inside
the sandbox or prints curl smoke-test commands.

## Layer coverage

| Layer                              | Mechanism                 | Status in this example                               |
| ---------------------------------- | ------------------------- | ---------------------------------------------------- |
| 1 — Network (host / IP allowlist)  | mapping rules + Cedar     | covered                                              |
| 2 — Command / syscall              | seccomp-unotify / ESF     | deferred (FIR-79)                                    |
| 3 — Filesystem                     | firma-run sandbox (bwrap) | covered via `[run.profiles.generic]` in `firma.toml` |
| 4 — Semantic (HTTP action classes) | Cedar policy bundle       | covered                                              |

Layer 3 and Layer 2 are enforced outside the sidecar. The Cedar policy
in `policies/llm-agent.cedar` does not duplicate filesystem path or
syscall rules — those belong to firma-run / bwrap / seccomp.

## Layer 3 — Filesystem sandbox (`[run.profiles.generic]` in `firma.toml`)

Linux-only. Backend: `bwrap`. Configured under `[run.profiles.generic]` in
`examples/generic-agent/firma.toml`.

| Access       | Paths                                                                                                                                                                                                                         |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Read + Write | Workspace directory. `run.sh` creates and launches from `examples/generic-agent/workspace/`. For direct `firma run` use, `cd` into your workspace first.                                                                      |
| Read only    | `/usr`, `/lib`, `/bin`, `/etc` (whole rootfs ro-bound — covers `/etc/sudoers`, `/etc/shadow`, `/etc/crontab`, `/etc/hosts`)                                                                                                   |
| No access    | `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.config/gcloud` (tmpfs mask on host `$HOME` + sandbox HOME redirected to per-run runtime dir)                                                                                              |
| No access    | `$HOST_HOME/.env` — masked via tmpfs (HOME redirection + explicit mask). `.env` files at arbitrary paths under the host rootfs remain readable via ro-bind; full pattern-deny needs a path-aware FS policy layer (follow-up). |
| No access    | Other users' home dirs (only the workspace path is bound RW; `/home/<other-user>` stays under the rootfs ro-bind)                                                                                                             |

The knobs the file sets are read by the bwrap backend
(`crates/firma-run/src/backend/linux_bwrap.rs`):

- `FIRMA_RUN_BWRAP_ROOTFS_MODE = "readonly"` — `--ro-bind /` + tmpfs on
  `/tmp`, `/var/tmp`.
- `FIRMA_RUN_BWRAP_RUNTIME_HOME = "false"` — when `"true"`, `HOME`,
  `XDG_CONFIG_HOME`, and `XDG_CACHE_HOME` all point at the per-run runtime
  dir (full home-dir isolation). Disabled by default so the agent retains
  its config (MCP servers, auth tokens, etc.) across runs. Set to `"true"`
  to restore isolation when home-dir confinement is required.
- `FIRMA_RUN_BWRAP_MASK_HOME_PATHS = ".ssh,.gnupg,.aws,.config/gcloud,.env"`
  — defense-in-depth tmpfs masks on the host home paths.

### Setting the workspace per project

Two options:

1. **`cd` into the project, then invoke `firma run`** (recommended). The
   generic profile auto-binds the launch cwd RW at the same path inside
   the sandbox. No edits required:

   ```bash
   cd /path/to/my-project
   firma run --profile generic \
     --config /path/to/openfirma/examples/generic-agent/firma.toml \
     -- <command>
   ```

2. **Pin an explicit absolute path** by uncommenting the
   `[[run.profiles.generic.mounts]]` block in `firma.toml` and editing
   both `source` and `target`. Adding any mount entry replaces the cwd
   default, so list every path the agent needs RW access to.

### Acceptance test

```bash
# Start the stack first (separate terminal).
bash examples/generic-agent/run.sh

# Then run the probes against it.
bash examples/generic-agent/verify-layer3.sh
```

Runs three probes through `firma run` against the stack started by `run.sh`:

| Probe                                | Expected                        |
| ------------------------------------ | ------------------------------- |
| sandbox `$HOME` != host `$HOME`      | preflight passes (bwrap active) |
| `echo ok > <workspace>/probe.txt`    | exit 0, file present (PASS)     |
| `echo bad >> ~/.ssh/authorized_keys` | exit non-zero (PASS — denied)   |

Exits 0 on PASS, non-zero on FAIL. Linux-only; requires `bwrap` and
`cargo`.

## Files

| File                               | Purpose                                                                                           |
| ---------------------------------- | ------------------------------------------------------------------------------------------------- |
| `firma.toml`                       | unified config — `[authority]`, `[sidecar.*]`, and `[run.profiles.*]` (Layer 3 bwrap profile)     |
| `policies/llm-agent.cedar`         | enforcement policy bundle streamed to the sidecar                                                 |
| `issuance-policies/issuance.cedar` | gates capability token issuance at the Authority                                                  |
| `mapping-rules.toml`               | supplemental host/method/path → action class rules (CONNECT tunnels, package managers, localhost) |
| `verify-layer3.sh`                 | filesystem sandbox acceptance test (workspace RW vs `~/.ssh` denied)                              |
| `run.sh`                           | startup script + curl smoke tests                                                                 |

The shipped provider mappings in `crates/firma-sidecar/config/mappings/`
(`github.toml`, `gmail.toml`) are merged on top — see
`firma.toml [sidecar.mapping] rules_paths`.

## Issuance vs enforcement

The Authority evaluates two distinct Cedar policy sets:

- **Issuance** (`issuance-policies/`) — controls whether the Authority
  will mint a capability token at all. Permissive in this template
  (`permit(principal, action, resource)`).
- **Enforcement** (`policies/`) — streamed to the sidecar and evaluated
  on every intercepted call. Narrow: hard-blocks on payment.\*,
  credential.write, code.destructive, account.permission.change,
  memory.cross_namespace.\*, repo.admin; permits read/write/merge code
  and communication.

The split lets operators issue broad tokens at session start while the
sidecar enforces fine-grained limits per call.

## Network rules (Layer 1)

Allowlist via `mapping-rules.toml`:

- `api.anthropic.com` (LLM, CONNECT-tunneled, no MITM)
- `api.github.com`, `gmail.googleapis.com` (MITM)
- `pypi.org`, `files.pythonhosted.org`, `crates.io`, `static.crates.io`,
  `registry.npmjs.org` (package registries)
- `localhost`, `127.0.0.1` (loopback — assumes trusted)

Defense-in-depth Cedar `forbid` on `169.254.169.254*` (cloud metadata).
Unmapped hosts are denied before Cedar by `default_protected = true`.

RFC-1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) cannot be
expressed as CIDR in Cedar. Enforce at the OS / network layer:

```bash
iptables -I OUTPUT -d 10.0.0.0/8     -j DROP
iptables -I OUTPUT -d 172.16.0.0/12  -j DROP
iptables -I OUTPUT -d 192.168.0.0/16 -j DROP
```

Or via `firma-run --unshare-net` plus an explicit allow-list.

## Semantic rules (Layer 4)

Hard-block (auto-deny in v0.1; HITL terminal flow planned):

- `payment.transfer`, `payment.purchase`, `payment.refund`,
  `payment.payout`, `browser.purchase`
- `account.permission.change`, `repo.admin`
- `credential.write`
- `code.destructive` (force-push, branch delete, file delete via API)
- `memory.cross_namespace.read`, `memory.cross_namespace.write`

Permit:

- `system.install` (host-restricted by mapping rules above)
- `credential.read`
- `code.read`, `code.review.read`, `issue.read`,
  `security.alert.read`, `notification.manage`
- `code.write`, `code.review.submit`, `issue.write`
- `code.merge`
- `communication.external.send`, `communication.internal.send`

`system.install` is currently auto-permit. The FIR-80 spec recommends
HITL gating; downgrade to `forbid` if running unattended.

## Smoke tests

The proxy expects `x-firma-session-id: preflight-session` on each
request to bind it to the preflight-issued capability token. The
`run.sh` output prints the exact curl invocations.

| Target                                    | Expected                 |
| ----------------------------------------- | ------------------------ |
| crates.io GET                             | 200                      |
| pypi.org GET                              | 200                      |
| api.github.com GET /repos/*               | 200                      |
| api.github.com DELETE /repos/_/git/refs/_ | 403 (`code.destructive`) |
| evil.com GET                              | 403 (unmapped)           |
| 169.254.169.254 GET                       | 403 (Cedar forbid)       |

## Pointing an agent at the proxy

```bash
export HTTP_PROXY=http://127.0.0.1:7474
export HTTPS_PROXY=http://127.0.0.1:7474
export REQUESTS_CA_BUNDLE=examples/generic-agent/.runtime/generated-firma-ca/firma-ca.crt
export SSL_CERT_FILE=$REQUESTS_CA_BUNDLE
export NODE_EXTRA_CA_CERTS=$REQUESTS_CA_BUNDLE
```

The agent must inject `x-firma-session-id: preflight-session` on every
outbound HTTP request. Long-term this header should default to the
preflight session_id when absent — tracked separately.

## NOT FOR PRODUCTION

The Mini Authority and this template are local-dev / testing only.
PASETO keys, audit signing keys, and the generated MITM CA all live in
`.runtime/` — copy nothing from here to production.
