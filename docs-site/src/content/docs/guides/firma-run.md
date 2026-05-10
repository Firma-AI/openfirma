---
title: Wrap an agent with firma run
description: Use the runtime wrapper so an agent's traffic must go through the Sidecar — even traffic the agent doesn't intend to route there.
---

`firma run` launches an agent inside an OS-level sandbox where every outbound call is forced through the Sidecar. Setting `HTTP_PROXY` is a hint; `firma run` is a constraint. This guide shows you how to use it, and when you should reach for it instead of plain proxy env vars.

You should already have a Sidecar running with a capability for some agent identity (see [Run the sidecar standalone](../run-the-sidecar/) and [Issue capability tokens](../issue-capability-tokens/)).

## When `firma run` is the right tool

Reach for `firma run` when one or more of these is true:

- The agent is third-party code or runs prompts you don't fully control (most LLM agents).
- You want a hard guarantee that nothing escapes the policy boundary.
- The agent might spawn child processes that don't inherit env vars.
- You're shipping a managed runtime to others and want enforcement to be part of the product.

For development work, a Sidecar you wrote, or a CI script you trust, plain proxy env vars are fine. For everything else, `firma run` is the answer.

For the conceptual background, read [The sandbox boundary](../../concepts/sandbox/).

## Step 1: Pick a backend

`firma run` uses a different sandbox backend per platform. The defaults are usually right:

| Platform | Default backend | Notes                                         |
| -------- | --------------- | --------------------------------------------- |
| Linux    | `bwrap`         | Requires unprivileged user namespaces enabled |
| macOS    | `vz`            | Native Apple Virtualization framework         |
| Windows  | `wsl2`          | Linux guest under WSL2                        |

Verify the platform default works on your host. On Linux:

```bash
unshare --user --pid echo ok
```

If this prints `ok`, bwrap will work. If it prints a permission error, you need to enable unprivileged user namespaces (`sysctl -w kernel.unprivileged_userns_clone=1` on some distros) or pick a different backend.

## Step 2: Use the bundled local example as a starting point

The repo ships a complete local-dev setup under `examples/firma-run/local/`. From the repo root:

```bash
examples/firma-run/local/setup.sh
```

This creates a `.local/` directory with:

- `.local/firma_sidecar.local.toml` — a working Sidecar config.
- `.local/mapping-rules.toml` — a starter mapping (one stub rule).
- `.local/audit-key.pem` — a freshly generated audit signing key.

The setup script is idempotent — re-running it leaves existing files alone. Inspect the generated config:

```bash
cat .local/firma_sidecar.local.toml
```

You'll see `[mapping].default_protected = false` and a `file` audit sink. For a real workload, you'd switch to `default_protected = true` and tighten the mapping. For first-touch, leave it as is.

## Step 3: Start the Sidecar

In a dedicated terminal:

```bash
cargo run --release -p firma -- sidecar -c .local/firma_sidecar.local.toml
```

Wait for the `sidecar ready` line.

## Step 4: Run a command under `firma run`

The simplest invocation:

```bash
cargo run --release -p firma -- run --profile generic -- curl https://example.com
```

Everything after `--` is the command and its arguments. `firma run`:

1. Resolves the `generic` profile.
2. Builds a sandbox using the platform default backend.
3. Starts the in-sandbox proxy bridge listening on `127.0.0.1:18080`.
4. Sets `HTTP_PROXY=http://127.0.0.1:18080` (and the HTTPS variant).
5. Launches `curl https://example.com` inside the sandbox under a sandbox identity.

The Sidecar receives the curl's request, runs it through the pipeline, and either dispatches or denies. The `curl` invocation never sees a token; it just talks to the proxy.

## Step 5: Use the right capability

For Stage 1 to allow the call, the Sidecar must have a capability matching `(session_id, action_class, resource)`. Two options:

**Pre-staged capability seed.** Issue a capability once with `firma authority issue --output .local/capability-<agent>.toml` and reference it in `[capability_seed].paths` in the Sidecar config. Right for a long-lived dev workflow.

**Per-run capability.** Pass `--capability-file` to `firma run`. The wrapper writes the file to a host-side path the Sidecar reads. Right for one-off invocations.

```bash
firma authority -c .local/authority.toml issue \
  --agent-id local-dev \
  --session-id $(uuidgen) \
  --action communication.external.send \
  --output .local/capability-local-dev.toml

cargo run --release -p firma -- run \
  --profile generic \
  --capability-file .local/capability-local-dev.toml \
  -- curl https://example.com
```

## Step 6: Inspect the effective config

Before you trust a `firma run` invocation in production, see what it's actually going to do:

```bash
firma run --profile generic --print-effective-config -- echo hi
```

This prints the resolved profile as JSON: which backend, which env vars are injected, which mounts are visible inside the sandbox, which identity remap applies. No agent is launched. Use this to audit your wrapper config the same way you'd `terraform plan` infrastructure.

## Useful flags

`firma run --help` is the full reference. The flags that come up most often:

| Flag                                | Effect                                                                                              |
| ----------------------------------- | --------------------------------------------------------------------------------------------------- |
| `--profile <name>`                  | Pick a runtime profile. `generic` is the default; `codex` adds workspace mounts for coding agents.  |
| `--config <file>`                   | Override profile defaults from a TOML/YAML file.                                                    |
| `--backend <bwrap\|vz\|wsl2\|firecracker>` | Override the platform default backend.                                                       |
| `--sidecar-endpoint <url>`          | Point at a Sidecar at a non-default address (e.g. UDS path or a different port).                    |
| `--capability-file <path>`          | Pre-staged capability seed for this run.                                                            |
| `--identity-mode <sandbox-user\|host-user>` | Choose whether the sandboxed process runs as the host user or a remapped sandbox user.        |
| `--print-effective-config`          | Print resolved config and exit. No agent launched.                                                  |

## What does and does not pass through

Inside the sandbox, the agent sees:

- A loopback interface where only `127.0.0.1:18080` is reachable.
- A DNS stub that answers only the hostnames the Sidecar is configured to route.
- `HTTP_PROXY` and `HTTPS_PROXY` set to the proxy bridge.
- Whatever filesystem the profile mounts (the `generic` profile mounts very little; `codex` mounts a workspace).

It does *not* see:

- The capability token (handled host-side; the agent never holds it).
- Host environment variables (the sandbox starts with a stripped env).
- Host filesystem outside profile-mounted paths.

This means an agent under `firma run` cannot:

- Open a raw TCP socket to anything but the proxy bridge.
- Resolve and connect to `8.8.8.8:53` to do its own DNS.
- Spawn a child that bypasses `HTTP_PROXY` (the network namespace forecloses on this regardless).
- Read host files containing secrets.

What it *can* still do is whatever its capability + policy allow it to do *via* the Sidecar. The sandbox is plumbing; the policy is what decides.

## Common gotchas

**`bwrap: setting up uid map: Permission denied`.** Unprivileged user namespaces are disabled on your kernel. Either enable them or use `--backend firecracker` if available.

**`firma run` exits immediately with no output.** Almost always a startup failure in the bridge. Run with `--print-effective-config` to verify the config first, then `RUST_LOG=debug firma run …` to see the bridge logs.

**The agent sees `HTTP_PROXY` but its calls still fail with DNS errors.** The DNS stub only answers hosts the Sidecar will route. If your mapping rules don't cover the host, the stub returns NXDOMAIN. Add the host to the mapping (and a permitting rule to the policy).

**Tight loops produce `CapabilityScopeMismatch`.** A coding agent doing one task per second can blow through `action_count` faster than expected. If your policy gates on `action_count`, raise the threshold or scope the rule more narrowly.

## What's next

- [Secure a local coding agent](../secure-a-coding-agent/) — putting `firma run` to work for Claude Code / Codex / Cursor.
- [Concepts: The sandbox boundary](../../concepts/sandbox/) — for the architectural reasoning.
- [Read & verify the audit log](../audit-log/) — observe what the wrapped agent actually does.
