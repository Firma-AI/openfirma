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

| Platform | Default backend | Notes                                                                |
| -------- | --------------- | -------------------------------------------------------------------- |
| Linux    | `bwrap`         | Requires unprivileged user namespaces + AppArmor allowance for bwrap |
| macOS    | `vz`            | Native Apple Virtualization framework                                |
| Windows  | `wsl2`          | Linux guest under WSL2                                               |

Verify the platform default works on your host. On Linux, the bwrap backend
needs two things: unprivileged user namespaces enabled, and — on AppArmor
distros — permission for bwrap to keep `CAP_NET_ADMIN` inside the namespace
so it can bring up loopback.

```bash
unshare --user --pid echo ok                # user namespaces
bwrap --unshare-net --bind / / true         # bwrap + net namespace
```

If the first command prints `ok` but the second exits with `bwrap: loopback:
Failed RTM_NEWADDR: Operation not permitted`, you're on a distro with
AppArmor restricting unprivileged user namespaces (Ubuntu 24.04 ships this
on by default). See [Common gotchas](#common-gotchas) below for the fix.

If `unshare --user --pid echo ok` itself fails with a permission error,
enable unprivileged user namespaces (`sysctl -w kernel.unprivileged_userns_clone=1`
on some distros) or pick a different backend.

## Step 2: Use the bundled local example as a starting point

The repo ships a complete local-dev setup under `examples/firma-run/local/`. From the repo root:

```bash
examples/firma-run/local/setup.sh
```

This creates a `.local/` directory with:

- `.local/firma.toml` — a working sectioned Sidecar config.
- `.local/mapping-rules.toml` — a starter mapping (one stub rule).
- `.local/audit-key.pem` — a freshly generated audit signing key.

The setup script is idempotent — re-running it leaves existing files alone. Inspect the generated config:

```bash
cat .local/firma.toml
```

You'll see `[sidecar.mapping].default_protected = false` and a `file` audit sink. For a real workload, you'd switch to `default_protected = true` and tighten the mapping. For first-touch, leave it as is.

## Step 3: Start the Sidecar

In a dedicated terminal:

```bash
cargo run --release -p firma -- sidecar -c .local/firma.toml
```

Wait for the `sidecar ready` line.

### Or: let `firma run` autostart it

You can skip the explicit Sidecar terminal entirely. When `firma run` is invoked and the configured Sidecar endpoint is unreachable, it autostarts a Sidecar as a child of the wrapper, waits for the seven-line ready log contract, and tears it down on exit. Marker files land under `$XDG_RUNTIME_DIR/firma/run/<sandbox_id>/` (Linux) or `/tmp/firma-$UID/firma/run/<sandbox_id>/` (macOS fallback). The spawned Sidecar inherits a config template from `--sidecar-config`, then `FIRMA_SIDECAR_CONFIG_FILE`, then the discovered `firma.toml`, then a synthesized minimal config — in that order — with the `[sidecar.interceptor]` section forced to `unix_socket` mode against the marker socket.

Opt out for production or CI:

- `--no-autostart` — fail with a typed `SidecarUnreachable` error instead of spawning a child Sidecar.
- `--sidecar=external` — same intent, more explicit; pairs with a systemd-managed or `firma stack start` Sidecar.

Autostart currently requires Unix. On Windows, use `--sidecar=external` with a pre-started Sidecar.

### Authority bootstrap

Before the Sidecar fires, `firma run` resolves which Authority to use.
Precedence: `--authority local` / `--authority <url>` > persisted
`[authority]` table in the discovered `firma.toml`
(`~/.config/firma/firma.toml` on Linux/macOS,
`%USERPROFILE%\.firma\firma.toml` on Windows) > a one-time y/N prompt when
both are empty and stdin is a TTY:

```text
No Authority is configured for this project.
firma run can start a local Mini Authority for development on [::1]:50051.
This is suitable for a single developer on a trusted workstation.

Start a local Mini Authority? [y/N]:
```

On `y` the choice is persisted and a per-run Mini Authority is spawned
with an ephemeral signing key plus the embedded `developer` policy
profile (a deny-all baseline). On `n`, no-TTY, or `--no-autostart`,
`firma run` exits with a typed error (`AuthorityDeclined`,
`AuthorityPromptNoTty`, or `MissingAuthority`). The spawned Authority is
killed on `firma run` exit.

Flags:

- `--authority local` — autostart a local Mini Authority on
  `[::1]:50051`; bypasses the prompt.
- `--authority <url>` — point at a remote Authority; bypasses the
  prompt; fails with `AuthorityUnreachable` if the URL does not answer.
- `--authority-profile <name>` — profile materialised by the
  autostarted Mini Authority. Today only `developer` ships. Ignored
  when the Authority is remote or already reachable.

`--no-autostart --authority local` is a typed argument-conflict error.

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

**Pre-staged capability seed.** Issue a capability once with `firma authority issue --output .local/capability-<agent>.toml` and reference it in `[sidecar.capability_seed].paths` in `firma.toml`. Right for a long-lived dev workflow.

**Per-run capability.** Pass `--capability-file` to `firma run`. The wrapper writes the file to a host-side path the Sidecar reads. Right for one-off invocations.

```bash
firma authority -c .local/firma.toml issue \
  --agent-id local-dev \
  --session-id $(uuidgen) \
  --action communication.external.send \
  --output .local/capability-local-dev.toml

# Note: the setup.sh-generated .local/firma.toml is sidecar-only (no
# [authority] section). To run `firma authority`, add an [authority]
# section to .local/firma.toml first, or point -c at a file that has one.

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

| Flag                                        | Effect                                                                                                                 |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `--profile <name>`                          | Pick a runtime profile. `generic` is the default; `codex` adds workspace mounts for coding agents.                     |
| `--config <file>`                           | Override profile defaults from a TOML/YAML file.                                                                       |
| `--backend <bwrap\|vz\|wsl2\|firecracker>`  | Override the platform default backend.                                                                                 |
| `--sidecar-endpoint <url>`                  | Point at a Sidecar at a non-default address (e.g. UDS path or a different port).                                       |
| `--sidecar <auto\|external>`                | `auto` (default) autostarts a per-run Sidecar when the endpoint is unreachable; `external` requires a pre-running one. |
| `--no-autostart`                            | Fail loudly if the Sidecar is unreachable, instead of autostarting. CI / production safety net.                        |
| `--sidecar-config <path>`                   | Sidecar TOML template for autostart. Falls back to `FIRMA_SIDECAR_CONFIG_FILE`, then the discovered `firma.toml`.      |
| `--sidecar-startup-timeout-secs <n>`        | Maximum wait for the autostarted Sidecar's `ready` line (default `10`).                                                |
| `--capability-file <path>`                  | Pre-staged capability seed for this run.                                                                               |
| `--identity-mode <sandbox-user\|host-user>` | Choose whether the sandboxed process runs as the host user or a remapped sandbox user.                                 |
| `--print-effective-config`                  | Print resolved config and exit. No agent launched.                                                                     |

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

**`bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`.** Hits on Ubuntu 24.04 and other distros that ship `kernel.apparmor_restrict_unprivileged_userns=1`. When bwrap enters its unprivileged user namespace, AppArmor transitions it to the `unprivileged_userns` profile, which `audit deny capability` — stripping `CAP_NET_ADMIN`. bwrap then can't add `127.0.0.1/8` to `lo` inside the new netns, and `--unshare-net` fails. Confirm with `sysctl kernel.apparmor_restrict_unprivileged_userns` (expect `1`) and `bwrap --unshare-net --bind / / true` (reproduces the error in isolation). Pick one of:

- **Targeted (recommended):** install an AppArmor profile that lets bwrap keep its caps inside the userns. Create `/etc/apparmor.d/bwrap`:

  ```
  abi <abi/4.0>,
  include <tunables/global>

  profile bwrap /usr/bin/bwrap flags=(unconfined) {
      userns,
      include if exists <local/bwrap>
  }
  ```

  Then `sudo apparmor_parser -r /etc/apparmor.d/bwrap`. This carves out bwrap specifically; other unprivileged-userns users on the host remain restricted.

- **Dev-host shortcut:** turn the restriction off globally. `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` (persist with a drop-in under `/etc/sysctl.d/`). Fine for a single-user dev VM; do not do this on shared or production hosts — any user can then create unprivileged user namespaces with full caps.

- **Sidestep bwrap:** use `--backend firecracker` if it's available in your setup. The VM backends don't depend on host AppArmor for namespace setup.

**`firma run` exits immediately with no output.** Almost always a startup failure in the bridge. Run with `--print-effective-config` to verify the config first, then `RUST_LOG=debug firma run …` to see the bridge logs.

**The agent sees `HTTP_PROXY` but its calls still fail with DNS errors.** The DNS stub only answers hosts the Sidecar will route. If your mapping rules don't cover the host, the stub returns NXDOMAIN. Add the host to the mapping (and a permitting rule to the policy).

**Tight loops produce `CapabilityScopeMismatch`.** A coding agent doing one task per second can blow through `action_count` faster than expected. If your policy gates on `action_count`, raise the threshold or scope the rule more narrowly.

## What's next

- [Secure a local coding agent](../secure-a-coding-agent/) — putting `firma run` to work for Claude Code / Codex / Cursor.
- [Concepts: The sandbox boundary](../../concepts/sandbox/) — for the architectural reasoning.
- [Read & verify the audit log](../audit-log/) — observe what the wrapped agent actually does.
