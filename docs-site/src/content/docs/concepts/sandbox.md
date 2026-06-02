---
title: The sandbox boundary
description: How firma run contains agent egress, what structural vs proxy-only enforcement means, and what each backend protects against.
---

`firma run` wraps an agent in a sandbox, routes its outbound traffic through the Sidecar, and — on structural backends — *removes* the agent's ability to bypass that route. On macOS and WSL2, where OS-level network confinement is not yet available, enforcement is proxy-based: traffic is mediated only for cooperative HTTP clients that honor `HTTP_PROXY`. This distinction is the most important thing to understand before relying on `firma run` for security enforcement.

## The problem with proxy env vars alone

`HTTP_PROXY` is a hint, not a constraint. It works because most HTTP libraries respect it by convention. But:

- A library that doesn't respect proxy env vars (some Go binaries, some C libraries) bypasses it silently.
- An agent that opens raw TCP sockets bypasses it.
- An agent that spawns a child process with a clean environment bypasses it.
- Anything that reads `/etc/hosts`, makes its own DNS query, or talks UDP bypasses it.

For a cooperative agent on a developer laptop, none of this matters. For a less-trusted agent — anything you didn't write, anything running prompts you don't fully control, anything that could be compromised — the proxy hint is not a security boundary. It's a convention, and the agent can choose to ignore it.

## Structural vs proxy-only enforcement

`firma run` has two materially different enforcement modes:

**Structural confinement** (Linux `bwrap`, Linux `firecracker`): The sandbox removes the agent's ability to bypass the proxy at the OS level. The agent runs in a network namespace where the only reachable destination is the proxy bridge — raw sockets, DNS lookups, and child processes all dead-end inside the sandbox. No extra cooperation from the agent is required.

**Proxy-only / compatibility mode** (macOS `vz`, Windows/WSL2 `wsl2`): The agent runs in the host environment with `HTTP_PROXY` and related environment variables injected. Outbound mediation depends on the agent (or its HTTP library) respecting those variables. Raw sockets, proxy-env-unset children, and non-HTTP protocols can bypass the Sidecar.

This is not a preference — it is a current capability gap. Structural parity is tracked separately by **FIR-72**. The macOS strategy decision is documented in [macOS structural confinement strategy](../macos-structural-strategy/): VZ guest-based structural parity is the primary path, while ESF-native controls are treated as targeted hardening rather than a standalone structural network boundary.

To prevent false confidence, `firma run` **fails closed** when a non-structural backend is selected. You must explicitly opt in with `--allow-non-structural` (or set `run.allow_non_structural = true` in `firma.toml`) to acknowledge the limitations of proxy-only mode:

```bash
# macOS: must opt into proxy-only compatibility mode
firma run --profile generic --allow-non-structural -- curl https://example.com

# Or persist the opt-in in firma.toml:
# [run]
# allow_non_structural = true
```

Without the opt-in, `firma run` prints a typed error explaining that the selected backend provides proxy-only enforcement, and how to proceed.

## What `firma run` does

`firma run` wraps the agent's launch in a sandbox. The specific mechanisms depend on the backend:

### Structural backends (bwrap, firecracker)

1. **Network namespace.** The agent runs in a sandbox where the only reachable network destination is a host-side process listening on `127.0.0.1:18080` (the proxy bridge).
2. **Proxy bridge.** A small helper inside the sandbox listens on `127.0.0.1:18080` and forwards bytes over a Unix socket to the host's Sidecar (typically at `$XDG_RUNTIME_DIR/firma/sidecar.sock`). The agent's traffic has nowhere else to go.
3. **DNS stub.** A stub resolver inside the sandbox answers DNS queries deterministically — only hostnames the Sidecar will route receive answers. Random outbound DNS is impossible.
4. **`HTTP_PROXY` injection.** For agents that *do* respect proxy env vars, `firma run` sets `HTTP_PROXY=http://127.0.0.1:18080` so they don't need any code change.
5. **Identity remap.** The agent runs under a sandbox user (configurable via `--identity-mode`), so it can't read host secrets via filesystem.

The result is that an agent running under a structural `firma run` can attempt to bypass the proxy in any way it likes — open raw sockets, set its own DNS, fork a child process — and *every one of those attempts dead-ends inside the sandbox*. The only exit is through the Sidecar.

### Proxy-only backends (vz, wsl2)

1. **`HTTP_PROXY` injection.** `firma run` sets `HTTP_PROXY`, `HTTPS_PROXY`, and related environment variables pointing to the Sidecar. Agent processes that read these vars will route traffic through the Sidecar automatically.
2. **`NO_PROXY` clearing.** Built-in profiles clear `NO_PROXY` / `no_proxy` to prevent a host environment variable from silently routing traffic around the Sidecar.
3. **Sandbox-exec (macOS only).** On macOS, `sandbox-exec` provides filesystem-level confinement for the `claude-code` profile (blocking reads/writes to `~/.ssh`, `~/.aws`, etc.), but it does not provide mandatory network confinement.
4. **Require explicit opt-in.** `firma run` fails closed unless `--allow-non-structural` is passed, making the proxy-only status explicit and noisy.

For well-behaved agents — standard HTTP libraries, no raw socket use — proxy-only enforcement is effective in practice. For adversarial or minimally cooperative agents, only the structural backends provide a hard guarantee.

## The four backends

Network sandboxing primitives differ across OSes, so `firma run` selects a backend by platform:

| Backend       | Platform | Mechanism                                    | Enforcement    |
| ------------- | -------- | -------------------------------------------- | -------------- |
| `bwrap`       | Linux    | Unprivileged user namespaces (bubblewrap)    | Structural     |
| `firecracker` | Linux    | KVM micro-VM                                 | Structural     |
| `vz`          | macOS    | Host proxy bridge + HTTP proxy injection (`HTTP_PROXY`) | Proxy-only (default); structural via TrustedBSD MAC when `FIRMA_RUN_VZ_STRUCTURAL_NETWORK=1` (experimental) |
| `wsl2`        | Windows  | HTTP proxy injection (`HTTP_PROXY`)         | Proxy-only     |

You can override the platform default with `--backend`:

```bash
firma run --profile generic --backend firecracker -- python my_agent.py
```

The choice is mostly an operational one: bwrap is fast to start and lightweight; current `vz` and `wsl2` are compatibility options on their platforms; firecracker gives you a real micro-VM at the cost of slightly slower start time.

`firma run` cannot escalate privileges. On Linux it requires unprivileged user namespaces (which most modern distros enable by default). On WSL hosts, implicit backend selection uses the `wsl2` compatibility backend instead of attempting `bwrap`.

## Platform enforcement matrix

The *strength* of the enforcement boundary differs by platform. This is the most important thing to understand when deploying `firma run` in a security-sensitive context.

| Platform        | Backend        | Enforcement mechanism                          | `structural` | Agent bypass possible?            | Requires `--allow-non-structural` |
| --------------- | -------------- | ---------------------------------------------- | :----------: | --------------------------------- | --------------------------------- |
| Linux (native)  | `bwrap`        | Network namespace; proxy bridge is only exit   | Yes          | No                                | No                                |
| Linux (native)  | `firecracker`  | KVM micro-VM network isolation                 | Yes          | No                                | No                                |
| macOS `vz` (default) | `vz`    | Host proxy bridge + HTTP proxy injection       | No           | Yes, if agent ignores `HTTP_PROXY` | Yes                               |
| macOS `vz` (experimental) | `vz` | `sandbox-exec` with `deny network-outbound`; host bridge + DNS stub on loopback | Yes (experimental) | No for IP egress; loopback-all scope is residual caveat | No (once E2E verified) |
| Windows / WSL2  | `wsl2`         | HTTP proxy injection (`HTTP_PROXY`)            | No           | Yes, if agent ignores `HTTP_PROXY` | Yes                               |

**Structural** means the sandbox removes the agent's ability to bypass the proxy at the OS level — no extra cooperation from the agent is required. **Proxy-only** means enforcement depends on the agent (or its HTTP library) respecting `HTTP_PROXY`. On proxy-only backends, `firma run` fails closed unless you pass `--allow-non-structural` to acknowledge this limitation.

`NO_PROXY` / `no_proxy` are cleared in all built-in profiles to prevent a host-env override from silently routing traffic around the proxy Sidecar on macOS and WSL2.

## When Firma run logs "backend compatibility proof"

When `firma run` runs with a structural backend, it logs:

```
structural=true ... "backend network enforcement proof"
```

When running with a proxy-only backend (after `--allow-non-structural` opt-in), it logs a **warning** instead:

```
structural=false mode=proxy_only enforced=false ... "backend compatibility proof — proxy-only mode; agent egress is NOT mandatorily confined"
```

This distinction exists so that log scanners and monitoring tools cannot misinterpret proxy-only mode as mandatory network confinement.

## Profiles

A **profile** declares the runtime shape: env injection, sandbox identity, network policy, capability lease behavior. The shipped profiles are:

- **`generic`** — works for any agent. Sandboxed, proxy-routed, `HTTP_PROXY` set. The default.
- **`codex`** — tuned for code-generation agents (Claude Code, Codex, Cursor) that need filesystem access to a project directory. Allows mounting a workspace path.
- **`claude-code`** — tuned for Claude Code with home-directory path masking and `sandbox-exec` confinement on macOS.

Custom profiles live in TOML and you can pass them via `--config`. For most workloads, `generic` is correct and you should reach for a custom profile only when you've hit a limit.

The profile resolves at startup, before the sandbox is built. You can preview it without launching the agent:

```bash
firma run --profile generic --print-effective-config -- echo hi
```

This prints the resolved config as JSON so you can see exactly what mounts, env vars, and identity remaps will be applied.

## Capability handling

The preferred runtime shape keeps capability material outside the agent process:

1. **Before** the sandbox starts, the operator stages capability material for the Sidecar, normally through `[capability_seed]`.
2. The host-side Sidecar reads that seed outside the sandbox.
3. Inside the sandbox, the agent only needs `HTTP_PROXY=http://127.0.0.1:18080`.
4. When the agent makes an outbound call, the Sidecar selects the right capability based on `(session_id, action_class, resource)` — which it knows from the request, not from the agent.

That is the mode to use when token non-exposure is a security requirement. Current `firma run --capability-file` support is a compatibility path: the runtime reads the file and exports `FIRMA_CAPABILITY_TOKEN` / `FIRMA_CAPABILITY_FILE` into the wrapped process environment. Do not rely on token non-exposure in that mode. The long-term direction is to keep the agent's only superpower as "ask the Sidecar to do this thing"; the Sidecar decides whether the capability covers it.

## What the sandbox protects against

What `firma run` protects against depends on the enforcement mode. The lists below reflect this: structural backends provide hard guarantees; proxy-only backends provide best-effort mediation.

### Structural backends (bwrap, firecracker) protect against:

- An agent that intentionally tries to bypass the proxy with raw TCP / UDP / non-HTTP protocols.
- An agent that spawns child processes that don't inherit `HTTP_PROXY`.
- DNS exfiltration via crafted lookups.
- Filesystem-mediated leaks across user boundaries (via identity remap).
- An agent reading host environment variables it shouldn't see.

### Proxy-only backends (vz, wsl2) protect against:

- A cooperative agent that routes its HTTP/HTTPS traffic through `HTTP_PROXY` / `HTTPS_PROXY`.
- A host environment where `NO_PROXY` might accidentally route traffic around the Sidecar (cleared by built-in profiles).

### Proxy-only backends do **not** protect against:

- A non-cooperative agent that opens raw sockets, ignores `HTTP_PROXY`, or uses non-HTTP protocols.
- An agent that spawns children with a clean environment that doesn't inherit proxy variables.
- DNS exfiltration via direct UDP queries.

### No backend protects against:

- Bugs in the chosen backend (bwrap escapes, VZ guest-host vulnerabilities, etc.). The sandbox is as strong as the backend.
- An agent that targets the Sidecar itself (e.g. exhausts its connections, exploits a parsing bug). The Sidecar is your TCB; treat it that way.
- Side channels (timing, power consumption, etc.). OpenFirma is a network policy boundary, not a side-channel boundary.
- Cooperative protocol abuse (e.g. an agent that uses an *allowed* destination to smuggle data). That's a policy problem, not a sandbox problem — see [Threat model & bypasses](../threat-model/).
- Anything that happens *inside* the sandbox that doesn't generate network traffic (an agent that just churns CPU, or that writes to its own scratch space).

The sandbox is the *plumbing* that routes outbound calls through the Sidecar. On structural backends, that plumbing is mandatory; on proxy-only backends, it depends on agent cooperation. It is the policy and capability layers, not the sandbox, that decide whether a given call is OK.

## When to use `firma run` vs proxy env vars alone

Use proxy env vars alone when:

- You're developing OpenFirma itself or a policy bundle.
- The agent is your own code, running on a machine you trust, and you're using OpenFirma for *audit and policy*, not for *containment*.
- You want the lowest-friction setup — no sandbox, just `HTTPS_PROXY=…`.

Use `firma run` when:

- The agent is third-party, untrusted, or runs prompts you don't fully control.
- You want a hard guarantee that nothing escapes the policy boundary, and you can use a structural backend.
- You're shipping an agent runtime to others and the policy boundary is part of the product (rather than an add-on operators have to remember to wire up).
- Your threat model includes a compromised agent process that might actively try to evade enforcement.

**Important:** If you are on macOS or WSL2 and your threat model includes a non-cooperative or adversarial agent, proxy-only enforcement may not be sufficient. Consider running `firma run` on a Linux host with the `bwrap` backend for structural confinement, or accept the proxy-only limitation explicitly via `--allow-non-structural`.

For the macOS parity decision, including the capability matrix and ESF caveats, see [macOS structural confinement strategy](../macos-structural-strategy/).

For a worked example of using `firma run` to govern a real coding agent, see [Secure a local coding agent](../../guides/secure-a-coding-agent/).

## Where to go next

- [Wrap an agent with `firma run`](../../guides/firma-run/) — the operator-side walkthrough.
- [Threat model & bypasses](../threat-model/) — what's in scope and what's not.
- [Interception](../interception/) — what happens once traffic reaches the Sidecar.
