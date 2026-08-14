---
title: The sandbox boundary
description: How firma run contains agent egress, what structural vs proxy-only enforcement means, and what each backend protects against.
---

`firma run` wraps an agent in a sandbox, routes its outbound traffic through the Sidecar, and — on structural backends — *removes* the agent's ability to bypass that route. On default macOS and WSL2 paths, enforcement is proxy-based: traffic is mediated only for cooperative HTTP clients that honor `HTTP_PROXY`. macOS also has experimental structural paths behind explicit environment gates. This distinction is the most important thing to understand before relying on `firma run` for security enforcement.

## The problem with proxy env vars alone

`HTTP_PROXY` is a hint, not a constraint. It works because most HTTP libraries respect it by convention. But:

- A library that doesn't respect proxy env vars (some Go binaries, some C libraries) bypasses it silently.
- An agent that opens raw TCP sockets bypasses it.
- An agent that spawns a child process with a clean environment bypasses it.
- Anything that reads `/etc/hosts`, makes its own DNS query, or talks UDP bypasses it.

For a cooperative agent on a developer laptop, none of this matters. For a less-trusted agent — anything you didn't write, anything running prompts you don't fully control, anything that could be compromised — the proxy hint is not a security boundary. It's a convention, and the agent can choose to ignore it.

## Structural vs proxy-only enforcement

`firma run` has two materially different enforcement modes:

**Structural confinement** (Linux `bwrap`; experimental macOS structural modes): The sandbox removes the agent's ability to bypass the proxy at the OS level. In the Linux path, the agent runs in a network namespace where the only reachable destination is the proxy bridge — raw sockets, DNS lookups, and child processes all dead-end inside the sandbox. The macOS sandbox-exec experiment blocks external IP egress but remains loopback-scoped. The macOS VZ guest path emits a strict launch contract for an operator-provided Virtualization.framework runner, which must boot the guest with bridge-only egress. No extra cooperation from the agent is required once the structural boundary is active.

**Proxy-only / compatibility mode** (macOS `vz`, Windows/WSL2 `wsl2`): The agent runs in the host environment with `HTTP_PROXY` and related environment variables injected. Outbound mediation depends on the agent (or its HTTP library) respecting those variables. Raw sockets, proxy-env-unset children, and non-HTTP protocols can bypass the Sidecar.

This is not a preference — it is a current capability gap. Cross-platform structural parity is tracked as a separate implementation effort. The macOS strategy decision is documented in [macOS structural confinement strategy](../macos-structural-strategy/): VZ guest-based structural parity is the primary path, while ESF-native controls are treated as targeted hardening rather than a standalone structural network boundary.

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

### Structural backends

1. **Network boundary.** On Linux `bwrap`, the agent runs in a network namespace where the only reachable network destination is a host-side process listening on `127.0.0.1:18080` (the proxy bridge). On experimental macOS network-deny mode, the agent is restricted to the Firma proxy bridge and DNS stub on loopback (port-scoped) and external IP egress is blocked. On macOS VZ guest mode, `firma run` writes a launch contract that requires the configured guest runner to expose only the sidecar bridge and DNS stub to the guest.
2. **Proxy bridge.** A small helper inside the sandbox listens on `127.0.0.1:18080` and forwards bytes over a Unix socket to the host's Sidecar (typically at `$XDG_RUNTIME_DIR/firma/sidecar.sock`). On Linux `bwrap`, the agent's traffic has nowhere else to go. On experimental macOS network-deny mode, external IP egress is blocked and the loopback re-allow is port-scoped to the bridge and DNS stub. On macOS VZ guest mode, the bridge URL is part of the runner contract.
3. **DNS stub.** A stub resolver answers DNS queries deterministically. On Linux it runs inside the sandbox path. On macOS structural paths, `firma run` starts a host-side refusal stub; sandbox-exec reaches it on loopback, and the VZ guest runner must wire guest DNS to it. Random outbound DNS must not be a successful bypass.
4. **`HTTP_PROXY` injection.** For agents that *do* respect proxy env vars, `firma run` sets `HTTP_PROXY=http://127.0.0.1:18080` so they don't need any code change.
5. **Identity remap.** The agent runs under a sandbox user (configurable via `--identity-mode`), so it can't read host secrets via filesystem.
6. **Config mask (Linux `bwrap`).** Firma config is masked from inside the sandbox by default. When `firma.toml` lives in a `.firma/` directory, that whole directory is tmpfs-overlaid so the file is absent and policy bundles and keys beside it are hidden too; an explicit bare config file outside `.firma/` is bound over `/dev/null` instead, because masking its parent could hide the workspace root. The mask covers more than the single resolved config, because the agent runs as your uid and the host filesystem is bind-mounted: it hides every `.firma/` on the current working directory's walk-up path (the same walk config discovery uses) plus `$HOME/.firma`, since a later `firma run` from any of those directories could discover a config planted there. Symlinked `.firma/` directories in that discoverable set fail closed before launch, because a writable symlink entry could otherwise be replaced with a real config directory for a later run. Since `firma.toml` is loaded once at startup and not hot-reloaded, this closes both a read leak (Authority topology / `agent_id`, keys) and a cross-session poisoning path where a compromised agent edits config to weaken its own next-run sandbox. Profile mounts are ordered around the mask: workspace-parent mounts and mounts targeting `.firma/` itself are emitted before the mask so the mask wins, while strict subpath mounts under `.firma/` are emitted after it — this is how the `vscode` profile keeps its state under `.firma/vscode/` without re-exposing `firma.toml`. One gap remains: an agent that plants a `.firma/` in a workspace *subfolder* you later `cd` into is a discovery-time trust problem the mask cannot solve.

The result is that an agent running under Linux structural `firma run` can attempt to bypass the proxy in any way it likes — open raw sockets, set its own DNS, fork a child process — and every one of those attempts dead-ends inside the sandbox. Experimental macOS network-deny mode provides a narrower claim: external IP egress is blocked, and the loopback re-allow is now port-scoped to Firma's own endpoints rather than all of loopback. Experimental macOS VZ guest mode has the stronger structural target, but depends on a runner and guest image bundle and still needs hardware E2E evidence before it becomes the default claim.

### Loopback blocking

A connection to `127.0.0.1`, `::1`, or any loopback address does not traverse `HTTP_PROXY`, so without extra controls an agent could reach local admin ports, internal daemons, or MCP servers with no policy evaluation and no audit trail. `firma run` closes this at the sandbox boundary — for the **agent process only**, never for Firma's own components:

- **Linux (bwrap).** A seccomp `user-notify` filter traps every `connect(2)` the agent makes. A host-side supervisor classifies the destination and **blocks** any loopback target that is not the proxy bridge or DNS stub, returning `EACCES`. This catches direct sockets and proxy-ignoring clients alike. The deny path is race-free; the allow path uses `SECCOMP_USER_NOTIF_FLAG_CONTINUE` and carries the usual seccomp-notify TOCTOU caveat, which is acceptable because the allow-list is just Firma's two loopback ports and the network namespace is already private. Each blocked attempt is reported to the Sidecar over the **`firma run` audit channel** — a per-run control socket carrying `RunAuditEvent` messages, of which the loopback block is the first kind — and recorded as a **signed audit event** (`DENY`, action class `network.loopback`, reason `loopback blocked`) visible in `firma monitor`.
- **macOS (sandbox-exec structural).** The `TrustedBSD` MAC profile denies all outbound, then re-allows loopback **only** to the proxy bridge and DNS stub ports. The block is structural, but sandbox-exec denials are not delivered to the Sidecar, so macOS does **not** emit a per-attempt signed audit event — a known gap.
- **Proxy-only backends (vz default, wsl2).** No loopback guard; these remain cooperative proxy-only.

The proxy bridge (`127.0.0.1:18080`) and DNS stub are explicitly exempt so Firma's own loopback traffic is unaffected. If the guard cannot start (for example, a kernel without seccomp user-notify), the run continues without it and logs a warning — in structural mode the private network namespace already isolates the agent from host loopback services, so the guard is defense in depth plus a direct-socket audit trail.

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
| `firecracker` | Linux    | KVM micro-VM                                 | Planned        |
| `vz`          | macOS    | Host proxy bridge + HTTP proxy injection (`HTTP_PROXY`); optional sandbox-exec network-deny or VZ guest runner contract | Proxy-only (default); experimental structural modes via `FIRMA_RUN_VZ_STRUCTURAL_NETWORK=1` or `FIRMA_RUN_VZ_GUEST=1` |
| `wsl2`        | Windows  | HTTP proxy injection (`HTTP_PROXY`)         | Proxy-only     |

You can override the platform default with `--backend`:

```bash
firma run --profile generic --backend firecracker -- python my_agent.py
```

The choice is mostly an operational one: bwrap is fast to start and lightweight; current `vz` and `wsl2` are compatibility options on their platforms; the Firecracker backend is planned as a VM path.

`firma run` cannot escalate privileges. On Linux it requires unprivileged user namespaces (which most modern distros enable by default). On WSL hosts, implicit backend selection uses the `wsl2` compatibility backend instead of attempting `bwrap`.

## Cross-OS capability matrix

Use this section as the current release claim for `firma run` confinement. It tracks runtime invariants, not only backend names, so a backend can be useful while still missing a structural guarantee.

| OS | Modes and release stance |
| -- | ------------------------ |
| Linux | `bwrap`: current structural release path.<br />`firecracker`: planned backend; no current release claim. |
| macOS | `vz` default: proxy-only compatibility path.<br />`vz` + `FIRMA_RUN_VZ_STRUCTURAL_NETWORK=1`: experimental `sandbox-exec` network-deny mode; not a default release claim.<br />`vz` + `FIRMA_RUN_VZ_GUEST=1`: experimental VZ guest runner contract mode; not a default release claim. |
| Windows / WSL2 | `wsl2`: proxy-only compatibility path. |

### Linux

Available modes:

- `bwrap` - current Linux default.
- `firecracker` - planned Linux micro-VM backend.

| Runtime invariant | `bwrap` | `firecracker` |
| ----------------- | ------- | ------------- |
| Sidecar-only egress | **Yes.** Network namespace makes the proxy bridge the only useful exit. | **Planned.** KVM micro-VM network isolation target. |
| DNS confinement | **Yes.** Sandbox resolver points at the local DNS stub or fails closed. | **Planned.** Guest-local deterministic resolver target. |
| Fail-closed startup | **Yes.** Backend, sidecar, policy, and seccomp setup failures block launch. | **Planned.** |
| Fail-closed runtime | **Yes.** With no direct egress route, sidecar or bridge loss breaks outbound traffic. | **Planned.** |
| Child/process-tree bypass resistance | **Yes.** Child processes inherit the network namespace. | **Planned.** |
| Syscall/seccomp enforcement | **Linux-only.** Static seccomp cBPF is supported with a bounded Cedar-subset projection. | **Planned.** Linux guest path should reuse static kernel controls where applicable. |
| Loopback blocking + audit | **Yes.** A seccomp `user-notify` guard blocks the agent's direct `connect(2)` to any loopback target other than the proxy bridge / DNS stub, and reports each block as a signed `network.loopback` DENY in `firma monitor`. | **Planned.** |
| Config (`firma.toml`) mask | **Yes.** Every `.firma/` on the cwd walk-up path plus `$HOME/.firma` is masked by default, so the agent cannot read Authority topology / `agent_id` or poison config for a later run unless an explicit mount re-exposes it. | **Planned.** |
| Immutable execution envelope | **Yes.** Runtime fixes identity, env, mounts, routing, and optional seccomp before launch. | **Planned.** |
| Interactive CLI/TUI support | **Yes.** Stdio, signals, and exit status are preserved through the wrapper path. | **Planned.** |
| Evidence status | Runtime code, Linux E2E harness, and FIR-111 seccomp spike artifacts exist. | Planned backend; no release evidence. |

### macOS

Available modes:

- `vz` default - proxy-only host compatibility mode.
- `vz` + `FIRMA_RUN_VZ_STRUCTURAL_NETWORK=1` - experimental `sandbox-exec` network-deny mode.
- `vz` + `FIRMA_RUN_VZ_GUEST=1` - experimental VZ guest runner contract mode.

#### `vz` default

| Runtime invariant | Status |
| ----------------- | ------ |
| Sidecar-only egress | **No.** Cooperative HTTP clients are mediated through injected proxy env. |
| DNS confinement | **No.** Host DNS remains available to non-cooperative processes. |
| Fail-closed startup | **Yes for startup.** Launch is blocked unless proxy-only mode is explicitly accepted and the sidecar path is prepared. |
| Fail-closed runtime | **Partial.** Proxy-routed clients fail, but direct sockets can bypass. |
| Child/process-tree bypass resistance | **No.** Children can ignore or clear proxy env. |
| Syscall/seccomp enforcement | **No.** seccomp is unavailable on macOS. |
| Immutable execution envelope | **Partial.** Runtime creates a deterministic launch envelope, but proxy-only children can still bypass network intent. |
| Interactive CLI/TUI support | **Yes.** Host-process compatibility path preserves normal CLI behavior. |
| Evidence status | Runtime proof logs and unit tests support the proxy-only claim. |

#### `vz` + `FIRMA_RUN_VZ_STRUCTURAL_NETWORK=1`

| Runtime invariant | Status |
| ----------------- | ------ |
| Sidecar-only egress | **Partial / experimental.** External IP egress is denied by `sandbox-exec`, and the loopback re-allow is port-scoped to the proxy bridge + DNS stub (other loopback services are denied). |
| DNS confinement | **Partial / experimental.** Non-loopback DNS is blocked by network denial; the host resolver is not replaced. |
| Fail-closed startup | **Yes / experimental.** Network-deny mode still uses the same startup fail-closed path. |
| Fail-closed runtime | **Partial / experimental.** External egress denied and loopback port-scoped to Firma endpoints; hardware E2E is pending. |
| Child/process-tree bypass resistance | **Partial / experimental.** Child processes should inherit the MAC sandbox label; loopback is port-scoped to Firma endpoints and hardware E2E is pending. |
| Syscall/seccomp enforcement | **No seccomp.** Uses TrustedBSD MAC network rules, not syscall filtering. |
| Loopback audit trail | **No.** The loopback block is structural, but `sandbox-exec` denials are not delivered to the Sidecar, so there is no per-attempt signed audit event (unlike the Linux seccomp guard). |
| Immutable execution envelope | **Partial / experimental.** Launch envelope plus MAC profile are fixed before process start. |
| Interactive CLI/TUI support | **Yes / experimental.** Still host-process based through `sandbox-exec`. |
| Evidence status | Runtime code and unit tests exist; macOS hardware E2E assertions are written but not yet green evidence. |

#### `vz` + `FIRMA_RUN_VZ_GUEST=1`

| Runtime invariant | Status |
| ----------------- | ------ |
| Sidecar-only egress | **Target / experimental.** Launch contract requires bridge-only guest egress; the runner and guest image must enforce it. |
| DNS confinement | **Target / experimental.** Contract carries the DNS stub address; the runner must wire guest DNS to it. |
| Fail-closed startup | **Target / experimental.** Artifact validation and contract generation fail closed; runner-side preflight must also prove the guest boundary. |
| Fail-closed runtime | **Target / experimental.** Guest route and bridge loss behavior must be proven by the runner and hardware E2E tests. |
| Child/process-tree bypass resistance | **Target / experimental.** Guest boundary should cover the process tree; runner and guest proof are pending. |
| Syscall/seccomp enforcement | **Target only.** Contract can carry a seccomp filter path for an in-guest Linux runner; guest loading is not a current release claim. |
| Immutable execution envelope | **Target / experimental.** Versioned launch contract records command, env, mounts, network endpoints, and required invariants. |
| Interactive CLI/TUI support | **Target / experimental.** Runner must preserve stdio, signals, exit status, terminal resize, and TTY behavior. |
| Evidence status | Runtime contract code and unit tests exist; signed VZ runner, guest image lifecycle, route proof, and hardware E2E are still pending. |

### Windows / WSL2

Available mode:

- `wsl2` - proxy-only compatibility mode.

| Runtime invariant | `wsl2` |
| ----------------- | ------ |
| Sidecar-only egress | **No.** Cooperative proxy env only. |
| DNS confinement | **No.** No mandatory DNS boundary. |
| Fail-closed startup | **Yes for startup.** Launch is blocked unless proxy-only mode is explicitly accepted and the sidecar path is prepared. |
| Fail-closed runtime | **Partial.** Proxy-routed clients fail, but direct sockets can bypass. |
| Child/process-tree bypass resistance | **No.** Children can ignore or clear proxy env. |
| Syscall/seccomp enforcement | **No current claim.** |
| Immutable execution envelope | **Partial.** Runtime injects env and identity into the WSL launch, but no structural boundary backs it. |
| Interactive CLI/TUI support | **Partial.** Basic process execution is supported; WSL terminal behavior depends on host setup. |
| Evidence status | Runtime code and unit tests support the proxy-only claim. |

## Known limits

These limits are part of the current release posture. Treat them as constraints on what `firma run` can claim today, not as implementation bugs.

| Limit | Current status | Practical effect |
| ----- | -------------- | ---------------- |
| macOS default `vz` is proxy-only | The default macOS backend launches a host process with proxy environment injection and a host-side bridge. | Cooperative HTTP clients are mediated, but raw sockets, direct DNS, and proxy-env-unset children can bypass the Sidecar. |
| macOS `sandbox-exec` mode is loopback-scoped | `FIRMA_RUN_VZ_STRUCTURAL_NETWORK=1` blocks external IP egress, but allows loopback so the proxy bridge and DNS stub can work. | Other host services listening on loopback remain reachable; this is not Linux-equivalent network namespace confinement. |
| VZ guest mode is not a default release claim | `FIRMA_RUN_VZ_GUEST=1` validates runner and image paths, writes the launch contract, and requires a configured runner and guest bundle to enforce bridge-only egress. | It remains experimental until hardware E2E proves guest lifecycle, guest routing, DNS confinement, and runtime loss behavior. |
| macOS hardware E2E evidence is not complete | The macOS assertion schema exists, but the structural suite is not yet green on supported macOS hardware. | macOS has no current release claim for Linux-style egress, DNS, child-process, or runtime fail-closed guarantees. |
| WSL2 is proxy-only | The current `wsl2` backend injects proxy env into the launched command. | It is useful for compatibility, but it is not a mandatory network boundary for non-cooperative processes. |
| seccomp is Linux-only static cBPF today | Managed seccomp is available for the Linux `bwrap` path as a static filter with a bounded Cedar-subset projection. | macOS and WSL2 do not get seccomp enforcement, and Linux syscall filtering is not live Cedar policy evaluation. |

**Structural** means the sandbox removes the agent's ability to bypass the proxy at the OS level - no extra cooperation from the agent is required. The experimental macOS network-deny mode is narrower than Linux because it is loopback-scoped rather than bridge-port-scoped. The experimental macOS VZ guest mode has the stronger structural target, but the runner and guest image own the actual Virtualization.framework lifecycle and in-guest enforcement.

**Proxy-only** means enforcement depends on the agent or its HTTP library respecting `HTTP_PROXY`. `firma run` refuses to launch proxy-only backends by default; `--allow-non-structural` is an explicit opt-in to that weaker enforcement model.

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

What `firma run` protects against depends on the enforcement mode. The lists below reflect this: Linux structural mode provides the strongest guarantee, experimental macOS network-deny mode blocks external IP egress with loopback caveats, and proxy-only backends provide best-effort mediation.

### Structural backends protect against:

- An agent that intentionally tries to bypass the proxy with raw TCP / UDP / non-HTTP protocols.
- An agent that spawns child processes that don't inherit `HTTP_PROXY`.
- DNS exfiltration via crafted lookups.
- Filesystem-mediated leaks across user boundaries (via identity remap).
- An agent reading host environment variables it shouldn't see.
- A wrapped process or descendant reading or forging host-side Firma runtime
  state. Linux masks the runtime root that contains per-run Sidecar and
  Authority files, sockets, metadata, signing keys, and capability seeds. The
  separate sandbox-local runtime remains visible because its proxy bridge and
  egress-guard sockets are part of the structural routing path.

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
