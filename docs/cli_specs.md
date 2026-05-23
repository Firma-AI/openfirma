**Firma CLI - Unified Runtime**

_Internal design proposal · v0.5 · supersedes v0.4 · aligned with FIR-84 (Done) and revised operational model_

| **PURPOSE**<br><br>Specify how Firma is shipped and operated as a single command-line surface - \`firma\` - replacing the current three-binary developer flow. This is v0.4 of the CLI spec. Architectural decisions (sidecar tenancy, Authority deployment shape, transport security, why-not-gRPC-everywhere) live in the V1 Architectural Decisions document and are referenced by section number rather than duplicated. Security findings live in the V1 Hardening & Security document.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CHANGES VS v0.4**<br><br>• Implementation status: FIR-84 ("Unify all binaries into a single firma CLI") is Done. The packaging refactor landed: firma sidecar, firma authority, firma run, firma \_\_dns-stub, firma \_\_proxy-bridge are now subcommands of one binary. Per-tool flags, env vars and exit codes preserved verbatim. Reference: github.com/Firma-AI/firma-oss PR #53.<br><br>• Operational model decision: \`firma stack\` is removed from the spec. The previously-discussed "stack supervisor" approach (FIR-86) is superseded. \`firma run\` is the primary entry point and bootstraps any missing component on demand.<br><br>• \`firma run\` autostart behaviour: confirmed and now first-class. If no Sidecar is reachable, \`firma run\` autostarts one (per Architectural Decisions §2). If no Authority is reachable, \`firma run\` prompts the user "no Authority found, start a local one? \[y/N\]" on first run and persists the choice in .firma/firma.toml. No silent local Authority bootstrap.<br><br>• \`firma sidecar status\` (docker-ps style) confirmed and tracked for implementation.<br><br>• Section 3.7 firma doctor and section 3.6 firma policy validate / test re-confirmed as V1 deliverables (still un-ticketed at the time of writing). |
| **READING ORDER**<br><br>1\. V1 Architectural Decisions - the "why" and "what shape"<br><br>2\. This document - the "how the user interacts"<br><br>3\. V1 Hardening & Security Checks - the "what to fix before GA"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |

# 1\. Objective

Firma ships as a unified developer experience under one entry-point command, firma, exposing every operational surface (Authority management, Sidecar management, agent runtime launching, monitoring) without forcing the user to remember three separate executables. **\`firma run\` is the primary command**: it bootstraps whatever is missing - Sidecar autostarts always; Authority is offered interactively the first time a project needs it. Three usage shapes:

- **one-command developer UX** - firma run codex bootstraps everything needed locally on first invocation, with one yes/no prompt for the local Authority;
- **local distributed enforcement** - Sidecar local to the agent boundary, never on the network hot path;
- **centralized governance** - one Authority can govern many Sidecars (see Architectural Decisions §3); when \[authority\].type = "remote" is configured in .firma/firma.toml, the bootstrap skips the local Authority prompt and connects to the configured URL instead;
- **optional local-only mode** - autostarted local Mini Authority for development with no external service.

_Architectural decisions referenced by this spec: sidecar tenancy is one-per-agent (Architectural Decisions §2); CLI is a frontend binary that execs siblings - implemented in FIR-84 (§5); HTTP-proxy remains the default transport for \`firma run\` (§6); \`firma sidecar status\` is redesigned \`docker ps\`-style (§3.3 and §7)._

# 2\. Runtime Components

## 2.1 Authority

Pre-flight policy decision and capability issuance. Source of truth for the policy bundle and the revocation list distributed to every connected Sidecar. Local Mini Authority (development) or centralized Authority (team / production). See Architectural Decisions §3 for deployment shapes.

## 2.2 Sidecar

Local enforcement engine, deployed alongside each agent runtime boundary. Two-stage evaluation pipeline plus credential injection and audit emission. Fail-closed by construction. In V1 the Sidecar is autostarted by \`firma run\` and dies with it (Architectural Decisions §2).

## 2.3 firma run - Primary entry point

User-facing launcher that wraps the agent process under enforcement and the configured sandbox backend. \`firma run\` is the primary command that operators learn first and use most. Its responsibility is end-to-end: discover or autostart the local Sidecar; resolve or interactively offer to start the Authority; obtain a capability token; configure the sandbox backend; wire the in-sandbox proxy bridge; launch the agent.

**IMPLEMENTATION STATUS**

FIR-84 (**Done**) has unified the binaries: firma sidecar, firma authority, firma run, firma \_\_dns-stub, firma \_\_proxy-bridge are now subcommands of one firma binary. Per-tool flags, env vars, and exit codes were preserved verbatim. The packaging refactor itself does NOT yet add the autostart behaviour described in this section - that requires a follow-up ticket (see §11 Open Questions).

What FIR-84 did **not** do, and is therefore still scope of this spec: the SidecarSupervisor (autostart Sidecar with kill-on-Drop), the interactive Authority bootstrap prompt (§4 step 4), the docker-ps-style firma sidecar status marker file scheme (§3.3 and §7), and the firma policy / firma doctor subcommands (§3.6 / §3.7).

The existing firma-run code already implements: backend selection (bwrap / vz / wsl2 / firecracker), sandbox identity remapping, capability lease, DNS stub, TCP-to-UDS proxy bridge, supervisor with signal forwarding. The remaining work for V1 is **extension, not rewrite**: add zero-config bootstrap, autostart logic, and the interactive Authority prompt on top of what is already there.

# 3\. CLI Surface

## 3.1 Top-level commands

firma run # PRIMARY - launch agents under enforcement, autostart deps

firma authority # manage Mini Authority / inspect remote authority

firma sidecar # inspect ephemeral sidecars, optional daemon mode

firma monitor # tail audit stream

firma policy # validate / test Cedar policies (V1 minimal)

firma doctor # diagnose installation and configuration (V1 minimal)

**NOT IN THE V1 SURFACE**

firma stack was previously proposed (FIR-86) as a supervisor that would spawn Authority + Sidecar as one long-lived bundle. It is **not part of V1**: firma run assumes that responsibility directly by autostarting any missing component. FIR-86 is to be closed or repurposed - see §11 Open Questions.

## 3.2 firma authority

Note: in V1 the default Mini Authority lifecycle is autostart-by-\`firma run\`, kill-on-exit (same model as the Sidecar in §3.3). The lifecycle commands below - start, stop, restart - are **daemon-mode only**: they target an Authority that the operator has explicitly started as a long-lived process. They do **not** affect the Mini Authority that firma run autostarts and terminates with the agent.

| **Command**                      | **Mode**    | **Behaviour**                                                                                                                                                |
| -------------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| firma authority start            | daemon only | Start a long-lived Mini Authority. Reads .firma/firma.toml or falls back to defaults. For the autostart-by-\`firma run\` case, you do not need this command. |
| firma authority stop             | daemon only | Stop the daemon. Reads PID from \$XDG_DATA_HOME/firma/authority/state/authority.pid. Affects only daemon-started Authorities.                                |
| firma authority restart          | daemon only | Stop + start.                                                                                                                                                |
| firma authority status           | any         | Health-check via gRPC. Accepts --url for remote authorities. Works on daemon-started, autostarted, or remote Authorities.                                    |
| firma authority logs             | daemon only | Tail the authority log file written by an explicitly-started daemon.                                                                                         |
| firma authority issue-capability | any         | Mint a signed capability token by calling IssueCapability. Mirrors the existing firma-authority issue subcommand.                                            |
| firma authority revoke           | any         | Append a token id to the revocation file; broadcast via WatchRevocations.                                                                                    |

_Removed from v0.2:_ firma authority list-tokens _- requires Mini Authority to persist issued-token state, which is not in V1 (Architectural Decisions §3.2)._

## 3.3 firma sidecar

Note: in V1 the default Sidecar lifecycle is autostart-by-\`firma run\`, kill-on-exit. The commands below are for two cases: (a) inspecting ephemeral Sidecars autostarted by ongoing firma run invocations (\`status\`, \`logs\`); (b) explicitly managing a long-lived Sidecar daemon for production / systemd deployments (\`start\`, \`stop\`).

| **Command**                                       | **Behaviour**                                                                                                                                                 |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| firma sidecar status                              | List all live Sidecars for the current user (docker-ps-style). Reads markers under \$XDG_RUNTIME_DIR/firma/run/&lt;sandbox_id&gt;/.                           |
| firma sidecar status --sandbox-id &lt;id&gt;      | Health-probe the single Sidecar identified by sandbox_id.                                                                                                     |
| firma sidecar status --json                       | JSON output for scripting.                                                                                                                                    |
| firma sidecar status --daemon                     | Health-probe a long-lived Sidecar (only present when explicitly started).                                                                                     |
| firma sidecar start                               | Explicitly start a Sidecar daemon. Production / systemd path. Honours --authority (local \| URL). Writes PID file under \$XDG_DATA_HOME/firma/sidecar/state/. |
| firma sidecar stop                                | Send SIGTERM to the explicitly-started daemon, wait for graceful drain.                                                                                       |
| firma sidecar restart                             | Stop + start (daemon mode only).                                                                                                                              |
| firma sidecar logs                                | Tail sidecar log file.                                                                                                                                        |
| firma sidecar inspect \[--sandbox-id &lt;id&gt;\] | Dump effective config + capability map + bundle version for the named Sidecar.                                                                                |
| firma sidecar refresh \[--sandbox-id &lt;id&gt;\] | Force-refresh policy bundle from authority. (The sidecar already auto-reloads via WatchPolicyBundle; this is a force operation.)                              |

## 3.4 firma run

Wraps an agent command under enforcement and a sandbox backend. Examples:

firma run codex

firma run claude

firma run --profile codex -- codex --yolo

firma run --profile team --authority <https://firma-auth.example> -- claude code

The current firma-run binary already supports --profile, --config, --backend, --sidecar-endpoint, --capability-file, --identity-mode. The unified CLI extends it with:

- \--authority &lt;url|local&gt; - remote Authority URL or \`local\` to autostart the Mini Authority.
- \--no-autostart - fail loudly if the Sidecar is not reachable. Production / CI safety net.
- \--sidecar=external - explicit opt-out of the autostart-and-kill model: use the existing Sidecar at \`--sidecar-endpoint\`. Production deployments where systemd manages the Sidecar.

## 3.5 firma monitor

Tail the local audit stream. Operates on the structured JSON-lines emitted by the sidecar audit sink - therefore presupposes JSON output (default).

firma monitor # tail all events

firma monitor --only-deny # filter on decision != ALLOW

firma monitor --agent codex # filter on agent_id

firma monitor --tail # follow live stream

firma monitor --json # raw JSON pass-through (no pretty-print)

## 3.6 firma policy (V1 minimal)

Cedar policy authoring is the most error-prone surface a developer touches. Two minimal subcommands save the team from the first malformed-policy fail-closed lockout:

| **Command**                              | **Behaviour**                                                                                                                                 |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| firma policy validate &lt;file.cedar&gt; | Parse + schema-check against the embedded Firma schema. Exit 0 on valid, non-zero with diagnostics on invalid.                                |
| firma policy test &lt;fixture.toml&gt;   | Evaluate a fixture (principal + action + resource + context) against a policy bundle. Prints ALLOW / DENY + diagnostics. Useful for CI gates. |

## 3.7 firma doctor (V1 minimal)

Diagnostic command. Prints a structured report covering: presence of sibling binaries on PATH or relative to current_exe; sandbox backend availability; Sidecar reachability; Authority reachability; parse status of .firma/firma.toml; presence of capability seed file. One day of work, six months of GitHub issues avoided.

# 4\. firma run - Boot Sequence

When the user runs \`firma run codex\`, the CLI executes a deterministic bootstrap. Steps may short-circuit (skip) when the required component is already reachable; the goal is "do the minimum needed to launch the agent securely":

1\. Resolve config - walk up from cwd looking for .firma/firma.toml;

fall back to \$XDG_CONFIG_HOME/firma/firma.toml;

else defaults

2\. Resolve identity - sandbox_id, session_id, profile from

RunIdentity::new

3\. Discover Sidecar - health-probe configured endpoint;

if reachable, skip step 3a and continue to step 4

3a. Spawn Sidecar - generate temp config, fork-exec firma sidecar

as a child of this firma run process,

scrape the seven-line "ready" log contract

(docs/cli.md). Timeout → fail with typed error.

4\. Resolve Authority - if \[authority\].type == "remote", use the URL;

else if a local Authority is reachable, use it;

else (interactive case, see §4.1):

prompt y/N to start a local Mini Authority;

on Y, fork-exec firma authority and persist

\[authority\].type = "local" in firma.toml;

on N, abort with a typed error explaining

how to set \[authority\].type = "remote"

5\. Obtain capability - if no --capability-file, call IssueCapability

over gRPC; persist seed at

\$XDG_RUNTIME_DIR/firma/capabilities/&lt;sandbox_id&gt;.toml

6\. Configure sandbox - backend prepare(): mount UDS into sandbox,

inject HTTP_PROXY env var, install proxy bridge,

apply identity remap

7\. Launch agent - wait_with_signal_forwarding;

on agent exit, terminate any components this

firma run autostarted (Sidecar always; Authority

only if it was prompt-started in this run)

**READY-LINE GATING**

Step 3a must scrape stdout for the seventh line (ready) of the sidecar startup log contract before sending traffic. If ready does not arrive within startup_timeout_secs (default 10 s), firma run aborts with a clean error pointing the user to firma sidecar logs. Without this gating, intermittent startup failures surface as misleading errors from the agent itself.

## 4.1 Interactive Authority bootstrap

Step 4 is the only step in the boot sequence that can prompt the user. The interaction is intentionally narrow: a single yes/no prompt, only on first use, with the choice persisted to project config so subsequent runs are silent.

**Trigger condition:** all four of the following are true.

- \[authority\] is missing or empty in the resolved firma.toml (the user has not committed to a deployment shape)
- No local Mini Authority is reachable at the default loopback endpoint
- \--authority was not passed on the command line
- stdin is a TTY (otherwise the prompt is impossible - abort with typed error and a hint about --authority local or \[authority\].type = "remote")

**The prompt:**

No Authority is configured for this project.

firma run can start a local Mini Authority for development on \[::1\]:50051.

This is suitable for a single developer on a trusted workstation.

Start a local Mini Authority? \[y/N\]:

**On Y:**

- fork-exec a Mini Authority process bound to loopback
- persist \[authority\]\\ntype = "local" in .firma/firma.toml (creating the file if missing). Subsequent firma run invocations skip this prompt entirely
- terminate the autostarted Authority on firma run exit only if it was started by this invocation; if a daemon-started Authority already existed and is being reused, it is left alone

**On N (or empty input):**

- abort with a typed error and three suggested next steps: (a) run firma authority start separately as a daemon, (b) configure \[authority\].type = "remote" with a URL in .firma/firma.toml, or (c) re-run with --authority local to bypass the prompt

**WHY INTERACTIVE INSTEAD OF SILENT**

The Mini Authority creates an Ed25519 signing key on first use, in a user-global directory (\$XDG_DATA_HOME/firma/authority/keys/). That is a security-relevant artefact. Silent creation in zero-config mode would be convenient but it would also surprise the developer with the existence of a long-lived key on their machine. A single yes/no prompt - once per project - converts a hidden side-effect into a deliberate, traceable user choice. After the first run, the choice is in firma.toml and there is no further friction.

## 4.2 Non-interactive overrides

For CI, scripted environments, and production deployments where prompts are unacceptable:

| **Mechanism**                                   | **Effect**                                                                                                                                                          |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| firma run --authority local &lt;agent&gt;       | Skip the prompt; autostart a local Mini Authority unconditionally.                                                                                                  |
| firma run --authority https://... &lt;agent&gt; | Skip the prompt; use the remote URL.                                                                                                                                |
| Pre-existing \[authority\] in firma.toml        | Skip the prompt; the project has already committed to a deployment shape.                                                                                           |
| firma run --no-autostart &lt;agent&gt;          | Refuse to autostart anything. If the Sidecar or Authority is missing, fail with a typed error. Recommended for CI where the absence of a component is itself a bug. |

# 5\. Zero-Config Development Mode

If no .firma/ is found and no --config is passed, firma run &lt;agent&gt; bootstraps a complete local stack on first invocation. The flow combines steps from §4 (Boot Sequence) with one-time scaffolding:

- creates .firma/ in the current working directory with default firma.toml
- initialises user-global state in \$XDG_DATA_HOME/firma/ (keys, tokens, revocations) - NOT in the project directory
- writes a **minimal explicit** Cedar policy bundle into .firma/policies/ (see §5.1 below)
- autostarts a local Sidecar on a UDS under \$XDG_RUNTIME_DIR/firma/ (per Hardening §Issue 5 - no 0.0.0.0 default)
- prompts "Start a local Mini Authority? \[y/N\]" (per §4.1) on first run; on Y, autostarts the Authority on \[::1\]:50051 and persists the choice in .firma/firma.toml
- issues a default capability for the agent and seeds the sidecar
- launches the agent under the configured sandbox backend

_Goal: a contributor with a fresh clone and zero Firma knowledge runs_ firma run claude*, answers a single y/N question, and gets a working enforced runtime. From the second run onward, it is fully silent.*

## 5.1 Generated default policy bundle

Earlier drafts proposed that zero-config mode write a default-deny + permit-known-host Cedar bundle covering popular API hosts (OpenAI, Anthropic, GitHub, etc.). Engineering review identified three risks with that approach:

- **Policy magic.** The developer does not see what is permitted and what is not, because the policy was generated by the tool from a hardcoded list. When something is unexpectedly denied - or unexpectedly allowed - the developer cannot inspect the rule that decided it.
- **Onboarding confusion.** "Why does OpenAI work but Anthropic does not?" "Oh, Anthropic is not in the hardcoded permit list." This is the single most common adoption friction in policy-driven systems.
- **Future unsafe defaults.** A maintainer adds a host to the permit list six months from now without thinking through the implications. The list grows quietly. Every consumer of the OSS inherits the new permission.

**V1 approach:** zero-config writes a **minimal, explicit, heavily-commented** policy file. No host-permit defaults. The developer reads the file on first run and decides what to add.

_Generated file at_ .firma/policies/default.cedar*:*

// ============================================================

// Firma - generated default development policy

//

// NOT INTENDED FOR PRODUCTION. NOT INTENDED FOR SHARED HOSTS.

//

// This file was generated by 'firma run' on first invocation

// in zero-config mode. It is the minimum policy required to

// run an agent under enforcement. It permits NOTHING by default.

//

// To allow your agent to call a specific service, ADD an

// explicit permit rule below. Examples are in:

// docs/policies/examples/

//

// To learn the action_class registry your agent will trigger,

// run with audit and inspect denied calls:

// firma monitor --only-deny

// ============================================================

// Default-deny: every action that is not explicitly permitted

// below is rejected by Stage 2.

forbid(principal, action, resource);

// Example: uncomment and adapt to permit a specific call class.

// permit(

// principal == Firma::Agent::"my-agent",

// action == Firma::Action::"model.inference.chat",

// resource is Firma::Resource

// ) when {

// resource.host == "api.openai.com"

// };

**WHY THIS WORKS BETTER**

The developer who hits their first DENY does not see "Firma blocked you for unclear reasons". They see "the default policy denies everything; here is the file to edit; here is the action_class that was denied". That is teachable. A hardcoded permit list is not - it works until it does not, and then nobody knows where the rule lives.

_The_ docs/policies/examples/ _directory ships a curated set of starter policies (per-action-class, per-host, per-budget) that the developer can copy. This separates "what the tool generates" (minimal, safe) from "what the docs offer" (rich, copyable, reviewed)._

# 6\. State Directories

**Critical change vs v0.1:** user-global state (authority keys, tokens, revocations) is separated from project-local config. The v0.1 spec mixed them in a single .firma/ tree, which is unsafe - accidental commits expose private keys.

## 6.1 User-global state

\$XDG_DATA_HOME/firma/ # default ~/.local/share/firma on Linux,

\# ~/Library/Application Support/firma on macOS

authority/

keys/

firma-authority.key # Ed25519 signing key (NEVER in repo)

firma-authority.pub

revocations/revocations.txt

state/authority.pid

sidecar/

state/sidecar.pid # only when explicitly started as daemon

capabilities/ # active capability lease files per sandbox_id

logs/

authority.log

sidecar.log

run.log

\$XDG_RUNTIME_DIR/firma/ # ephemeral runtime sockets and markers

sidecar.sock # default UDS for the Sidecar

run/

&lt;sandbox_id&gt;/ # per-firma-run marker dir

sidecar.sock # if per-run UDS

sidecar.pid

metadata.toml

## 6.2 Project-local config

./.firma/ # in the project working directory

firma.toml # config (authority url, profiles, paths)

policies/

default.cedar # base policies for this project

by-agent-id/

&lt;agent-id&gt;.cedar # per-AGENT-ID overrides - bound to the

\# agent identity in capability claims,

\# NOT to the agent runtime tool name

audit/

events.jsonl # local JSON-lines audit (default sink)

**NAMING DISCIPLINE**

Renamed from v0.1: policies/agents/codex.cedar → policies/by-agent-id/&lt;agent-id&gt;.cedar. In FEP the principal is the agent_id inside the capability claims, and policy binds to action_class (transport-independent, FEP §2.3 + invariant \[I-N1\]). The new path nudges the team toward writing policies bound to identity, not to tool names like "codex" or "claude".

# 7\. Sandbox ⇄ Sidecar Wiring

The contract between the sandboxed agent and the host-side Sidecar:

## 7.1 Process placement

- **Sidecar runs on the host** - outside any sandbox. Preserves access to credential stores, audit sinks, and the Authority gRPC stream. Placing the Sidecar inside the agent sandbox would defeat the security model.
- **Agent runs inside the sandbox** - under the configured backend. The agent process has no direct credential access.

## 7.2 Transport between sandbox and Sidecar

Already implemented in crates/firma-run/src/proxy_bridge.rs. Contract:

- host-side Sidecar exposes a UDS at \$XDG_RUNTIME_DIR/firma/sidecar.sock (or a per-sandbox-id path)
- inside the sandbox, firma-run \_\_proxy-bridge (an internal helper) listens on 127.0.0.1:18080 and proxies bytes to the host UDS
- the agent gets HTTP_PROXY=<http://127.0.0.1:18080> injected into its environment

The reason for the bridge: bwrap / vz namespaces cannot directly bind-mount a host socket into many target paths cleanly across all backends; TCP-on-loopback inside + UDS-on-host outside is the lowest-common-denominator transport.

## 7.3 Session propagation

The agent's capability is bound to a specific session*id and agent_id. firma run obtains the capability \_before* the sandbox starts and persists it as a seed file the Sidecar reads via \[capability_seed\].paths. The agent itself never handles the token - it only sets HTTP_PROXY. The Sidecar attaches the right token to outbound calls based on the (host, action_class) it normalizes from the request.

_Security note: the Sidecar must verify the local client identity (e.g. via SO_PEERCRED) before trusting an_ x-firma-session-id _header. See Hardening §Issue 1._

# 8\. UX Goals

## 8.1 Developer UX

firma run codex

must be enough to bootstrap the environment, start the local stack, and launch the agent securely. No prior config, no manual sidecar start, no manual capability issuance.

## 8.2 Team / Production UX

firma run codex --profile team

uses centralized Authority (with V1 TLS server-only, V1.1 mTLS), local Sidecar daemon (probably system-managed via systemd), production policies, production audit sinks. Same command surface, different config resolution.

# 9\. Recommended V1 Scope

Implementation status as of FIR-84 (Done) and pending work for the rest of the surface:

| **Subcommand**                                                    | **V1?**       | **Implementation status**                                                                                                                                   |
| ----------------------------------------------------------------- | ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| firma run (basic, with --sidecar-endpoint)                        | YES           | Shipped via FIR-84.                                                                                                                                         |
| firma run (with autostart Sidecar + interactive Authority prompt) | YES           | NEW WORK - open ticket. Builds on the existing crate; ~2-3 days work per Architectural Decisions §2.3.                                                      |
| firma sidecar (subcommand wrapping the existing daemon)           | YES           | Shipped via FIR-84.                                                                                                                                         |
| firma sidecar status (docker-ps style with markers)               | YES           | NEW WORK - open ticket. Depends on the SidecarSupervisor writing markers under \$XDG_RUNTIME_DIR/firma/run/&lt;sandbox_id&gt;/.                             |
| firma sidecar start/stop/restart (daemon mode)                    | YES           | Shipped via FIR-84.                                                                                                                                         |
| firma authority (subcommand wrapping the existing daemon)         | YES           | Shipped via FIR-84.                                                                                                                                         |
| firma authority issue-capability/revoke                           | YES           | Shipped via FIR-84.                                                                                                                                         |
| firma authority list-tokens                                       | NO            | Requires Mini Authority token persistence - not in V1.                                                                                                      |
| firma monitor                                                     | YES           | NEW WORK - open ticket. Tail of existing JSON-lines audit sink. FIR-86 originally bundled this with \`firma stack\`; carve it out into a standalone ticket. |
| firma policy validate                                             | YES           | NEW WORK - open ticket. High-leverage for adoption.                                                                                                         |
| firma policy test                                                 | YES (minimal) | NEW WORK - open ticket. Single fixture, single bundle, single eval. CI-friendly.                                                                            |
| firma doctor                                                      | YES (minimal) | NEW WORK - open ticket. PATH probes, sandbox backend probes, sidecar/authority health probes. FIR-84 listed it explicitly as out-of-scope follow-up.        |
| firma stack                                                       | NO            | Removed from spec. FIR-86 to be closed or repurposed (see §11).                                                                                             |
| firma config                                                      | NO            | Defer until pain materializes.                                                                                                                              |

# 10\. Out of Scope (deliberately)

- **process fusion.** No multicall busybox-style binary. The firma binary execs siblings - confirmed by FIR-84 implementation (Architectural Decisions §5).
- **firma stack supervisor.** Removed from V1. The "single supervisor that owns Authority + Sidecar" model is superseded by firma run bootstrapping each component on demand. This is the v0.5 decision and supersedes the FIR-86 direction.
- **multi-tenant Authority.** Stays in proprietary Firma Authority + F-Control Plane (Architectural Decisions §3).
- **issued-token enumeration.** Mini Authority signs and forgets in V1.
- **escalation / HITL flows.** Schema-reserved per FEP, not implemented in V1.
- **provenance chain capture.** Schema-reserved field on the envelope; not populated by V1 runtime.
- **gRPC-only transport for agent ↔ sidecar.** HTTP-proxy on UDS remains the default - preserves "wrap any HTTP-speaking agent" property (Architectural Decisions §6). gRPC mode stays available as opt-in for explicit SDK integrations.

# 11\. Open Questions and Follow-up Tickets

Coordination items between this spec and the Linear backlog as of v0.5:

## 11.1 FIR-86 disposition

FIR-86 ("Add stack and monitor commands to firma CLI") was started before the v0.5 decision to remove firma stack. Two parts of FIR-86 need to be separated:

- firma stack {start|stop|status} - **cancel**. The supervisor model is replaced by firma run autostarting individual components.
- firma monitor - **keep**, but extract into a standalone ticket. The audit-tail functionality is in V1 scope per §3.5; only the bundling under firma stack is dropped.

## 11.2 Tickets to open

Five new Linear tickets capture the V1 work that is not yet covered:

| **Title**                                                          | **Estimate** | **Spec ref**                                   |
| ------------------------------------------------------------------ | ------------ | ---------------------------------------------- |
| firma run: autostart Sidecar with kill-on-Drop (SidecarSupervisor) | 2-3 days     | §2.3, §4 step 3a, Architectural Decisions §2.3 |
| firma run: interactive Authority bootstrap prompt                  | 1 day        | §4 step 4, §4.1                                |
| firma sidecar status (docker-ps-style markers)                     | 1 day        | §3.3, §7                                       |
| firma monitor (carved out of FIR-86)                               | 2-3 days     | §3.5                                           |
| firma policy validate + firma policy test                          | 1-2 days     | §3.6                                           |
| firma doctor (minimal diagnostic)                                  | 1 day        | §3.7                                           |

## 11.3 Decisions deferred to engineering execution

- Should the autostarted Mini Authority bind \[::1\]:50051 or a UDS to avoid port collision on shared dev machines? Probably UDS for local mode, TCP+TLS for centralised mode. Decided in implementation.
- Format of the per-Sidecar marker file under \$XDG_RUNTIME_DIR/firma/run/&lt;sandbox_id&gt;/: TOML, JSON, or directory of single-purpose files? No architectural impact - pick whichever the team prefers.
- Should firma monitor have an auto-tail mode that follows new events as they arrive (similar to tail -f), or always require --tail? Probably auto-tail when stdout is a TTY.
- Concurrent firma run invocations: should the second one reuse the autostarted Sidecar from the first one (PID file with refcount), or always autostart its own? **v0.5 default: always its own** - Architectural Decisions §2 says one Sidecar per agent, period. Reusing is an optimisation we can add later if memory pressure becomes real.

# Appendix - Mapping spec to implementation

| **Spec section**                                                                 | **Implementation status**                                                      |
| -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| §3.1 unified firma binary with subcommands                                       | DONE - FIR-84 (PR #53)                                                         |
| §3.2 firma authority subcommands                                                 | DONE - FIR-84                                                                  |
| §3.3 firma sidecar subcommands (basic)                                           | DONE - FIR-84                                                                  |
| §3.3 firma sidecar status (docker-ps markers)                                    | NEW WORK - open ticket                                                         |
| §3.4 firma run --profile/--config/--backend/--sidecar-endpoint/--capability-file | DONE - predates FIR-84, preserved by it                                        |
| §3.4 firma run --authority and --no-autostart flags                              | NEW WORK - open ticket                                                         |
| §3.5 firma monitor                                                               | NEW WORK - carve from FIR-86 into standalone ticket                            |
| §3.6 firma policy validate / test                                                | NEW WORK - open ticket                                                         |
| §3.7 firma doctor                                                                | NEW WORK - open ticket                                                         |
| §4 boot sequence steps 5-7 (capability + sandbox + agent)                        | DONE - crates/firma-run/src/runtime.rs::execute_run, preserved by FIR-84       |
| §4 step 3a (autostart Sidecar with ready-line gating)                            | NEW WORK - open ticket                                                         |
| §4 step 4 + §4.1 (interactive Authority bootstrap)                               | NEW WORK - open ticket                                                         |
| §5.1 generated default policy bundle (minimal explicit)                          | NEW WORK - bundled with §4 step 4 ticket                                       |
| §7 sandbox ⇄ sidecar UDS bridge                                                  | DONE - crates/firma-run/src/proxy_bridge.rs + dns_stub.rs, preserved by FIR-84 |

_- end of document -_
