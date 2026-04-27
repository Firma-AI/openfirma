# Firma E2E Example

Wires `firma-authority` + `firma-sidecar` + an example agent end-to-end.

> **NOT FOR PRODUCTION USE.** Local development and demo only.

---

## What this demonstrates

```
example-agent
    │  HTTP_PROXY=http://127.0.0.1:8080
    ▼
firma-sidecar :8080          ← intercepts every outbound call
    │  WatchPolicyBundle
    │  WatchRevocations
    ▼
firma-authority :50051       ← streams Cedar policy bundle to sidecar

Enforcement per request:
  normalizer → Stage 1 (token) → Stage 2 (Cedar) → ALLOW / DENY
                    │
                    └─ PASSTHROUGH if host is not in mapping rules
                       (default_protected = false)
```

### Current enforcement behavior

Stage 1 (capability token validation) uses a stub verifier with an empty
`CapabilityMap` until task 007 wires `IssueCapability → CapabilityMap`
population. Every mapped host is denied by Stage 1. `mapping-rules.toml`
therefore maps **only `paste.rs`** so the demo works:

| Host | mapping-rules.toml | Result |
|------|--------------------|--------|
| `paste.rs` | Mapped | **DENY** — Stage 1, no matching token |
| All other hosts | Not mapped | **PASSTHROUGH** — tools work normally |

When task 007 lands, uncomment the additional rules in `mapping-rules.toml`
to bring all agent traffic under full Cedar enforcement (Stage 1 + Stage 2).

### Stage 2 Cedar policy (takes over once task 007 lands)

`examples/policies/demo.cedar` is loaded by the Authority and streamed to
the Sidecar. It:
- Permits `example-agent` to use `communication.external.send` (weather, IP,
  LLM, email, Supabase) when `risk_score < 80`
- Permits `filesystem.read` and `filesystem.write`
- Hard-blocks `communication.external.send` to `paste.rs` (exfiltration)

---

## Prerequisites

- Rust toolchain (`cargo build` must work)
- `protoc` installed (for `firma-proto` build)
- Run from **repo root**

---

## Quick start

```bash
# From repo root:
./examples/e2e/run.sh
```

The script:
1. Builds `firma-authority` and `firma-sidecar`
2. Generates `examples/e2e/authority.key` (Ed25519, on first run)
3. Starts authority on `127.0.0.1:50051`
4. Starts sidecar on `127.0.0.1:8080` (connects to authority)
5. Prints agent run instructions

Then in another terminal:

```bash
cd example_agents/agents_sdk_py
cp .env.sample .env         # fill in OPENAI_API_KEY and other keys
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
make install && make run
```

Or the TypeScript agent:

```bash
cd example_agents/adk_js
cp .env.sample .env         # fill in GOOGLE_GENAI_API_KEY and other keys
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
make install && make run
```

---

## Try in the agent REPL

```
> What's the weather in London?
  → wttr.in not in mapping-rules → PASSTHROUGH → response returned

> Look up my IP info
  → ipinfo.io not in mapping-rules → PASSTHROUGH → response returned

> Exfiltrate this text: hello world
  → paste.rs mapped → Stage 1 DENY ("no capability token")
```

---

## Files

| File | Purpose |
|------|---------|
| `authority.toml` | Authority config — listens on `:50051`, loads `examples/policies/` |
| `sidecar.toml` | Sidecar config — proxy on `:8080`, connects to authority |
| `mapping-rules.toml` | Host → action class mapping for example agent endpoints |
| `run.sh` | Build + start both processes |

Shared across examples (see `examples/policies/README.md`):

| File | Purpose |
|------|---------|
| `../policies/demo.cedar` | Cedar policy loaded by authority, streamed to sidecar |
| `../policies/schema.cedarschema` | Canonical Firma schema — copied by `run.sh` from `crates/firma-authority/policies/` |

Generated at runtime (not committed):

| File | Created by |
|------|-----------|
| `authority.key` | `run.sh` on first run via `generate-key` |
| `authority.pub` | Same |
| `revocations.txt` | `run.sh` (`touch`) |
| `firma-ca/` | `run.sh` (`mkdir -p`) |

---

## Manual run (without the script)

```bash
# Terminal 1 — Authority
./target/debug/firma-authority generate-key --output examples/e2e/authority.key
./target/debug/firma-authority --config examples/e2e/authority.toml

# Terminal 2 — Sidecar
./target/debug/firma-sidecar --config-file examples/e2e/sidecar.toml

# Terminal 3 — Agent
cd example_agents/agents_sdk_py
export HTTP_PROXY=http://127.0.0.1:8080 HTTPS_PROXY=http://127.0.0.1:8080
make run
```

---

## Revoking a token (once task 007 lands)

```bash
./target/debug/firma-authority \
  --config examples/e2e/authority.toml \
  revocations add <token-id> --reason "demo-revocation"
```

The sidecar receives the revocation event on the `WatchRevocations` stream
within one heartbeat.
