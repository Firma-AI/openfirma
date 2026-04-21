# Firma OSS Interception Boundary Bypass Analysis

Status: draft security analysis  
Date: 2026-04-13  
Owner: Security / Dario W1

## Purpose

This document audits the interception boundary for `firma-sidecar`, maps known bypass vectors, evaluates `ExecutionEnvelope` integrity against transport-layer tampering, and defines the structural constraints a future eBPF-based enforcement layer would need to satisfy.

This is a structural analysis artifact and it is intended to become the OSS security model disclosure for the interception boundary.

## Scope and method

This analysis is grounded in:

- `context/firma_oss_component_reference.md`
- `context/firma_fep_spec.md`
- `context/domain-design-decisions.md`
- `memory-bank/intents/006-sidecar-proxy-enforcement/requirements.md`
- the current `firma-sidecar` and `firma-core` code implementing normalization and enforcement primitives
- the proposed host-boundary remediation in `origin/fix/T-002-resource-scope-prefix-matching` (referenced from PR #16)

In particular, the analysis focuses on:

- the intended OSS V1 enforcement boundary
- the currently implemented library guarantees in `crates/firma-sidecar`
- the gap between the semantic FEP invariants and the current concrete Rust types

Out of scope:

- eBPF implementation details
- host/container sandboxing implementation
- cloud firewall or service-mesh policy
- exploit proof-of-concept development

## Executive summary

The main conclusions are:

1. Firma OSS V1 is an L7 policy enforcement layer, not a process-containment boundary. This is explicitly stated in the OSS component reference and remains the most important security disclosure: the Sidecar does not, by itself, stop arbitrary process behavior or raw socket access.
2. The intended OSS V1 interception boundary is HTTP/HTTPS request-path interception plus supported LLM response-path tool-call interception. Generic gRPC hot-path interception, MCP `stdio`, Unix sockets, raw TCP, and native database wire protocols are not covered in V1.
3. The strongest bypass vectors are:
   - direct outbound TCP / non-proxied HTTPS
   - localhost / loopback access
   - in-process SDK or local tool execution
   - MCP `stdio` / local transport
   - generic gRPC client traffic
4. Inside the covered request path, capability scope enforcement still has a host-boundary gap today:
   - `CapabilityMap` currently uses raw `starts_with` matching for `resource_scope`
   - that can over-match `api.openai.com` against `api.openai.com.evil.com/...` or `/v1` against `/v1alpha`
   - the referenced `fix/T-002-resource-scope-prefix-matching` branch proposes the right direction: host/path-aware boundary matching plus tests
   - this is not a transport bypass, but it is a real authorization-scope broadening risk inside the covered path
5. `ExecutionEnvelope` integrity is strong with respect to capability authenticity and normalized action/resource selection inside the current enforcement pipeline, but not fully sealed end-to-end:
   - capability claims are sidecar-selected and cryptographically verified
   - Stage 2 evaluates normalized `action_class` and `resource`, not transport-specific fields
   - however, the current Rust `ExecutionEnvelope` type exposes public fields, so post-construction immutability is a documented invariant rather than a fully type-enforced property
   - additionally, the current pipeline writes caller-supplied `session_id` into `ExecutionMetadata` while Stage 2 evaluates `claims.session_id`, creating a metadata consistency gap
6. eBPF can help close some bypass classes, especially direct TCP and loopback, but eBPF alone will not fully solve local tool execution, `stdio`, or semantic intent reconstruction for encrypted protocols. A future eBPF layer would need complementary userspace hooks and strict process attribution.

## Security boundary: What Firma is and is not

The component reference is explicit:

- Firma Sidecar is the L7 / application-layer policy enforcement layer.
- It is not the hard boundary for process isolation.
- Container isolation, seccomp, network policy, and similar runtime controls remain orthogonal and necessary.

This means the practical boundary in V1 is:

- trusted for: policy evaluation of calls that actually cross the Sidecar interception layer
- not trusted for: preventing an agent process from making calls the Sidecar never sees

This distinction is the key to every bypass vector below.

## Implementation status snapshot

The intended architecture and the currently implemented code are not the same thing yet.

### Intended OSS V1 boundary

- HTTP/HTTPS request-path interception via Pingora proxy
- LLM response-path tool-call interception for supported providers
- local Stage 1 + Stage 2 enforcement
- Authority gRPC only for issuance and policy/revocation streaming, never on the hot path

### Currently implemented in the repository

- `firma-authority` gRPC service is implemented
- `firma-sidecar` contains the intent normalizer, Stage 1 token validation, Stage 2 policy enforcement trait surface, and pipeline orchestration
- `firma-sidecar` does not yet implement the Pingora transport layer in the binary
- `firma-sidecar` does not currently depend on Pingora or Tonic
- the LLM response parser is specified in memory-bank artifacts but not yet implemented in code
- the current branch still uses prefix-based `resource_scope` matching in `CapabilityMap`; the tighter host-boundary matcher exists only on `origin/fix/T-002-resource-scope-prefix-matching`

### Security implication

This document therefore evaluates two things at once:

- the intended V1 security boundary as specified
- the already-implemented semantics inside the sidecar enforcement library

From a shipping-security perspective, the current `firma-sidecar` binary should not be treated as an active interception boundary yet.

## Minimal trusted computing base for the V1 interception boundary

1. The transport-layer interception mechanism that receives the call before dispatch.
   - In intended V1, this is the HTTP/HTTPS proxy and LLM response-path filter.
2. The Intent Normalizer and mapping configuration.
   - This is where raw transport input becomes the canonical `ExecutionEnvelope` intent.
3. Stage 1 capability selection and token verification.
   - Token authenticity, expiry, and revocation must be trusted.
4. Stage 2 policy evaluation and policy freshness logic.
   - Decisions must be made against the normalized envelope and local policy bundle only.
5. The credential injector and connector boundary.
   - These components must not re-interpret raw transport input or mutate envelope semantics.
6. Deployment-layer egress forcing.
   - The agent must actually be forced through the Sidecar for covered transports.

Strictly speaking, runtime containment is outside Firma's application-layer TCB. Practically, however, it is still required to stop agent-controlled traffic from bypassing the Sidecar entirely. In V1, the Sidecar cannot honestly claim a complete interception boundary without containment or network-routing support from the host environment.

## Intended interception coverage in V1

### Covered

- outbound HTTP/HTTPS that is routed through the Sidecar proxy
- LLM response-path tool-call instructions for supported providers and formats
- Stage 1 and Stage 2 enforcement over normalized action/resource data

### Not covered

- direct TCP/UDP sockets
- non-proxied HTTP/HTTPS clients
- localhost / loopback traffic not routed through the Sidecar
- Unix sockets
- MCP over `stdio` or local process transport
- generic gRPC client traffic
- native database wire protocols
- local-only effects such as shell, file, subprocess, or embedded SQLite execution

## Bypass vector map

Severity scale:

- Critical: defeats the boundary broadly with little or no policy visibility
- High: practical bypass for meaningful classes of agent behavior
- Medium: narrower, config-dependent, or requires a secondary mistake
- Low: limited blast radius or mainly correctness/audit impact

Status values:

- Closed in V1
- Partial in V1
- Deferred post-V1

| Vector                                                | Example                                                                                                        | Impact                                                                             | Status           | Severity | Evidence / Notes                                                                                                                                     | Recommended Mitigation                                                                            |
| ----------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- | ---------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Direct outbound TCP / UDP                             | Agent opens raw socket to external host                                                                        | Sidecar never sees the call; no envelope created                                   | Deferred post-V1 | Critical | V1 sidecar is explicitly HTTP proxy oriented; eBPF is roadmap only                                                                                   | Host egress controls, sidecar-forcing network policy, future eBPF socket capture                  |
| Non-proxied HTTP/HTTPS client                         | SDK ignores `HTTP_PROXY`, custom TLS stack, raw socket HTTPS                                                   | HTTP request bypasses proxy and request-path enforcement                           | Deferred post-V1 | Critical | V1 depends on proxy routing; no host-level forcing in OSS                                                                                            | Host-level proxy enforcement, iptables/eBPF, runtime sandboxing                                   |
| Localhost / loopback escape                           | Agent calls `127.0.0.1:*`, `::1`, or another local service directly                                            | Bypasses external proxy path; may reach sensitive local services                   | Deferred post-V1 | High     | No loopback interception mechanism exists in V1                                                                                                      | Local service isolation, firewall/namespace policy, future eBPF with loopback coverage            |
| Unix socket escape                                    | Tool talks to `/var/run/...sock` or local daemon socket                                                        | Bypasses network proxy entirely                                                    | Deferred post-V1 | High     | Unix socket mode is architectural/future; no generic socket interception exists                                                                      | Runtime policy, filesystem/socket ACLs, future hook or syscall-level coverage                     |
| Generic gRPC hot-path traffic                         | Tool uses internal `tonic` client to call service directly                                                     | HTTP proxy does not see generic gRPC client calls                                  | Deferred post-V1 | High     | Requirements explicitly state V1 does not intercept gRPC agent-to-service traffic                                                                    | Future gRPC hook, L7 proxying for HTTP/2/gRPC, or eBPF + userspace parsing                        |
| MCP over `stdio` / local process transport            | Agent invokes local MCP server as child process                                                                | No proxy boundary crossed; no pre-execution envelope created                       | Deferred post-V1 | High     | Future MCP usage is called out in repo docs; HTTP proxy does not cover `stdio`                                                                       | Future stdio/local hook, tighter runtime isolation                                                |
| Native DB wire protocol                               | PostgreSQL/MySQL direct connection                                                                             | DB action bypasses HTTP proxy entirely                                             | Deferred post-V1 | High     | Explicitly out of scope in V1 requirements                                                                                                           | DB proxy mode or eBPF/socket controls in future                                                   |
| Local SDK / local tool execution                      | Shell, file I/O, subprocess, SQLite, local business logic                                                      | Effects may happen with no network call for Sidecar to intercept                   | Partial in V1    | High     | Response-path parser can deny supported LLM tool suggestions before execution, but once local code runs there is no generic effect interception      | Response-path enforcement for supported providers, future SDK hooks, containment/runtime controls |
| Unsupported provider / format on response path        | New LLM provider, Realtime/WebSocket API, unknown tool-call payload format                                     | Tool suggestion reaches agent without Sidecar evaluation                           | Partial in V1    | High     | Unit brief explicitly forwards unknown/unsupported providers without response-path evaluation                                                        | Clear provider support disclosure, parser expansion, fail-closed policy for high-risk deployments |
| Malformed or oversized streaming body                 | SSE or JSON array stream never forms valid events                                                              | Planned response parser forwards remaining stream without response-path evaluation | Partial in V1    | High     | SSE reassembly story explicitly chooses fail-open on parse failure / buffer overflow                                                                 | Prefer configurable fail-closed mode for protected LLM endpoints, strict fixture coverage         |
| Misconfigured non-protected host passthrough          | `mapping.default_protected = false` or permissive allowlisting                                                 | Unknown hosts can be forwarded without normalization or policy                     | Partial in V1    | Medium   | Code supports `Passthrough`; config default is hardened (`default_protected = true`) but the escape hatch exists                                     | Keep `default_protected = true`, treat passthrough as exceptional and auditable                   |
| Resource-scope prefix bypass                          | Token scoped to `api.openai.com` or `.../v1` is matched against `api.openai.com.evil.com/...` or `.../v1alpha` | Stage 1 may select a capability outside the intended host/path boundary            | Partial in V1    | High     | Current `CapabilityMap` uses `resource.starts_with(resource_scope)`; `origin/fix/T-002-resource-scope-prefix-matching` adds host/path-aware matching | Adopt T-002 host-boundary semantics and keep the regression tests                                 |
| Transport-name semantic leakage                       | High-risk action disguised under transport-specific name or unmapped host/path                                 | Policy may not fire if normalization is wrong or too permissive                    | Partial in V1    | Medium   | FEP treats this as a primary threat; normalizer is designed to fail closed for protected actions                                                     | Strong rule coverage, registry conformance tests, protected-by-default config                     |
| Downstream envelope mutation                          | Connector or later stage mutates `intent`, `capability`, or `metadata` after ALLOW                             | Stage 2 decision and dispatched call can diverge                                   | Partial in V1    | Medium   | FEP forbids this, but current Rust envelope fields are public                                                                                        | Make envelope fields private, use read-only accessors and derived transport views                 |
| Session metadata confusion                            | Caller passes wrong `session_id`; token selection ignores `session_id` today                                   | Final envelope metadata can diverge from verified claims/session used in Stage 2   | Partial in V1    | Medium   | `CapabilityMap::select()` ignores `session_id`; pipeline writes caller-supplied `session_id` into metadata                                           | Validate session equality and derive metadata session from verified claims                        |
| Timestamp drift between evaluation and audit envelope | Stage 2 context uses fresh `Utc::now()`, not the normalized timestamp                                          | Small discrepancy between evaluated context and emitted envelope/audit metadata    | Partial in V1    | Low      | Mainly audit/reproducibility correctness issue                                                                                                       | Use normalized timestamp consistently through Stage 2 and final envelope                          |

## Detailed findings

### TCP bypass

Finding: a direct TCP connection from the agent can bypass the intended V1 boundary.

Reason:

- OSS V1 is specified as an HTTP/HTTPS proxy transport.
- `eBPF interception mode` is explicitly out of scope for V1.
- the current sidecar binary does not yet implement a transport boundary at all

Implication:

- without host-level routing or containment, an agent that can open arbitrary sockets can skip the Sidecar entirely
- this is the highest-severity structural bypass class

Classification: deferred post-V1

### Localhost escape

Finding: localhost and loopback calls are not structurally closed by V1.

Reason:

- loopback calls do not necessarily traverse `HTTP_PROXY`
- local services, admin ports, MCP daemons, or sidecar-adjacent processes may be reachable directly
- the Sidecar is not the process containment boundary

Implication:

- an agent may reach sensitive local services or alternate control paths outside the Sidecar's visibility

Classification: deferred post-V1

### SDK escape

Finding: SDK/local execution is only partially closed in V1.

What V1 does close:

- for supported LLM providers, the planned response-path parser can deny tool suggestions before the runtime executes them

What V1 does not close:

- direct local file, shell, subprocess, SQLite, or in-memory business logic
- SDK-initiated actions that never cross HTTP proxy or supported response parsers
- MCP `stdio` or local runtime integrations

Classification: partial in V1

### Protocol-level gaps

Finding: protocol coverage is intentionally incomplete in V1.

Notable gaps:

- generic gRPC hot-path interception
- native database wire protocols
- unsupported LLM response formats and transports
- malformed/oversized streaming bodies that the planned response parser forwards without evaluation

Classification: mixed, but mostly partial in V1 or deferred post-V1

## ExecutionEnvelope integrity vs transport

### What is strong today

#### Capability authenticity is robust

Stage 1 selects the capability internally from `CapabilityMap` and then verifies it cryptographically:

- the agent does not get to provide trusted claims directly
- signature validation rejects forged or tampered tokens
- expiry and revocation are checked locally

This is a strong property: transport input cannot directly forge capability claims that Stage 1 will trust.

#### Stage 2 evaluates normalized meaning, not raw transport

The normalizer constructs canonical `intent.action_class` and `intent.resource`. Stage 2 then evaluates:

- principal: verified `claims.agent_id`
- action: normalized `intent.action_class`
- resource: normalized `intent.resource`

This is aligned with FEP invariant `[I-N1]`: policy is supposed to bind to canonical meaning, not transport-specific details such as `raw_transport` or `raw_action_ref`.

#### Sensitive header handling is conservative

The normalizer strips sensitive headers like `Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`, and `X-Api-Key` before they enter the envelope and therefore before they can leak into logs or audits.

### What is not yet fully guaranteed

#### Envelope immutability is not fully type-enforced

The FEP and memory-bank design repeatedly require that the envelope become immutable after interception and that downstream components operate on derived transport views rather than mutating the envelope.

However, the current `ExecutionEnvelope` and nested structs expose public fields in `firma-core`.

Implication:

- the enforcement pipeline itself does not mutate the envelope after construction
- but downstream Rust code with ownership of the envelope could mutate it
- this means immutability is currently an architectural convention plus review requirement, not a sealed type guarantee

Conclusion:

- cannot honestly claim: "the envelope cannot be modified post-construction"
- can claim: "the intended boundary treats post-construction mutation as non-conformant, and the current pipeline itself does not mutate after construction"

#### Session metadata consistency gap

`CapabilityMap::select()` receives `session_id` but explicitly does not use it yet. The code comments say this is deferred until multi-agent-per-sidecar support exists.

At the same time, `EnforcementPipeline::enforce()`:

- evaluates Stage 2 using `claims.session_id`
- writes the caller-supplied `session_id` into `ExecutionMetadata`

Implication:

- a mismatched caller `session_id` can produce final envelope metadata that differs from the verified session in the token claims and from the session value used by Stage 2
- this is primarily an integrity and audit-correlation issue today
- it becomes more serious when multi-session token maps are introduced

Conclusion:

- transport input cannot currently forge trusted capability claims
- but a caller can influence emitted session metadata in a way that is not yet bound back to verified claims

#### Timestamp consistency gap

The normalizer stores `Utc::now()` in `NormalizedEnvelope.timestamp`, but Stage 2 builds its Cedar context with a fresh `Utc::now()` rather than reusing the normalized timestamp.

Implication:

- the final envelope timestamp and the evaluated policy timestamp can differ slightly
- this is low severity but weakens replay/debug fidelity

### Overall integrity conclusion

`ExecutionEnvelope` construction is protected against direct transport-layer forgery of capability claims and against policy decisions binding to raw transport fields.

However, the current implementation does not fully satisfy the stronger claim that the envelope is impossible to modify or confuse post-construction. The remaining issues are:

- public mutable fields rather than sealed immutable types
- caller-controlled `session_id` copied into final metadata
- Stage 2 timestamp drift from the normalized envelope timestamp

The correct statement for V1 is therefore:

- envelope integrity is strong inside the normalization + Stage 1 + Stage 2 path
- full immutability and transport-to-envelope consistency are not yet completely enforced by the concrete type/API surface

## eBPF constraints for post-V1 enforcement

The future eBPF story must be scoped carefully. eBPF can close important bypass classes, but only if the following structural constraints are satisfied.

### 1. Capture the right traffic classes

An eBPF layer would need to observe at least:

- outbound `connect`/`sendmsg`-style socket activity for TCP
- loopback traffic (`127.0.0.1`, `::1`)
- container / namespace-local traffic

If UDP or QUIC-based providers become relevant, the capture model must expand beyond TCP.

### 2. Attribute traffic to the correct workload

It must be possible to attribute an observed socket or syscall to:

- the agent process or cgroup
- the sidecar process
- the authority process
- any helper/connector process

Without correct attribution, the eBPF layer risks either:

- missing agent bypass traffic
- or accidentally intercepting the Sidecar's own traffic and creating enforcement loops

### 3. Avoid self-interception and control-plane recursion

The eBPF layer must explicitly exclude or separately classify:

- Sidecar outbound traffic
- Authority gRPC traffic
- audit sink traffic
- policy/revocation stream traffic

Otherwise, the enforcement layer can deadlock on itself or misclassify its own control-plane operations as agent actions.

### 4. Preserve enough metadata for normalization

Socket-level visibility alone is not enough to reconstruct semantic intent.

For example:

- a raw TLS socket does not reveal HTTP method/path/body without additional visibility
- a gRPC HTTP/2 stream does not trivially expose semantic method and message shape
- local shell/file effects may never cross a socket boundary at all

Therefore, a production-grade eBPF design would still need userspace helpers or programmatic hooks for:

- HTTP parsing
- HTTP/2 / gRPC parsing
- `stdio` / local IPC
- local execution surfaces that have no network footprint

### 5. Make readiness and failure semantics explicit

If eBPF becomes part of the enforcement boundary, startup/readiness must answer:

- did the program attach successfully?
- are all required probes active?
- is loopback included?
- is traffic attribution still valid after process restarts?

Failure semantics must be explicit:

- fail-open is not acceptable for high-risk protected traffic if eBPF is a required control
- if attach fails, readiness should fail or the deployment should clearly disclose degraded protection

### 6. Cover loopback and namespace-local traffic

eBPF that only covers external NIC egress does not close localhost escape. Loopback and namespace-local visibility are first-class requirements.

### 7. Recognize what eBPF cannot solve alone

Even a strong network eBPF layer does not fully solve:

- shell/file/subprocess/local DB effects
- MCP over `stdio`
- in-memory SDK behavior that never opens a relevant socket

Closing these classes requires:

- runtime containment
- programmatic interceptors/hooks
- or syscall/LSM-style controls beyond simple network interception

## V1 closure summary

### Closed in V1

- forged or tampered capability claims entering Stage 1
- expiry and revocation checks on the hot path
- policy decisions binding to raw transport fields instead of normalized action/resource
- unclassified protected HTTP traffic when `default_protected = true`

### Partially closed in V1

- tool execution before local side effects begin
- unsupported or malformed LLM response formats
- passthrough behavior driven by config
- host/path resource-scope precision during Stage 1 token selection
- envelope immutability and transport-to-envelope consistency

### Deferred to post-V1

- direct TCP / UDP bypass
- loopback / localhost bypass
- generic gRPC hot-path interception
- MCP `stdio` / local transport interception
- Unix socket interception
- native database wire protocol interception
- eBPF-backed socket enforcement

## Recommendations

### Immediate documentation / security model recommendations

1. Document the v1 boundary honestly:
   - HTTP/HTTPS routed through the Sidecar
   - supported response-path LLM tool interception
   - no generic claim of "all agent actions are intercepted"
2. Document the required deployment assumptions:
   - proxy routing
   - CA trust for HTTPS MITM
   - container/runtime controls to prevent direct socket bypass
3. Document explicit exclusions:
   - direct TCP
   - localhost
   - gRPC hot-path
   - MCP `stdio`
   - local-only tools/effects

### Immediate engineering recommendations

1. Preserve `mapping.default_protected = true` as the secure default and treat any passthrough configuration as an explicit risk acceptance.
2. Adopt the T-002 host-boundary matcher for `resource_scope` selection and preserve its regression tests for subdomain and path-prefix edge cases.
3. Make `ExecutionEnvelope` fields private and expose read-only accessors plus a dedicated transport-view builder.
4. Validate that caller `session_id` matches verified token claims, and prefer deriving final metadata from verified claims.
5. Reuse the normalized timestamp through Stage 2 and final envelope assembly for tighter audit/evaluation consistency.
6. When the transport layer lands, add integration tests specifically for:
   - proxy bypass attempts
   - loopback access
   - resource-scope host-boundary edge cases
   - IP-literal and alternate-host coverage
   - malformed response-path streams

### Post-V1 recommendations

1. Prioritize the bypass classes that actually evade the current boundary:
   - direct TCP/loopback visibility
   - local/`stdio` MCP interception
   - generic gRPC hook for enterprise RPC clients
2. Treat eBPF as one part of the answer, not the whole answer.
3. Keep FEP's semantic normalization model independent of interception transport so future hooks all feed the same enforcement pipeline.

## Final thoughts

The interception boundary is not yet a complete security boundary in OSS V1.

It is a strong application-layer enforcement boundary for:

- traffic that actually passes through the Sidecar
- supported LLM response-path tool-call formats
- verified capability tokens and normalized semantic actions

It is not yet a complete bypass-proof boundary against:

- raw network egress
- localhost/local transports
- generic gRPC
- SDK-local effects
- MCP `stdio`

The right OSS disclosure is therefore:

- V1 provides policy enforcement, not full containment
- several bypass classes remain open unless the deployment environment forces traffic through the Sidecar
- future eBPF and transport hooks can narrow these gaps, but they must satisfy the structural constraints listed above
