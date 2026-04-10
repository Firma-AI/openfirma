---
bolt: 008-enforcement-pipeline
created: 2026-04-05T17:00:00Z
status: accepted
superseded_by: null
---

# ADR-002: Sidecar-managed capability map for token selection

## Context

The enforcement pipeline needs a capability token for every request it evaluates (Stage 1 validates the token, Stage 2 uses its claims for scope check and context). The agent is transparent — it knows nothing about Firma, sets `HTTP_PROXY`, and makes normal HTTP requests. The sidecar must select the correct token without agent cooperation.

This decision impacts: token cache lifecycle, shared vs per-agent sessions, restart/recovery semantics, revocation consistency, and audit token correlation.

Four options were evaluated:

1. **Token-per-session** — one active capability bound to the session
2. **Token-in-request header** — explicit token reference on every call
3. **Sidecar-managed capability map** — lookup by (session_id, action_class, resource)
4. **Derived capability selector** — deterministic selection from normalized envelope fields

Option 2 is ruled out because it violates the agent transparency requirement (agent must set a Firma-specific header).

## Decision

Use a **sidecar-managed capability map** (Option 3). The sidecar holds multiple capability tokens, each scoped to specific action classes and/or resources. After intent normalization produces an `ExecutionEnvelope`, the sidecar selects the best-matching token from the map by (session_id, action_class, resource).

### How It Works

```text
Agent makes HTTP request (knows nothing about Firma)
       │
       ▼
┌──────────────────┐
│ IntentNormalizer  │  → action_class, resource
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ CapabilityMap    │  → select token by (session_id, action_class, resource)
│  .select()       │
└────────┬─────────┘
         │ selected CapabilityToken
         ▼
┌──────────────────┐
│ Stage1Validator   │  → validate selected token
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Stage2Evaluator   │  → scope check + Cedar eval using token claims
└────────┬─────────┘
         │
         ▼
    EnforcementDecision
```

### Selection Algorithm

```rust
impl CapabilityMap {
    /// Select the best-matching token for the given envelope.
    /// Returns DENY if no matching token covers the action.
    pub fn select(
        &self,
        session_id: &str,
        action_class: &str,
        resource: &str,
    ) -> Result<&CapabilityToken, EnforcementDecision>;
}
```

**Matching rules** (most specific wins):
1. Token whose `action_set` contains the exact `action_class` AND whose `resource_scope` matches the `resource`
2. Token whose `action_set` contains the exact `action_class` with wildcard resource scope
3. Token with wildcard action set (`*`) matching the resource
4. No match → DENY: `TOKEN_INVALID` with detail "no capability token covers this action"

**Tie-breaking**: If multiple tokens match, prefer the one with the narrowest scope (fewest actions, most specific resource). If still tied, prefer the token with the latest `issued_at` (freshest).

### Provisioning

**Authority mode** (`--authority-url` configured):
- At startup, sidecar reads a capability manifest from config: a list of (agent_id, action_set, resource_scope) tuples
- Sidecar calls `AuthorityService.IssueCapability` for each entry
- Tokens stored in the capability map
- Sidecar refreshes tokens before expiry (re-issue with same scope)

**File mode** (no Authority, dev/testing):
- Operator provides pre-signed tokens in config (or a tokens directory)
- Sidecar loads them into the capability map at startup
- No auto-refresh (tokens expire → fail-closed)

### Capability Manifest (config)

```toml
# Each entry becomes one IssueCapability request at startup
[[capabilities]]
agent_id = "weather-agent"
action_set = ["llm.inference", "http.get"]
resource_scope = "api.openai.com/*"

[[capabilities]]
agent_id = "weather-agent"
action_set = ["http.get"]
resource_scope = "api.weatherapi.com/*"

[[capabilities]]
agent_id = "weather-agent"
action_set = ["file.read", "file.write"]
resource_scope = "local:///tmp/weather-cache/*"
```

### Pipeline Integration

The `enforce()` signature changes — token selection moves inside the pipeline, after normalization:

```rust
pub async fn enforce(
    &self,
    request: &RawRequest<'_>,
    session_id: &str,
    session_state: &SessionState,
) -> EnforcementDecision {
    // 1. Normalize intent
    let envelope = self.normalizer.normalize(request)?;

    // 2. Select capability token (NEW — between normalization and Stage 1)
    let token = self.capability_map.select(
        session_id,
        envelope.intent.action_class(),
        envelope.intent.resource(),
    )?;

    // 3. Stage 1: validate selected token
    let claims = self.stage1.validate(&token.raw_token)?;

    // 4. Stage 2: Cedar evaluation with claims from selected token
    self.stage2.evaluate(&envelope, &claims, session_state)
}
```

Note: `enforce()` no longer takes `raw_token: &str`. The sidecar provides the session_id; the pipeline selects the token internally.

## Rationale

### Why Option 3 over Option 1 (token-per-session)

Token-per-session is simpler but forces a single broadly-scoped token per agent. This means:
- Revocation is all-or-nothing (revoke the session token → agent can do nothing)
- No least-privilege: the token must cover every action the agent might ever take
- Audit events all share one token_id — less granular correlation
- Forces Cedar policies to do all fine-grained control, even scope boundaries that should be token-level

The capability map enables:
- **Per-capability revocation**: revoke the `file.write` token without affecting `llm.inference`
- **Least-privilege tokens**: each token scoped to exactly the actions/resources it covers
- **Richer audit**: token_id in audit events tells you which capability was exercised
- **Natural mapping to operator intent**: the capability manifest reads like a permission declaration

### Why Option 3 over Option 4 (derived selector)

Option 4 is a refinement of Option 3 with deterministic selection purely from envelope fields. Option 3 is more general — it allows session_id in the selection key, supporting future multi-agent-per-sidecar without a redesign. The selection algorithm already uses envelope fields (action_class, resource) as primary keys; session_id is additive.

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Token-per-session (1) | Simplest; one token to manage | Coarse revocation; no least-privilege; broad scope forced | Insufficient granularity for production use |
| Token-in-header (2) | Explicit; agent controls token | Violates agent transparency requirement | Agent must know nothing about Firma |
| Derived selector (4) | Pure function; no session_id needed | Less general; harder to extend to multi-agent | Option 3 subsumes it; session_id useful for future |

## Consequences

### Positive

- Per-capability revocation — revoke one token without killing the session
- Least-privilege — each token scoped to its action class / resource
- Richer audit — token_id correlates to specific capability exercised
- Multi-agent ready — session_id in selection key supports shared sidecar (future)
- Natural operator UX — capability manifest reads as a permission declaration
- Dual-mode — file mode loads pre-signed tokens, Authority mode issues at startup

### Negative

- More complex token lifecycle — N tokens to manage vs 1
- Startup is slower — N IssueCapability calls vs 1
- Operator must define capability manifest (what scopes to request)
- Token refresh logic is per-token, not per-session

### Risks

- **Manifest misconfiguration**: operator forgets to declare a needed capability → requests denied. Mitigation: clear error messages identifying the missing capability; example manifests for common providers.
- **Token explosion**: many fine-grained capabilities → large map. Mitigation: support wildcard action_set and resource_scope; operators choose their granularity.
- **Refresh thundering herd**: all tokens issued at startup expire at the same time. Mitigation: jitter refresh timing; Authority can vary TTLs.
- **File mode token expiry**: pre-signed tokens expire with no auto-refresh. Mitigation: clear DENY message with "token expired, no Authority configured for refresh"; documentation.

## Related

- **Stories**: 003-stage1-token-validation (validates selected token), 005-two-phase-pipeline-integration (enforce() signature change)
- **Standards**: No standards change needed
- **Previous ADRs**: ADR-001 in this bolt (firma-core type evolution — ExecutionIntent fields used for token selection)
- **Impact**: enforce() API signature changes from `(request, raw_token, session_state)` to `(request, session_id, session_state)`. Technical design must be updated.
