# Budget Ceiling Requirements

**Status: OPEN — requirements not yet finalized. This document captures open questions that must be resolved before implementation begins.**

Budget ceiling enforcement is the mechanism by which Firma enforces spending limits on agent activity. A capability token may carry a ceiling value; the Sidecar tracks cumulative spend for that token and denies requests once the ceiling is reached or exceeded.

## Open Questions

### 1. Value Kind — What does a "budget" measure?

The ceiling could represent different kinds of resource consumption. Each has different measurement, estimation, and enforcement characteristics.

| Kind | Unit | Notes |
|------|------|-------|
| **Monetary** | Currency amount | Maps directly to cost, but requires a pricing model per tool/API |
| **Token count** | LLM tokens (input + output) | Natural for LLM calls, meaningless for HTTP tool calls |
| **Call count** | Number of requests | Simple, provider-agnostic, but coarse |
| **Composite** | Multiple dimensions combined | Most expressive, most complex |

Open questions:
- Is a single kind sufficient for V1, or must the enum be open from day one?
- If monetary: in what unit? Cents (integer arithmetic)?
- If token count: does it count input tokens, output tokens, or both?
- Can a token carry multiple ceilings (e.g., both a cost ceiling and a call ceiling)?

### 2. Time Window — Over what period does the budget reset?

A ceiling can be absolute (valid for the token's TTL only) or rolling (resets periodically).

| Window | Description |
|--------|-------------|
| **Per-token** | Ceiling applies for the lifetime of the capability token; no reset |
| **Per-session** | Ceiling applies from session start to session end |
| **Daily** | Budget window is a calendar day (midnight to midnight) |
| **Weekly** | Rolling 7-day window |
| **Monthly** | Calendar month |
| **Custom interval** | User-defined reset interval in seconds |

Open questions:
- Should the sidecar report back the consumed budget? Or should the usage be retrieved by other means (like calling a third-party APIs, ...)?
- What happens on Sidecar restart? (V1 has no persistent state — counters reset. Is this acceptable for budget enforcement, or does it mean budget enforcement is only meaningful within a single token lifetime?)
- Is per-token sufficient for V1, or do users need cross-token budget tracking?
- If rolling windows are needed, where is the counter stored? (Per-token counters live in Sidecar memory; cross-token counters require persistent state — a V1 non-starter per the known limitation in `domain-design-decisions.md`.)
- Is the time window an attribute of the token, or a system-wide configuration?

### 3. Scope — What is the ceiling applied to?

A ceiling can be scoped to different units of activity.

| Scope | Description |
|-------|-------------|
| **Per-token** | One counter for all calls made with this token |
| **Per-session** | One counter across all tokens in a session |
| **Per-agent** | One counter across all sessions for an agent identity |
| **Per-tool** | Separate counter for each tool/action class |
| **Per-resource** | Separate counter per target resource or endpoint |

Open questions:
- Is per-token the only scope needed for V1?
- If per-session scope is needed: how is the session identified? (`session_id` in the token? In the Execution Envelope metadata?)
- If a token for the same `session_id` has a different `budget_ceiling`, should the Sidecar replace the previous `ceiling_budget` for that session?
- Should the budget be updated pre-call (estimated), post-call (actual), or both?

### 4. Estimation — How is spend measured before the actual cost is known?

For LLM calls, the output token count is unknown until the call completes. For HTTP calls, the cost may depend on the response payload size or API-specific billing logic.

Open questions:
- Does Firma measure spend pre-call (block if estimated cost exceeds ceiling) or post-call (block when cumulative actual cost exceeds ceiling)?
- If pre-call: what estimation model is used? Fixed cost per call? Input-token-based estimate? User-supplied estimate in the request?
- If post-call: what happens on the first request that pushes the counter over? Is it allowed and the next one is denied, or is the call that causes the overflow denied?
- Who provides the cost per unit? The capability token? The policy bundle? A per-connector config table? An external pricing API?
- What happens when the Sidecar cannot compute or estimate cost (e.g., no pricing model for the tool)? Fail open or fail closed?

### 5. Storage and Configuration — How do operators define budgets?

Open questions:
- How is the counter persisted across requests within a token lifetime? In-memory (simple, lost on restart)?
- Is there a configuration schema for budget limits in `firma-sidecar` config (e.g., `config.toml`)? Or is everything token-driven?
- How is the budget ceiling stored in the Authority?

### 6. Wire Format and Type Safety

Open questions:
- The `CapabilityClaims` struct currently has no `budget_ceiling` field. When added, should it be `Option<BudgetCeiling>` (ceiling is optional per token)?
- How is `BudgetCeiling` serialized in the PASETO v4 token payload (JSON)? What is the canonical representation?
- What is the proto representation in `types.proto`?
- Does the `Execution Envelope` metadata carry a `budget_consumed` field (it is referenced in `domain-design-decisions.md`)? If so, who populates it and when?

### 7. Denial Semantics

Open questions:
- When the ceiling is reached mid-stream (e.g., during a streaming LLM response), should the stream be cut? Or only the next call be denied?
- What is the behavior when the estimated cost of a single call exceeds the remaining budget entirely?

---

## Known V1 Constraint

Per `domain-design-decisions.md`:

> **Sidecar restart**: In-process state lost — budget counters reset, sessions cleared. Agents must re-issue capabilities. Known V1 limitation (no persistent state).

This means:
- Any budget enforcement in V1 is bounded by the capability token's TTL and the Sidecar's uptime.
- Cross-token or cross-session budget tracking is out of scope for V1.
- Per-token in-memory counters are the only feasible V1 implementation.
