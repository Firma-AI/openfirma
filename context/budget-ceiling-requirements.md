# Budget Ceiling Requirements

Budget ceiling enforcement is the mechanism by which Firma enforces spending limits on agent activity. A capability token may carry a ceiling value; the Sidecar tracks cumulative spend for that token and denies requests once the ceiling is reached or exceeded.

## Open Questions

### 1. Value Kind — What does a “budget” measure?

The ceiling could represent different kinds of resource consumption. Each has different measurement, estimation, and enforcement characteristics.

| Kind            | Unit                         | Notes                                                            |
| --------------- | ---------------------------- | ---------------------------------------------------------------- |
| **Monetary**    | Currency amount              | Maps directly to cost, but requires a pricing model per tool/API |
| **Token count** | LLM tokens (input + output)  | Natural for LLM calls, but meaningless for HTTP tool calls       |
| **Call count**  | Number of requests           | Simple and provider-agnostic, but coarse                         |

Open questions:

* Is a single `u64` kind sufficient?
* If monetary: what unit should be used (e.g., cents)?
* If token count: should it include input tokens, output tokens?

---

### 2. Time Window — Over what period does the budget ceiling apply?

| Window              | Description                                                     |
| ------------------- | --------------------------------------------------------------- |
| **Per-token**       | The ceiling applies for the lifetime of the capability token    |
| **Per-session**     | The ceiling applies from session start to session end           |
| **Per-agent**       | A single counter across all sessions for a given agent identity |
| **Custom interval** | A user-defined reset interval (daily, weekly, monthly, etc.)    |

Open questions:

* Which time windows should the budget ceiling support?
* What happens on Sidecar restart?
* Should it report consumed budget, or should usage be retrieved via other means (e.g., third-party APIs)?
* Does Firma track cross-token budget?

---

### 3. Estimation — How is spend measured before the actual cost is known?

For LLM calls, the output token count is unknown until the call completes. For HTTP calls, the cost may depend on response payload size or API-specific billing logic.

Open questions:

* Should Firma measure spend pre-call (blocking if the estimated cost exceeds the ceiling) or post-call (blocking once the cumulative actual cost exceeds the ceiling)?
* If pre-call: what estimation model should be used? Fixed cost per call, input-token-based estimate, or a user-supplied estimate?
* If post-call: what happens to the first request that exceeds the ceiling? Is it allowed (and the next one denied), or is the overflowing request itself denied?
* Who defines the cost per unit?
* What happens when the Sidecar cannot compute or estimate the cost (e.g., no pricing model for the tool)? Fail open or fail closed?

---

### 4. Storage and Configuration

Open questions:

* How is the budget ceiling stored in the Authority?
* How do users define the budget?

---

## Known V1 Constraint

Per `domain-design-decisions.md`:

> **Sidecar restart**: In-process state is lost—budget counters reset and sessions are cleared. Agents must re-issue capabilities. This is a known V1 limitation (no persistent state).

This means:

* Budget enforcement in V1 is bounded by the capability token’s TTL and the Sidecar’s uptime.
* Cross-token or cross-session budget tracking is out of scope for V1.

