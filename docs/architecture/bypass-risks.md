# Bypass Risk Analysis

Identifies paths that could skip enforcement stages in `firma-sidecar` and
documents mitigations.

## Risk 1: Interceptor Bypass

**Scenario:** The agent makes outbound calls that do not pass through the
sidecar interceptor.

**Examples:**

- The agent uses a direct TCP or TLS connection instead of the configured HTTP
  proxy.
- The agent connects to a database using a native wire protocol, such as
  Postgres `libpq`. The V1 sidecar is an HTTP proxy and does not intercept
  native database connections.
- The agent spawns a child process that inherits a clean environment without
  `HTTP_PROXY` set.
- Container networking allows egress traffic to bypass the sidecar container.

**Impact:** Stage 1 and Stage 2 are never invoked. The agent can reach external
systems without local enforcement.

**Mitigations:**

- **Network policy:** Use Kubernetes `NetworkPolicy` or `iptables` rules to
  force all egress through the sidecar listen port.
- **Environment lockdown:** Strip raw credentials from the agent environment so
  only the sidecar holds credential material for injection after `Allow`.
- **gRPC hook mode:** When the agent SDK supports it, use gRPC interception
  instead of environment-variable proxy configuration.
- **Audit gap detection:** Monitor for outbound connections that do not have a
  corresponding sidecar audit event.

## Risk 2: Stage 1 Skipped

**Scenario:** A code path reaches Stage 2 without passing through Stage 1 token
validation.

**Impact:** Stage 2 receives unverified or forged `CapabilityClaims`. Forged
claims could widen the action set or resource scope before policy evaluation.

**Mitigations:**

- **Pipeline entry point:** Use `EnforcementPipeline::enforce()` as the single
  enforcement entry point from interceptors and downstream callers.
- **Sequential chaining:** The pipeline calls Stage 1 before Stage 2. Stage 2
  receives `CapabilityClaims` from Stage 1's `ValidatedCapability` result.
- **Short-circuit on failure:** If Stage 1 returns `Err`, the pipeline returns
  `Deny` immediately. Stage 2 is not invoked.
- **Tests:** Keep happy-path and failure-path tests around the full pipeline so
  changes that reorder or bypass Stage 1 are caught locally.

## Risk 3: Stage 2 Skipped

**Scenario:** A request passes Stage 1 but the pipeline returns `Allow` without
evaluating policy constraints.

**Impact:** A valid token grants access within its token scope without bundle
freshness checks, time restrictions, or resource constraints.

**Mitigations:**

- **Sequential chaining:** `EnforcementPipeline::enforce()` constructs `Allow`
  only after `ConstraintEnforcer::evaluate()` returns `Ok(())`.
- **Fail closed on stale bundle:** If `policy.is_fresh()` is false, Stage 2
  returns `Deny`.
- **No early allow:** Token validation success is not enough to assemble the
  final `ExecutionEnvelope`.
- **Tests:** Keep a Stage 2 denial case that verifies the full pipeline returns
  `Deny` after Stage 1 succeeds.

## Risk 4: Stale Policy Bundle

**Scenario:** The policy bundle has not been refreshed within its TTL, but
requests are still being processed.

**Impact:** The sidecar could enforce outdated policies if staleness were not
caught before evaluation.

**Mitigations:**

- **Bundle freshness check:** Stage 2 checks `policy.is_fresh()` before policy
  evaluation and returns `Deny` when the bundle is stale.
- **Configuration:** The Authority advertises its `bundle_ttl_seconds` in each
  streamed bundle. There is no separate Sidecar TTL setting.

## Risk 5: Token Reuse After Revocation

**Scenario:** A capability token is revoked by the Authority, but the local
revocation store has not received the update.

**Impact:** The revoked token may continue to pass Stage 1 until revocation
state propagates or the token expires.

**Mitigations:**

- **Short TTLs:** Capability tokens should have short expiry windows.
- **Local revocation check:** Stage 1 calls `RevocationStore::is_revoked()` as
  part of token validation.
- **Authority disconnect handling:** When Authority integration is enabled,
  new token issuance should stop on stream loss while existing tokens expire.
