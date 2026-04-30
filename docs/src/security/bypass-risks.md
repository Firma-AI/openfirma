# Bypass Risks

## Risk taxonomy

The five identified bypass risks fall into three categories:

- **Transport bypass** (Risk 1): agent traffic never reaches the sidecar. The
  sidecar cannot enforce policy it never sees.
- **Pipeline bypass** (Risks 2–3): traffic reaches the sidecar but skips an
  enforcement stage. A partial pipeline is as dangerous as no pipeline.
- **State-staleness** (Risks 4–5): enforcement runs but operates against
  outdated policy or revocation state. Decisions may be correct in form but
  wrong in substance.

## Per-risk treatment

| Risk                                                              | Severity | Mitigation                                                                                               | Residual exposure                                                                                    |
| ----------------------------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Interceptor bypass (direct TCP / native protocol / child process) | Critical | Host egress forcing (iptables / NetworkPolicy); `firma-run` structural confinement                       | Without host-level controls, an agent that does not honor `HTTP_PROXY` bypasses enforcement entirely |
| Stage 1 skipped                                                   | High     | `EnforcementPipeline::enforce()` single entry point; sequential chaining; short-circuit on Stage 1 error | Code changes that bypass the pipeline entry point                                                    |
| Stage 2 skipped                                                   | High     | Sequential chaining; fail-closed on stale bundle; no early-allow path                                    | Same — requires intentional pipeline modification                                                    |
| Stale policy bundle                                               | Medium   | Stage 2 freshness check; configurable TTL (`bundle_ttl_seconds`, default 30 s)                           | Brief window during Authority reconnect                                                              |
| Token reuse after revocation                                      | Medium   | Local `RevocationStore::is_revoked()` check; short TTLs; disconnect handling                             | Propagation lag between Authority revocation and local cache update                                  |

## Compensating controls

Three controls apply across multiple risks:

1. **firma-run structural confinement** — on Linux/bwrap, network namespace
   isolation prevents transport bypass even when the agent ignores `HTTP_PROXY`.
   This is the strongest defense against Risk 1 without requiring kernel-level
   iptables rules.
2. **Audit log immutability** — every enforcement decision emits a signed event.
   Gaps in the audit stream are observable and alert-worthy, providing
   after-the-fact detection for transport bypass and pipeline-skip scenarios.
3. **Capability scope tightening** — issuing narrowly-scoped tokens (short TTL,
   tight resource scope) limits the blast radius of both revocation-lag and
   prefix-matching gaps. Smaller scope means a compromised or stale token can
   do less damage.

## Open issues

- `CapabilityMap` uses `starts_with` prefix matching for `resource_scope`;
  host-boundary-aware matching is in progress (prevents scope over-matching
  such as `api.openai.com.evil.com` matching a token scoped to
  `api.openai.com`).
- `ExecutionEnvelope` fields are public; post-construction immutability is a
  convention, not a type guarantee.
- `session_id` in `ExecutionMetadata` is caller-supplied and not yet validated
  against verified token claims.
- Stage 2 builds its Cedar context with a fresh `Utc::now()` rather than
  reusing the normalized envelope timestamp, creating a small
  evaluation/audit discrepancy.

For full attack-tree analysis, see [Bypass Analysis](./bypass-analysis.md).
