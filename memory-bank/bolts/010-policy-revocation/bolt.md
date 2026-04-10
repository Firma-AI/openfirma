---
id: 010-policy-revocation
unit: 003-policy-revocation
intent: 006-sidecar-proxy-enforcement
type: ddd-construction-bolt
status: planned
stories:
  - 002-grpc-policy-source
  - 004-grpc-revocation-source
created: 2026-04-05T12:00:00Z
started: null
completed: null
current_stage: null
stages_completed: []

requires_bolts: [009-policy-revocation]
enables_bolts: []
requires_units: []
blocks: false

complexity:
  avg_complexity: 2
  avg_uncertainty: 2
  max_dependencies: 2
  testing_scope: 2
---

# Bolt: 010-policy-revocation

## Overview

Second bolt for policy and revocation — gRPC streaming sources for Authority integration.

## Objective

Implement gRPC-based PolicySource (WatchPolicyBundle stream, incremental updates, TTL/fail-closed) and gRPC-based RevocationSource (WatchRevocations stream, bloom filter + LRU updates). Enables production mode with Authority as policy/revocation source.

## Stories Included

- **002-grpc-policy-source**: WatchPolicyBundle stream, incremental updates, TTL/fail-closed (Must)
- **004-grpc-revocation-source**: WatchRevocations stream, bloom filter + LRU updates (Must)

## Bolt Type

**Type**: DDD Construction Bolt
**Definition**: `.specsmd/aidlc/templates/construction/bolt-types/ddd-construction-bolt.md`

## Stages

- [ ] **1. Domain Model**: Pending → ddd-01-domain-model.md
- [ ] **2. Technical Design**: Pending → ddd-02-technical-design.md
- [ ] **3. Implementation**: Pending → src/firma-sidecar/
- [ ] **4. Test & Verify**: Pending → ddd-03-test-report.md

## Dependencies

### Requires
- 009-policy-revocation (traits and revocation cache must exist)

### Enables
- None (completes policy-revocation unit)

## Success Criteria

- [ ] gRPC policy: connects, receives initial bundle, applies incremental updates
- [ ] gRPC policy: TTL expiry → fail-closed (DENY all with POLICY_BUNDLE_STALE)
- [ ] gRPC policy: reconnect with full bundle push
- [ ] gRPC policy: failed parse → retain last valid
- [ ] gRPC revocation: events update bloom filter + LRU
- [ ] Revocation propagation < 1s p99

## Notes

- Depends on firma-proto gRPC definitions (intent 003, complete and stable)
- gRPC mode activated when --authority-url is configured
- TTL/fail-closed behavior is security-critical — test thoroughly
