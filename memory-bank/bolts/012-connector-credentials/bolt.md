---
id: 012-connector-credentials
unit: 005-connector-credentials
intent: 006-sidecar-proxy-enforcement
type: ddd-construction-bolt
status: planned
stories:
  - 001-http-connector
  - 002-credential-provider-trait
  - 003-credential-injection
created: 2026-04-05T12:00:00Z
started: null
completed: null
current_stage: null
stages_completed: []

requires_bolts: []
enables_bolts: []
requires_units: []
blocks: false

complexity:
  avg_complexity: 2
  avg_uncertainty: 1
  max_dependencies: 1
  testing_scope: 2
---

# Bolt: 012-connector-credentials

## Overview

Single bolt for the HTTP connector and credential injection — outbound request dispatch with connection pooling, credential resolution, and fail-closed injection.

## Objective

Build the outbound dispatch layer: generic HTTP connector translating authorized ExecutionEnvelopes to HTTP requests, CredentialProvider trait with config-based implementation, and transport-ready view derivation with credential injection.

## Stories Included

- **001-http-connector**: Outbound dispatch, connection pooling, timeouts (Must)
- **002-credential-provider-trait**: CredentialProvider trait + config-based implementation (Must)
- **003-credential-injection**: Derive transport view, inject creds, fail-closed (Must)

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
- None (independent outbound dispatch)

### Enables
- None (integrated by proxy-core after Stage 2 ALLOW)

## Success Criteria

- [ ] Authorized envelope translated to correct HTTP request
- [ ] Connection pooling with configurable pool size
- [ ] Timeout enforcement with CONNECTOR_TIMEOUT
- [ ] Connector does not modify intent/capability/metadata fields
- [ ] Per-target credential mapping from config
- [ ] Bearer, custom header, query param injection
- [ ] Agent never sees credentials
- [ ] Failed injection → DENY: CREDENTIAL_INJECTION_FAILED

## Notes

- Simplest bolt in the intent — well-understood HTTP client patterns
- Key constraint: ExecutionEnvelope is immutable, credentials via derived view
- V1 scope deliberately minimal (config-based only)
