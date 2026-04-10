---
id: 006-proxy-core
unit: 001-proxy-core
intent: 006-sidecar-proxy-enforcement
type: ddd-construction-bolt
status: planned
stories:
  - 001-http-proxy-listener
  - 002-https-mitm-interception
  - 003-ca-keypair-management
created: 2026-04-05T12:00:00Z
started: null
completed: null
current_stage: null
stages_completed: []

requires_bolts: []
enables_bolts: [007-proxy-core]
requires_units: []
blocks: false

complexity:
  avg_complexity: 3
  avg_uncertainty: 2
  max_dependencies: 2
  testing_scope: 3
---

# Bolt: 006-proxy-core

## Overview

First bolt for the proxy core — establishes the Pingora HTTP/HTTPS proxy transport layer with TLS MITM interception and CA keypair management.

## Objective

Implement the foundational proxy transport: Pingora listener for plain HTTP, HTTPS CONNECT with dynamic cert generation via rcgen/rustls, domain cert caching, and CA keypair lifecycle (generate, persist, reuse).

## Stories Included

- **001-http-proxy-listener**: Plain HTTP proxy interception (Must)
- **002-https-mitm-interception**: HTTPS CONNECT + TLS MITM (Must)
- **003-ca-keypair-management**: CA keypair generation and persistence (Must)

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
- None (foundational transport layer)

### Enables
- 007-proxy-core (config, health, denial responses)

## Success Criteria

- [ ] Plain HTTP requests intercepted with full request available
- [ ] HTTPS CONNECT triggers dynamic cert gen for target domain
- [ ] Certs cached per-domain (no duplicate generation)
- [ ] CA keypair generated on first run, persisted, reused
- [ ] Integration tests for Pingora request/response lifecycle
- [ ] Concurrent cert generation tests

## Notes

- Pingora lifecycle hook ordering is a high-risk area — spike early
- Sparse Pingora documentation means integration tests are critical
- This bolt establishes the process skeleton that all other bolts plug into
