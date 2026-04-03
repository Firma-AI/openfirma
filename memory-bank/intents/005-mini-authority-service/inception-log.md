---
intent: 005-mini-authority-service
created: 2026-04-01T10:00:00Z
completed: null
status: in-progress
---

# Inception Log: mini-authority-service

## Overview

**Intent**: Real firma-authority binary — Cedar policy loader, gRPC service implementation, capability token generation
**Type**: green-field
**Created**: 2026-04-01T10:00:00Z

## Artifacts Created

| Artifact | Status | File |
|----------|--------|------|
| Requirements | in-progress | requirements.md |
| System Context | pending | system-context.md |
| Units | pending | units/ |
| Stories | pending | units/*/stories/ |
| Bolt Plan | pending | memory-bank/bolts/ |

## Summary

| Metric | Count |
|--------|-------|
| Functional Requirements | TBD |
| Non-Functional Requirements | TBD |
| Units | TBD |
| Stories | TBD |
| Bolts Planned | TBD |

## Units Breakdown

| Unit | Stories | Bolts | Priority |
|------|---------|-------|----------|

## Decision Log

| Date | Decision | Rationale | Approved |
|------|----------|-----------|----------|
| 2026-04-01 | Support both startup load and hot-reload for Cedar policies | User wants authority ready for intent 007 dev mode; hot-reload is core to DX | Yes |
| 2026-04-01 | Simple file/CLI revocation mechanism for V1 | Keep scope minimal; no additional RPC needed | Yes |
| 2026-04-01 | Validate requests against Cedar before issuing tokens | Authority should enforce policy at issuance, not just sign blindly | Yes |
| 2026-04-01 | Assume intent 004 example agents exist; plug before shipping | Another team member building 004 in parallel | Yes |

## Scope Changes

| Date | Change | Reason | Impact |

## Ready for Construction

**Checklist**:
- [ ] All requirements documented
- [ ] System context defined
- [ ] Units decomposed
- [ ] Stories created for all units
- [ ] Bolts planned
- [ ] Human review complete

## Next Steps

1. Complete inception artifacts
2. Begin Construction Phase

## Dependencies

- Intent 002 (core types, PASETO v4 signer/verifier)
- Intent 003 (gRPC proto definitions, AuthorityService)
- Intent 004 (example agents — assumed available, built by another team member)
