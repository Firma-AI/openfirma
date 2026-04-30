---
id: 002-process-supervision-and-signal-forwarding
unit: 001-cli-runtime-orchestrator
intent: 007-firma-run-sandbox-launcher
status: ready
priority: must
created: 2026-04-26T12:00:00Z
assigned_bolt: 014-cli-runtime-orchestrator
implemented: false
---

# Story: 002-process-supervision-and-signal-forwarding

## User Story

**As an** operator
**I want** `firma-run` to supervise child processes correctly
**So that** interruptions and exits behave predictably

## Acceptance Criteria

- [ ] **Given** wrapped process is running, **When** parent receives `SIGINT`, **Then** signal is forwarded to wrapped process group
- [ ] **Given** wrapped process exits with code `N`, **When** wrapper exits, **Then** wrapper returns exit code `N`
- [ ] **Given** wrapped process hangs on shutdown, **When** grace timeout expires, **Then** wrapper force-terminates and exits with deterministic non-zero code

## Technical Notes

- Use process-group aware signaling
- Support both non-interactive and interactive child modes
- Ensure cleanup for bridge/helper child processes

## Dependencies

### Requires
- 001-cli-surface-and-arg-parsing

### Enables
- 003-tui-safe-stdio-passthrough
- 004-fail-closed-startup-order

## Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| Child exits before supervision loop starts | Wrapper returns child code cleanly |
| Multiple helper processes exist | All owned children receive termination |
| Repeated Ctrl-C | Escalates from graceful to forced termination |

## Out of Scope

- Network confinement behavior
