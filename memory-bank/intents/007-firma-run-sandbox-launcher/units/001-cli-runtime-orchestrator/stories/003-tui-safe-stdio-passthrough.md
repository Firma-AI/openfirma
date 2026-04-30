---
id: 003-tui-safe-stdio-passthrough
unit: 001-cli-runtime-orchestrator
intent: 007-firma-run-sandbox-launcher
status: ready
priority: must
created: 2026-04-26T12:00:00Z
assigned_bolt: 014-cli-runtime-orchestrator
implemented: false
---

# Story: 003-tui-safe-stdio-passthrough

## User Story

**As an** agent developer
**I want** TUI/interactive tools to keep normal behavior under `firma run`
**So that** the wrapper is operationally invisible

## Acceptance Criteria

- [ ] **Given** wrapped command uses TTY controls, **When** run through `firma-run`, **Then** cursor/ANSI output remains correct
- [ ] **Given** terminal is resized, **When** wrapped process is running, **Then** child receives resize updates
- [ ] **Given** command uses stdin prompts, **When** user types input, **Then** input reaches child without buffering artifacts

## Technical Notes

- Prefer PTY mode when parent has TTY
- Preserve raw mode toggling expectations
- Keep binary-safe stdout/stderr forwarding

## Dependencies

### Requires
- 002-process-supervision-and-signal-forwarding

### Enables
- 006-e2e-bench-and-docs/002-codex-profile-e2e

## Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| Parent has no TTY (CI) | Falls back to pipe mode safely |
| Large stdout bursts | No deadlock/backpressure stalls |
| Child writes to stderr only | Stream remains visible and ordered enough for UX |

## Out of Scope

- Profile-specific defaults
