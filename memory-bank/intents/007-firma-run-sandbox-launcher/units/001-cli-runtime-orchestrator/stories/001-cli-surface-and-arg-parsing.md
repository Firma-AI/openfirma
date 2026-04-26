---
id: 001-cli-surface-and-arg-parsing
unit: 001-cli-runtime-orchestrator
intent: 007-firma-run-sandbox-launcher
status: ready
priority: must
created: 2026-04-26T12:00:00Z
assigned_bolt: 014-cli-runtime-orchestrator
implemented: false
---

# Story: 001-cli-surface-and-arg-parsing

## User Story

**As an** engineer running an agent
**I want** a stable `firma run` CLI surface
**So that** I can wrap commands without learning backend internals

## Acceptance Criteria

- [ ] **Given** I run `firma run -- python agent.py`, **When** args are parsed, **Then** the wrapper identifies `python agent.py` as wrapped command and applies default `generic` profile
- [ ] **Given** I pass `--profile codex`, **When** command starts, **Then** resolved profile is `codex`
- [ ] **Given** I pass `--config ./firma-run.yaml`, **When** config loads, **Then** CLI uses that file as override source
- [ ] **Given** unknown CLI flags are provided, **When** parsing runs, **Then** command fails fast with actionable usage error

## Technical Notes

- Use clap subcommand model (`firma run`)
- Preserve `--` passthrough semantics
- Keep final parsed model independent from execution logic

## Dependencies

### Requires
- None

### Enables
- 002-process-supervision-and-signal-forwarding
- 004-fail-closed-startup-order

## Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| Missing wrapped command after `--` | Exit with usage error |
| Both profile and config specify profile fields | Deterministic merge order (CLI > file > default) |
| Duplicate flags | Parser rejects or chooses documented precedence |

## Out of Scope

- Process lifecycle behavior
- Sandbox backend implementation
