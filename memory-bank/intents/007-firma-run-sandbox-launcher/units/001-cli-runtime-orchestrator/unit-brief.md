---
unit: 001-cli-runtime-orchestrator
intent: 007-firma-run-sandbox-launcher
phase: inception
status: ready
created: 2026-04-26T12:00:00Z
updated: 2026-04-26T12:00:00Z
---

# Unit Brief: CLI Runtime Orchestrator

## Purpose

Provide the `firma run` entrypoint and runtime supervision behavior so wrapped agents behave like native commands while the wrapper enforces startup and shutdown safety.

## Scope

### In Scope
- CLI command surface and argument parsing
- Child process orchestration and signal forwarding
- Interactive-safe stdio/TTY handling
- Startup ordering gates for fail-closed behavior

### Out of Scope
- Sandbox backend internals (Unit 002)
- Network confinement and DNS mechanics (Unit 003)
- Identity and capability semantics (Unit 004)

---

## Assigned Requirements

| FR | Requirement | Priority |
|----|-------------|----------|
| FR-1 | CLI Surface and Invocation Model | Must |
| FR-2 | Process Orchestration and Interactive Safety | Must |

---

## Domain Concepts

### Key Entities
| Entity | Description | Attributes |
|--------|-------------|------------|
| RunCommand | Parsed user invocation | profile, config path, command argv |
| RuntimeSupervisor | Process lifecycle coordinator | child pid, signal state, exit status |
| StartupGate | Required preconditions before agent launch | sidecar ready, backend ready |

### Key Operations
| Operation | Description | Inputs | Outputs |
|-----------|-------------|--------|---------|
| parse_run_args | Parse CLI invocation | argv | RunCommand |
| start_supervised_process | Launch and supervise wrapped process | RunCommand, prepared runtime | pid + streams |
| forward_signals | Mirror parent signals to child group | signal events | graceful/forced termination |

---

## Story Summary

| Metric | Count |
|--------|-------|
| Total Stories | 4 |
| Must Have | 4 |
| Should Have | 0 |
| Could Have | 0 |

### Stories

| Story ID | Title | Priority | Status |
|----------|-------|----------|--------|
| 001-cli-surface-and-arg-parsing | CLI command and parser | Must | Planned |
| 002-process-supervision-and-signal-forwarding | Supervisor lifecycle and signals | Must | Planned |
| 003-tui-safe-stdio-passthrough | Interactive-safe stdio handling | Must | Planned |
| 004-fail-closed-startup-order | Startup gating invariants | Must | Planned |

---

## Dependencies

### Depends On
| Unit | Reason |
|------|--------|
| None | Foundation unit |

### Depended By
| Unit | Reason |
|------|--------|
| 002-bwrap-backend-contract | Backend wired through orchestrator |
| 005-profiles-and-config | CLI selects profile/config |

---

## Constraints

- Preserve wrapped command exit code semantics
- Preserve PTY/TUI behavior
- No launch before sidecar/backend readiness gates pass

## Success Criteria

### Functional
- [ ] CLI parses all required flags and passthrough args
- [ ] Signals are forwarded correctly
- [ ] Interactive behavior is preserved
- [ ] Startup fails closed when prerequisites are unavailable

### Quality
- [ ] Integration tests cover signal and exit-code behavior
- [ ] CLI docs/examples match implementation
