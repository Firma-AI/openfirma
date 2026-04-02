---
unit: 002-typescript-adk-agent
intent: 004-example-agents
phase: construction
status: complete
created: 2026-04-01T10:00:00Z
updated: 2026-04-02T10:00:00Z
---

# Unit Brief: TypeScript ADK Agent

## Purpose

Provide a complete, runnable TypeScript example agent using Google Agent Development Kit (ADK) that demonstrates the same multi-tool patterns as the Python agent. Proves Firma is SDK-agnostic — identical enforcement behavior with a completely different agent framework.

## Scope

### In Scope

- Agent definition with Google ADK
- 9 tools matching the Python agent: network (weather, IP info, fetch, post), database (SQL query), file (read, write), email (send), shell (execute)
- SQLite database with identical seed data
- Interactive session
- `.env.sample` with credential injection annotations
- Makefile with `install` and `run` targets (pnpm-based)
- `package.json` / `tsconfig.json` with minimal dependencies

### Out of Scope

- Firma sidecar configuration or proxy setup
- Production-grade error handling
- Tests
- Shared code with the Python agent

---

## Assigned Requirements

| FR | Requirement | Priority |
|----|-------------|----------|
| FR-2 | TypeScript Agent (Google ADK) | Must |
| FR-3 | Shared Seed Data | Must |
| FR-4 | Environment Configuration | Must |

---

## Domain Concepts

### Key Entities
| Entity | Description | Attributes |
|--------|-------------|------------|
| Agent | Google ADK agent instance | name, model, instructions, tools |
| Tool | ADK tool definition | name, description, parameters (Zod), execute |
| Database | SQLite DB seeded with products | path, seed SQL, better-sqlite3 instance |

### Key Operations
| Operation | Description | Inputs | Outputs |
|-----------|-------------|--------|---------|
| getWeather | Fetch weather from wttr.in | city name | formatted weather string |
| getIpInfo | Fetch IP geolocation | none (uses injected token) | IP info JSON |
| dbQuery | Execute SQL against SQLite | SQL string | JSON results or row count |
| readFile / writeFile | File I/O | path (+ content) | file contents or confirmation |
| sendEmail | Simulate email by writing to .data/emails/ | address, subject, body | confirmation |
| runShell | Execute shell command | command string | stdout + stderr |

---

## Story Summary

| Metric | Count |
|--------|-------|
| Total Stories | 3 |
| Must Have | 3 |

### Stories

| Story ID | Title | Priority | Status |
|----------|-------|----------|--------|
| 001-agent-scaffold | Agent scaffold and REPL | Must | Complete |
| 002-tool-definitions | Tool definitions | Must | Complete |
| 003-database-seed | Database seed and service | Must | Complete |

---

## Dependencies

### Depends On
None

### Depended By
None

### External Dependencies
| System | Purpose | Risk |
|--------|---------|------|
| Google AI API | LLM backend via ADK | Requires API key |
| wttr.in | Weather data | Free, no key needed |
| ipinfo.io | IP geolocation | Token injected by Firma |

---

## Technical Context

### Suggested Technology
- Node 20+, pnpm for dependency management
- Google ADK (`@google/adk` v0.6.1)
- `better-sqlite3` for SQLite
- `zod` for tool parameter schemas
- Native `fetch` for HTTP

### Data Storage
| Data | Type | Volume | Retention |
|------|------|--------|-----------|
| Products | SQLite | 10 rows (seed) | Session-local |
| Emails | Flat files | Per-session | Ephemeral |

---

## Constraints

- Must be self-contained under `example_agents/adk_js/`
- No imports from any Firma crate or workspace code
- Total source < 300 lines
- Feature-parity with Python agent (same tools, same seed data)

---

## Success Criteria

### Functional
- [x] `make install && make run` starts the agent
- [x] All 9 tools are callable and return sensible results
- [x] Database is auto-seeded on first run

### Quality
- [x] Code is readable without comments (self-documenting)
- [x] `.env.sample` documents all required variables

---

## Bolt Suggestions

| Bolt | Type | Stories | Objective |
|------|------|---------|-----------|
| 005-typescript-adk-agent | simple-construction-bolt | 001, 002, 003 | Complete TypeScript agent |

---

## Notes

The existing `agents_sdk_js/` directory on main uses OpenAI Agents SDK and is being replaced with a Google ADK implementation at `adk_js/`.
