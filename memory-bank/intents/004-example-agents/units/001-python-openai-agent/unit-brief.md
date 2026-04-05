---
unit: 001-python-openai-agent
intent: 004-example-agents
phase: construction
status: complete
created: 2026-04-01T10:00:00Z
updated: 2026-04-02T10:00:00Z
---

# Unit Brief: Python OpenAI Agent

## Purpose

Provide a complete, runnable Python example agent using the OpenAI Agents SDK that demonstrates multi-tool AI agent patterns. Serves as a reference implementation for users integrating Python-based agents with Firma.

## Scope

### In Scope

- Agent definition with OpenAI Agents SDK (`openai-agents`, model `gpt-4.1`)
- 9 tools across 5 categories: network (weather, IP info, fetch, post), database (SQL query), file (read, write), email (send), shell (execute)
- SQLite database with seed data (products table)
- Interactive REPL loop via SDK
- `.env.sample` with credential injection annotations
- Makefile with `install` and `run` targets (uv-based)
- `pyproject.toml` with minimal dependencies

### Out of Scope

- Firma sidecar configuration or proxy setup
- Production-grade error handling or retry logic
- Async streaming of tool results
- Tests (these are examples, not library code)

---

## Assigned Requirements

| FR | Requirement | Priority |
|----|-------------|----------|
| FR-1 | Python Agent (OpenAI Agents SDK) | Must |
| FR-3 | Shared Seed Data | Must |
| FR-4 | Environment Configuration | Must |

---

## Domain Concepts

### Key Entities
| Entity | Description | Attributes |
|--------|-------------|------------|
| Agent | OpenAI Agents SDK agent instance | name, model, instructions, tools |
| Tool | Function callable by the agent | name, parameters, execute function |
| Database | SQLite DB seeded with products | path, seed SQL, engine |

### Key Operations
| Operation | Description | Inputs | Outputs |
|-----------|-------------|--------|---------|
| get_weather | Fetch weather from wttr.in | city name | formatted weather string |
| get_ip_info | Fetch IP geolocation | none (uses injected token) | IP info JSON |
| db_query | Execute SQL against SQLite | SQL string | JSON results or row count |
| read_file / write_file | File I/O | path (+ content) | file contents or confirmation |
| send_email | Simulate email by writing to .data/emails/ | address, subject, body | confirmation |
| run_shell | Execute shell command | command string | stdout + stderr |

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
| OpenAI API | LLM backend | Requires API key |
| wttr.in | Weather data | Free, no key needed |
| ipinfo.io | IP geolocation | Token injected by Firma |

---

## Technical Context

### Suggested Technology
- Python 3.12+, uv for dependency management
- `openai-agents` SDK
- `httpx` for async HTTP
- `sqlalchemy` for SQLite access

### Data Storage
| Data | Type | Volume | Retention |
|------|------|--------|-----------|
| Products | SQLite | 10 rows (seed) | Session-local |
| Emails | Flat files | Per-session | Ephemeral |

---

## Constraints

- Must be self-contained under `example_agents/agents_sdk_py/`
- No imports from any Firma crate or workspace code
- Total source < 300 lines

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
| 004-python-openai-agent | simple-construction-bolt | 001, 002, 003 | Complete Python agent |

---

## Notes

Implementation is already complete on branch `intent-004/example-agents`. This inception documents the existing work retroactively.
