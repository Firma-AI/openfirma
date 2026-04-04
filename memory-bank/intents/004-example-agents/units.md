---
intent: 004-example-agents
phase: inception
status: units-decomposed
updated: 2026-04-01T10:00:00Z
---

# Example Agents - Unit Decomposition

## Units Overview

This intent decomposes into 2 units of work:

### Unit 1: 001-python-openai-agent

**Description**: Python example agent using the OpenAI Agents SDK (`openai-agents`). Interactive REPL with 9 tools across 5 categories (network, database, file, email, shell). Uses uv for dependency management, SQLite for data, httpx for async HTTP.

**Stories**:

- Story-001: Agent scaffold and REPL
- Story-002: Tool definitions
- Story-003: Database seed and service

**Deliverables**:

- `example_agents/agents_sdk_py/` — complete, runnable agent project

**Dependencies**:

- Depends on: None
- Depended by: None (independent of Unit 2)

**Estimated Complexity**: S

### Unit 2: 002-typescript-adk-agent

**Description**: TypeScript example agent using Google Agent Development Kit (ADK). Feature-parity with the Python agent — same tool categories, same seed data, same interactive experience. Uses pnpm for dependency management, better-sqlite3 for data, native fetch for HTTP.

**Stories**:

- Story-001: Agent scaffold and REPL
- Story-002: Tool definitions
- Story-003: Database seed and service

**Deliverables**:

- `example_agents/adk_js/` — complete, runnable agent project

**Dependencies**:

- Depends on: None
- Depended by: None (independent of Unit 1)

**Estimated Complexity**: S

## Unit Dependency Graph

```text
[001-python-openai-agent]     [002-typescript-adk-agent]
        (independent — can be built in parallel)
```

## Execution Order

Both units are independent and can be built in any order or in parallel.

1. Unit 001: Python OpenAI Agent
2. Unit 002: TypeScript ADK Agent
