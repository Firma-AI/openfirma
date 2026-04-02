---
intent: 004-example-agents
phase: inception
status: complete
created: 2026-04-01T10:00:00Z
updated: 2026-04-02T10:00:00Z
---

# Requirements: Example Agents

## Intent Overview

Provide two fully working example agents — one in Python (OpenAI Agents SDK) and one in TypeScript (Google ADK) — that demonstrate how AI agents integrate with Firma without any agent-side code changes. The agents use common tool patterns (HTTP, database, file I/O, shell, email) that exercise Firma's enforcement and credential-injection capabilities. These examples serve as the primary onboarding material for users evaluating or adopting Firma.

## Business Goals

| Goal | Success Metric | Priority |
|------|----------------|----------|
| Demonstrate SDK-agnostic enforcement | Both agents work identically through Firma sidecar with zero agent code changes | Must |
| Provide copy-paste starting points | Each agent runs standalone with `make run` after env setup | Must |
| Exercise diverse tool patterns | At least 5 tool categories (network, DB, file, shell, email) per agent | Must |
| Show credential injection | At least one tool per agent uses a secret injected by infrastructure, not hardcoded | Should |

---

## Functional Requirements

### FR-1: Python Agent (OpenAI Agents SDK)
- **Description**: A Python agent using `openai-agents` with tools for weather lookup, IP info, URL fetch/post, SQL database queries, file read/write, email send, and shell execution
- **Acceptance Criteria**: `make install && make run` starts an interactive REPL; all tools callable by the agent
- **Priority**: Must
- **Related Stories**: 001-agent-scaffold, 002-tool-definitions, 003-database-seed

### FR-2: TypeScript Agent (Google ADK)
- **Description**: A TypeScript agent using Google Agent Development Kit with feature-parity tools matching the Python agent
- **Acceptance Criteria**: `make install && make run` starts an interactive session; all tools callable by the agent
- **Priority**: Must
- **Related Stories**: 001-agent-scaffold, 002-tool-definitions, 003-database-seed

### FR-3: Shared Seed Data
- **Description**: Both agents use an identical SQLite seed schema (products table) so behavior is comparable across SDKs
- **Acceptance Criteria**: Same `seed.sql` content produces identical query results in both agents
- **Priority**: Must

### FR-4: Environment Configuration
- **Description**: Each agent includes a `.env.sample` documenting required environment variables (API keys, tokens) with comments explaining which are injected by Firma
- **Acceptance Criteria**: `.env.sample` exists with all required vars and injection annotations
- **Priority**: Must

---

## Non-Functional Requirements

### Simplicity
| Requirement | Metric | Target |
|-------------|--------|--------|
| Lines of code per agent | Total source lines | < 300 |
| Dependencies | Direct deps | < 10 per agent |
| Setup steps | Commands to run | 2 (install + run) |

### Portability
| Requirement | Metric | Target |
|-------------|--------|--------|
| Python version | Minimum | 3.12+ |
| Node version | Minimum | 20+ |
| OS support | Platforms | macOS, Linux |

---

## Constraints

### Technical Constraints

**Intent-specific constraints**:
- No Firma crate changes — examples live entirely under `example_agents/`
- Each agent is self-contained with its own dependency management (uv for Python, pnpm for TS)
- No shared code between the two agents — they are independent demonstrations

### Business Constraints
- Examples must be understandable by developers unfamiliar with Firma internals
- Tool implementations should be simple enough to read in 5 minutes

---

## Assumptions

| Assumption | Risk if Invalid | Mitigation |
|------------|-----------------|------------|
| Users have API keys for the respective SDK (OpenAI / Google) | Agent won't start | Clear error message + .env.sample docs |
| SQLite is available on target platform | DB tools fail | SQLite is bundled with Python and available via npm packages |
| Firma sidecar is running for enforcement demo | Tools work but without enforcement | Document that standalone mode works for development, sidecar mode for enforcement |

---

## Open Questions

| Question | Owner | Due Date | Resolution |
|----------|-------|----------|------------|
| None | — | — | — |
