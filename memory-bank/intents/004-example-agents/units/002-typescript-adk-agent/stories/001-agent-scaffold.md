---
intent: 004-example-agents
unit: 002-typescript-adk-agent
story: 001-agent-scaffold
status: planned
priority: Must
complexity: 1
uncertainty: 1
dependencies: 0
---

# Story: Agent Scaffold and REPL

## User Story

**As a** developer evaluating Firma
**I want** a runnable TypeScript agent with an interactive session
**So that** I can see how a Google ADK agent works end-to-end

## Acceptance Criteria

- [ ] `package.json` with `@google/adk` v0.6.1, `better-sqlite3`, `zod` dependencies
- [ ] `src/main.ts` defines the agent with name, model, instructions, and tool list
- [ ] Interactive session starts with `pnpm start`
- [ ] Makefile with `install` (pnpm install) and `run` targets
- [ ] `.env.sample` with Google AI API key and `IPINFO_TOKEN` documented
- [ ] `tsconfig.json` configured for ESM output

## Notes

Agent uses Google's model via ADK. Interactive loop may use readline or ADK-provided session management.
