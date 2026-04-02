---
intent: 004-example-agents
unit: 002-typescript-adk-agent
story: 002-tool-definitions
status: planned
priority: Must
complexity: 1
uncertainty: 1
dependencies: 0
---

# Story: Tool Definitions

## User Story

**As a** developer evaluating Firma
**I want** feature-parity tools in TypeScript matching the Python agent
**So that** I can compare SDK experiences and confirm Firma works identically

## Acceptance Criteria

- [ ] `src/tools/network.ts` — `getWeather`, `getIpInfo`, `fetchUrl`, `postData` (native fetch)
- [ ] `src/tools/database.ts` — `dbQuery` (SELECT returns JSON, mutations return row count)
- [ ] `src/tools/file.ts` — `readFile`, `writeFile` (creates parent dirs)
- [ ] `src/tools/email.ts` — `sendEmail` (writes to `.data/emails/`)
- [ ] `src/tools/shell.ts` — `runShell` (30s timeout, captures stdout+stderr)
- [ ] `src/tools/index.ts` re-exports all tools
- [ ] All tools use Zod schemas for parameter validation

## Notes

`getIpInfo` demonstrates credential injection — `IPINFO_TOKEN` is injected by Firma sidecar. Uses `better-sqlite3` (synchronous native driver) instead of SQLAlchemy.
