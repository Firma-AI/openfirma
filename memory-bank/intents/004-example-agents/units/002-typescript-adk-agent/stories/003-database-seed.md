---
intent: 004-example-agents
unit: 002-typescript-adk-agent
story: 003-database-seed
status: complete
priority: Must
complexity: 1
uncertainty: 1
dependencies: 0
---

# Story: Database Seed and Service

## User Story

**As a** developer evaluating Firma
**I want** the same pre-seeded SQLite database as the Python agent
**So that** I can verify identical query results across SDKs

## Acceptance Criteria

- [x] `seed.sql` identical to Python agent's seed data (10-row products table)
- [x] `src/services/database.ts` provides `getDb()` with lazy init and `initializeDatabase()`
- [x] Database stored at `.data/firma.db` (gitignored)
- [x] `.data/` directory auto-created if missing
- [x] WAL journal mode enabled for better concurrency
- [x] Seed runs automatically on first agent startup

## Notes

Same seed data as Python agent. Uses `better-sqlite3` for synchronous native SQLite access.
