---
intent: 004-example-agents
unit: 001-python-openai-agent
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
**I want** a pre-seeded SQLite database with sample data
**So that** the `db_query` tool has data to query immediately on first run

## Acceptance Criteria

- [x] `seed.sql` creates `products` table with 10 rows (Electronics, Furniture, Office Supplies)
- [x] `agent/services/database.py` provides `get_engine()` with lazy init and `initialize_database()`
- [x] Database stored at `.data/firma.db` (gitignored)
- [x] `.data/` directory auto-created if missing
- [x] Seed runs automatically on first agent startup

## Notes

Same seed data used in both Python and TypeScript agents for consistency.
