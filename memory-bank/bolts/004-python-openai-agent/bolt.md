---
id: 004-python-openai-agent
unit: 001-python-openai-agent
intent: 004-example-agents
type: simple-construction-bolt
status: complete
stories:
  - 001-agent-scaffold
  - 002-tool-definitions
  - 003-database-seed
created: 2026-04-01T10:00:00Z
started: 2026-04-01T11:00:00Z
completed: 2026-04-01T12:00:00Z
current_stage: null
stages_completed:
  - name: plan
    completed: 2026-04-01T11:00:00Z
  - name: implement
    completed: 2026-04-01T11:30:00Z
  - name: validate
    completed: 2026-04-01T12:00:00Z
requires_bolts: []
enables_bolts: []
requires_units: []
blocks: false
complexity:
  avg_complexity: 1
  avg_uncertainty: 1
  max_dependencies: 0
  testing_scope: 1
---

# Bolt: 004-python-openai-agent

## Overview

Build the complete Python example agent using the OpenAI Agents SDK with all tools, database seed, and interactive REPL.

## Objective

Deliver a self-contained, runnable Python agent at `example_agents/agents_sdk_py/` that demonstrates multi-tool AI agent patterns for Firma users.

## Stories Included

- **001-agent-scaffold**: Agent definition, REPL, Makefile, .env.sample (Must)
- **002-tool-definitions**: 9 tools across 5 categories (Must)
- **003-database-seed**: SQLite seed data and database service (Must)

## Bolt Type

**Type**: Simple Construction Bolt
**Definition**: `.specsmd/aidlc/templates/construction/bolt-types/simple-construction-bolt.md`

## Stages

- [x] **1. plan**: Implementation plan
- [x] **2. implement**: Write all source files
- [x] **3. validate**: Verify `make install && make run` works

## Dependencies

### Requires
- None

### Enables
- None (independent)

## Success Criteria

- [x] `make install` completes without errors
- [x] `make run` starts interactive REPL
- [x] All 9 tools registered with agent
- [x] Database auto-seeds on first run
- [x] `.env.sample` documents all required variables
