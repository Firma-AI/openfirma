---
id: 005-typescript-adk-agent
unit: 002-typescript-adk-agent
intent: 004-example-agents
type: simple-construction-bolt
status: planned
stories:
  - 001-agent-scaffold
  - 002-tool-definitions
  - 003-database-seed
created: 2026-04-01T10:00:00Z
started: null
completed: null
current_stage: null
stages_completed: []
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

# Bolt: 005-typescript-adk-agent

## Overview

Build the complete TypeScript example agent using Google ADK with feature-parity tools, database seed, and interactive session.

## Objective

Deliver a self-contained, runnable TypeScript agent at `example_agents/adk_js/` that proves Firma is SDK-agnostic by matching the Python agent's capabilities with a completely different framework.

## Stories Included

- **001-agent-scaffold**: Agent definition, session loop, Makefile, .env.sample (Must)
- **002-tool-definitions**: 9 tools with Zod schemas across 5 categories (Must)
- **003-database-seed**: SQLite seed data and database service (Must)

## Bolt Type

**Type**: Simple Construction Bolt
**Definition**: `.specsmd/aidlc/templates/construction/bolt-types/simple-construction-bolt.md`

## Stages

- [ ] **1. plan**: Implementation plan
- [ ] **2. implement**: Write all source files
- [ ] **3. validate**: Verify `make install && make run` works

## Dependencies

### Requires
- None

### Enables
- None (independent)

## Success Criteria

- [ ] `make install` completes without errors
- [ ] `make run` starts interactive session
- [ ] All 9 tools registered with agent
- [ ] Database auto-seeds on first run
- [ ] `.env.sample` documents all required variables
- [ ] Tool output matches Python agent for same inputs
