# Agents

This project uses the **specsmd AI-DLC** (AI-Driven Development Life Cycle) workflow for structured feature development. The workflow is organized into phases, each managed by a specialized agent.

## Available Agents

### Inception Agent

Plans features by gathering requirements, defining system context, decomposing into units, creating stories, and planning construction bolts.

```
/specsmd-inception-agent --intent="{intent-name}"
```

**Skills**: create-intent, list-intents, requirements, context, units, stories, bolt-plan, review

### Construction Agent

Executes bolts through DDD stages: domain model, technical design, implementation, and testing.

```
/specsmd-construction-agent --unit="{unit-name}" --bolt-id="{bolt-id}"
```

### Master Agent

Routes requests to the appropriate phase agent based on project state.

```
/specsmd-master-agent
```

### Operations Agent

Handles build, deploy, verify, and monitor tasks.

```
/specsmd-operations-agent
```

## Memory Bank

All artifacts live under `memory-bank/`:

- `intents/` — Feature definitions, requirements, units, stories
- `bolts/` — Execution instances with stage artifacts
- `standards/` — Project-wide tech stack, coding standards, architecture
- `project.yaml` — Project type and initialization metadata

## Workflow

```
Inception → Construction → Operations
   │              │              │
   ├─ Requirements ├─ Domain Model ├─ Build
   ├─ Context      ├─ Tech Design  ├─ Deploy
   ├─ Units        ├─ Implement    ├─ Verify
   ├─ Stories      └─ Test         └─ Monitor
   └─ Bolt Plan
```

IMPORTANT: always check the "context" folder before starting producing any artifact.

IMPORTANT: always run `make check` before presenting implementation as complete. This runs fmt, clippy, and tests. CI will fail if this doesn't pass locally.
