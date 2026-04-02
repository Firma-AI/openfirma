---
intent: 004-example-agents
unit: 001-python-openai-agent
story: 001-agent-scaffold
status: complete
priority: Must
complexity: 1
uncertainty: 1
dependencies: 0
---

# Story: Agent Scaffold and REPL

## User Story

**As a** developer evaluating Firma
**I want** a runnable Python agent with an interactive REPL
**So that** I can see how an OpenAI Agents SDK agent works end-to-end

## Acceptance Criteria

- [x] `pyproject.toml` with `openai-agents`, `httpx`, `sqlalchemy` dependencies
- [x] `agent/main.py` defines the agent with name, model, instructions, and tool list
- [x] `agent/__init__.py` exists for package structure
- [x] Interactive REPL starts with `uv run python -m agent.main`
- [x] Makefile with `install` (uv sync) and `run` targets
- [x] `.env.sample` with `OPENAI_API_KEY`, `IPINFO_TOKEN` documented

## Notes

Agent uses `gpt-4.1` model. REPL is provided by the SDK's `run_demo_loop`.
