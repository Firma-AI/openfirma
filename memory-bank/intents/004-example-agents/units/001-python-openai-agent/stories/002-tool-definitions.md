---
intent: 004-example-agents
unit: 001-python-openai-agent
story: 002-tool-definitions
status: complete
priority: Must
complexity: 1
uncertainty: 1
dependencies: 0
---

# Story: Tool Definitions

## User Story

**As a** developer evaluating Firma
**I want** a diverse set of agent tools covering common I/O patterns
**So that** I can see how Firma enforces and injects credentials across different tool types

## Acceptance Criteria

- [x] `agent/tools/network.py` — `get_weather`, `get_ip_info`, `fetch_url`, `post_data`
- [x] `agent/tools/database.py` — `db_query` (SELECT returns JSON, mutations return row count)
- [x] `agent/tools/file.py` — `read_file`, `write_file` (creates parent dirs)
- [x] `agent/tools/email.py` — `send_email` (writes to `.data/emails/`)
- [x] `agent/tools/shell.py` — `run_shell` (30s timeout, captures stdout+stderr)
- [x] `agent/tools/__init__.py` re-exports all tools
- [x] All tools use Python type hints for parameter schemas

## Notes

`get_ip_info` demonstrates credential injection — `IPINFO_TOKEN` is injected by Firma sidecar, not hardcoded in agent code.
