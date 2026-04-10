---
unit: 004-llm-response-parser
intent: 006-sidecar-proxy-enforcement
phase: inception
status: draft
created: 2026-04-05T12:00:00Z
updated: 2026-04-05T12:00:00Z
---

# Unit Brief: LLM Response Parser

## Purpose

Implement response-path evaluation for LLM tool call instructions. Pluggable provider parsers detect tool calls in LLM API responses (both streaming SSE and non-streaming JSON), evaluate each through the enforcement pipeline, and rewrite denied calls to provider-native structured denial results that the agent runtime can consume.

## Scope

### In Scope

- `LlmResponseParser` trait with provider detection (automatic based on target host)
- OpenAI parser: `function_call` and `tool_calls` in streaming + non-streaming responses
- Anthropic parser: `tool_use` content blocks in streaming + non-streaming responses
- Gemini parser: `functionCall` in streaming + non-streaming responses
- SSE streaming: tool calls split across multiple chunks correctly reassembled
- On DENY (rewrite path): provider payload rewritten in-flight to structured denial result
- On DENY (synthesis path): provider-native tool-result message synthesized and injected
- On ALLOW: response forwarded byte-identical
- Unknown/unsupported providers: response forwarded without response-path evaluation
- Trait documented for community provider contributions

### Out of Scope

- Request-path enforcement (owned by 002-enforcement-pipeline via 001-proxy-core)
- Policy evaluation logic (owned by 002-enforcement-pipeline; this unit calls it)
- HTTP proxy transport (owned by 001-proxy-core; this unit is a Pingora response filter)

---

## Assigned Requirements

| FR | Requirement | Priority |
|----|-------------|----------|
| FR-7 | LLM Response Parser (Response-Path Evaluation) | Must |

---

## Domain Concepts

### Key Entities

| Entity | Description | Attributes |
|--------|-------------|------------|
| LlmResponseParser | Trait for provider-specific response parsing | provider_id, parse(), rewrite_denial() |
| ToolCallDetection | Extracted tool call from LLM response | tool_name, arguments, provider_format |
| DenialResult | Provider-native structured denial | firma_decision: DENY, reason, provider_format |
| SseBuffer | Buffer for reassembling chunked SSE events | chunks, complete_events, pending_data |

### Key Operations

| Operation | Description | Inputs | Outputs |
|-----------|-------------|--------|---------|
| detect_provider | Identify LLM provider from target host | Host header | Provider parser (or None) |
| parse_response | Extract tool calls from response | Response body (full or SSE chunks) | Vec<ToolCallDetection> |
| evaluate_tool_call | Run extracted tool call through enforcement | ToolCallDetection → ExecutionEnvelope | Decision |
| rewrite_denial | Replace denied tool call with structured denial | Original response, denied tool call | Modified response |
| synthesize_denial | Create provider-native denial result message | Denied tool call, reason | Injected denial message |

---

## Story Summary

| Metric | Count |
|--------|-------|
| Total Stories | 5 |
| Must Have | 5 |
| Should Have | 0 |
| Could Have | 0 |

### Stories

| Story ID | Title | Priority | Status |
|----------|-------|----------|--------|
| 001-openai-parser | OpenAI function_call/tool_calls, streaming + non-streaming | Must | Planned |
| 002-anthropic-parser | Anthropic tool_use blocks, streaming + non-streaming | Must | Planned |
| 003-gemini-parser | Gemini functionCall, streaming + non-streaming | Must | Planned |
| 004-sse-stream-reassembly | Chunked SSE reassembly for cross-chunk tool calls | Must | Planned |
| 005-denial-rewrite-synthesis | Provider-native denial result rewriting and synthesis | Must | Planned |

---

## Dependencies

### Depends On

| Unit | Reason |
|------|--------|
| 002-enforcement-pipeline | Extracted tool calls are evaluated through Stage 1 + Stage 2 |

### Depended By

| Unit | Reason |
|------|--------|
| 001-proxy-core | Integrated as Pingora response body filter |

### External Dependencies

| System | Purpose | Risk |
|--------|---------|------|
| OpenAI API format | Response format for tool_calls | Medium — format changes possible |
| Anthropic API format | Response format for tool_use | Medium — format changes possible |
| Gemini API format | Response format for functionCall | Medium — format changes possible |

---

## Technical Context

### Suggested Technology

- Pingora response body filter hooks
- serde_json for JSON parsing
- Custom SSE parser for streaming responses

### Integration Points

| Integration | Type | Protocol |
|-------------|------|----------|
| Enforcement Pipeline | Internal | Rust trait calls |
| Pingora Response Filter | Internal | ProxyHttp response hooks |
| LLM Provider APIs | External | HTTPS (response parsing) |

---

## Constraints

- Must handle both streaming (SSE `data:` events) and non-streaming (full JSON) responses
- Tool calls split across multiple SSE chunks must be correctly reassembled before evaluation
- On ALLOW: response must be forwarded byte-identical (zero modification)
- Provider detection is automatic based on target host
- Each parser must have comprehensive tests against recorded real LLM responses
- Both rewrite and synthesis denial paths must be tested independently

---

## Success Criteria

### Functional

- [ ] OpenAI parser detects function_call and tool_calls (streaming + non-streaming)
- [ ] Anthropic parser detects tool_use blocks (streaming + non-streaming)
- [ ] Gemini parser detects functionCall (streaming + non-streaming)
- [ ] SSE streaming: cross-chunk tool calls correctly reassembled
- [ ] On DENY: provider-native structured denial result returned to agent
- [ ] On ALLOW: response byte-identical to original
- [ ] Unknown providers: response forwarded without evaluation
- [ ] Trait documented for community contributions

### Non-Functional

- [ ] Minimal latency added to response path for non-tool-call responses
- [ ] Streaming responses not buffered entirely (parse incrementally where possible)

### Quality

- [ ] Tests against recorded real LLM responses for all 3 providers
- [ ] Tests with tool calls chunked at arbitrary byte boundaries
- [ ] Tests for multi-tool responses
- [ ] Both rewrite and synthesis denial paths tested independently

---

## Bolt Suggestions

| Bolt | Type | Stories | Objective |
|------|------|---------|-----------|
| 011-llm-response-parser | DDD | 001, 002, 003, 004, 005 | Full LLM response parser with all providers |

---

## Notes

- This is the most technically treacherous unit — SSE streaming with in-flight rewriting is high risk
- Recorded real LLM responses are essential test fixtures; cannot rely on mocked formats
- Provider API format changes are a maintenance concern — trait abstraction helps but doesn't eliminate it
- The response parser operates as a Pingora response body filter, which has its own lifecycle constraints
