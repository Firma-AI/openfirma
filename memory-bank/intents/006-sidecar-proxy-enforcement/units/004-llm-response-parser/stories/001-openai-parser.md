---
id: 001-openai-parser
unit: 004-llm-response-parser
intent: 006-sidecar-proxy-enforcement
status: draft
priority: must
created: 2026-04-05T12:00:00Z
assigned_bolt: null
implemented: false
---

# Story: 001-openai-parser

## User Story

**As the** response-path evaluator
**I want to** detect OpenAI tool call instructions in Responses API and Chat Completions API responses (both streaming and non-streaming)
**So that** each tool call can be independently evaluated by the enforcement pipeline

## Acceptance Criteria

- [ ] **Given** a non-streaming Responses API response containing `output` items with `type: "function_call"`, **When** the response body is parsed, **Then** the parser extracts each function call (call_id, name, arguments) as an independent `ToolCallDetection`
- [ ] **Given** a streaming Responses API response (SSE events with types `response.output_item.added`, `response.function_call_arguments.delta`, `response.function_call_arguments.done`), **When** the events are processed incrementally, **Then** the parser accumulates argument deltas per call_id and produces a complete `ToolCallDetection` on the `done` event
- [ ] **Given** a non-streaming Chat Completions API response containing a `tool_calls` array in the assistant message, **When** the response body is parsed, **Then** the parser extracts each tool call (id, function name, arguments) as an independent `ToolCallDetection`
- [ ] **Given** a streaming Chat Completions API response containing `tool_calls` delta fragments across multiple SSE `data:` events, **When** the events are processed, **Then** each tool call is independently reassembled by `index` and yielded as a separate `ToolCallDetection`
- [ ] **Given** a non-streaming Chat Completions API response containing the legacy `function_call` field, **When** the response body is parsed, **Then** the parser extracts the function name and arguments as a `ToolCallDetection`
- [ ] **Given** an outbound request whose target host is `api.openai.com`, **When** the response arrives, **Then** the OpenAI parser is automatically selected via provider detection (no manual configuration required)
- [ ] **Given** the OpenAI parser is selected, **When** the response path is `/v1/responses`, **Then** the Responses API parsing logic is used; **When** the path is `/v1/chat/completions`, **Then** the Chat Completions parsing logic is used
- [ ] **Given** recorded real OpenAI API responses (Responses API and Chat Completions API, both streaming and non-streaming, single and multi-tool), **When** the parser is run against each fixture, **Then** all tool calls are correctly detected with matching names and arguments

## Technical Notes

- **Responses API** (`/v1/responses`) is the primary OpenAI API surface. Tool calls appear as `output` items with `type: "function_call"` containing `call_id`, `name`, and `arguments`. Streaming uses typed SSE events: `response.output_item.added` (signals a new function call), `response.function_call_arguments.delta` (argument fragments), and `response.function_call_arguments.done` (complete arguments). The parser must accumulate argument deltas per `call_id` and emit on the `done` event.
- **Chat Completions API** (`/v1/chat/completions`) remains supported. Two formats: the legacy `function_call` (single function, deprecated but still in use) and the current `tool_calls` array (supports parallel tool calling). Non-streaming: parse `choices[0].message.tool_calls` and `choices[0].message.function_call`. Streaming: `ChatCompletionChunk` with `choices[0].delta` containing partial `tool_calls` or `function_call` fragments; accumulate by `index` field; emit on `finish_reason` or `[DONE]`.
- **API path detection**: use the request path to select parsing mode — `/v1/responses` uses Responses API logic, `/v1/chat/completions` uses Chat Completions logic. Fall back to Chat Completions parsing if path is ambiguous.
- Provider detection: match target host against `api.openai.com`. Consider also matching custom OpenAI-compatible endpoints if an `x-openai-*` header is present, but default to host-based detection for V1.
- Implement as a struct implementing the `LlmResponseParser` trait defined in story 005.
- Test fixtures should be recorded from actual OpenAI API calls and stored as files in the test data directory. Fixtures needed: Responses API single function_call (non-streaming), Responses API multiple function_calls (non-streaming), Responses API streaming, Chat Completions single tool_calls (non-streaming), Chat Completions multiple tool_calls (non-streaming), Chat Completions streaming, legacy function_call (non-streaming).

## Dependencies

### Requires

- 004-sse-stream-reassembly (SSE chunk reassembly logic used by streaming path)
- 005-denial-rewrite-synthesis (`LlmResponseParser` trait definition; `ToolCallDetection` type)

### Enables

- 005-denial-rewrite-synthesis (OpenAI-specific denial result format for rewrite/synthesis paths)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Response contains no tool calls (plain text completion) | Parser returns empty `Vec<ToolCallDetection>`; response forwarded unchanged |
| Responses API: multiple `function_call` output items in one response | Each extracted as independent `ToolCallDetection` |
| Responses API: streaming `response.function_call_arguments.delta` with empty string | Accumulated as no-op; does not corrupt buffer |
| Responses API: `response.output_item.added` for non-function-call type (e.g. `message`) | Ignored by parser; only `function_call` type items processed |
| Chat Completions: response contains both `function_call` and `tool_calls` | Both extracted; each yields independent `ToolCallDetection` entries |
| Chat Completions: `tool_calls` array with a single element | Treated identically to multi-element array; one `ToolCallDetection` yielded |
| Streaming response with `arguments` split mid-JSON across deltas | Parser accumulates argument fragments; only emits when complete |
| Streaming response with `[DONE]` event | Parser finalizes any in-progress tool calls and emits them |
| `function_call` with empty arguments (`""` or `"{}"`) | Parsed as valid tool call with empty/no arguments |
| Malformed JSON in `arguments` field (non-JSON string) | Tool call still detected; arguments passed through as raw string for enforcement to evaluate |
| OpenAI returns an error response (4xx/5xx) | Parser detects non-success status; skips tool call detection; forwards error response unchanged |
| Request path doesn't match `/v1/responses` or `/v1/chat/completions` | Falls back to Chat Completions parsing logic |

## Out of Scope

- Evaluation of extracted tool calls through the enforcement pipeline (handled by unit 002 integration)
- Denial result rewriting/synthesis for OpenAI format (story 005)
- SSE byte-boundary reassembly (story 004; this story assumes well-formed SSE events)
- OpenAI-compatible third-party providers (e.g., Azure OpenAI, local models with OpenAI-compatible APIs) beyond basic host detection
- OpenAI Realtime API (WebSocket-based) tool call format
