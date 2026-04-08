---
id: 002-anthropic-parser
unit: 004-llm-response-parser
intent: 006-sidecar-proxy-enforcement
status: draft
priority: must
created: 2026-04-05T12:00:00Z
assigned_bolt: null
implemented: false
---

# Story: 002-anthropic-parser

## User Story

**As the** response-path evaluator
**I want to** detect Anthropic tool_use content blocks in both streaming and non-streaming responses
**So that** each tool call can be independently evaluated by the enforcement pipeline

## Acceptance Criteria

- [ ] **Given** a non-streaming Anthropic API response containing one or more `tool_use` content blocks in the `content` array, **When** the response body is parsed, **Then** the parser extracts each tool_use block (id, name, input) as an independent `ToolCallDetection`
- [ ] **Given** a streaming Anthropic API response with `content_block_start` events of type `tool_use`, **When** the SSE events are processed incrementally, **Then** the parser recognizes the start of each tool call and begins accumulating its input data
- [ ] **Given** a streaming Anthropic API response with `content_block_delta` events containing `input_json_delta` fragments, **When** the deltas are processed, **Then** the parser accumulates JSON fragments and produces a complete `ToolCallDetection` upon receiving the corresponding `content_block_stop` event
- [ ] **Given** an outbound request whose target host is `api.anthropic.com`, **When** the response arrives, **Then** the Anthropic parser is automatically selected via provider detection (no manual configuration required)
- [ ] **Given** recorded real Anthropic API responses (both streaming and non-streaming, single and multi-tool), **When** the parser is run against each fixture, **Then** all tool calls are correctly detected with matching names and input objects

## Technical Notes

- Anthropic uses a content-block model: the response `content` array may contain interleaved `text` and `tool_use` blocks. Only `tool_use` blocks are relevant for enforcement.
- Non-streaming responses: parse `content[]` where `type == "tool_use"`. Each block has `id`, `name`, and `input` (an object, not a string).
- Streaming responses use a distinct event structure from OpenAI:
  - `content_block_start` with `content_block.type == "tool_use"` signals a new tool call, providing `id` and `name`.
  - `content_block_delta` with `delta.type == "input_json_delta"` provides incremental JSON string fragments in `delta.partial_json`.
  - `content_block_stop` signals the end of the current content block; the parser should finalize the accumulated JSON and emit the `ToolCallDetection`.
- The parser must track content blocks by index to correctly associate deltas with their originating block, since multiple tool_use blocks can be interleaved with text blocks.
- Provider detection: match target host against `api.anthropic.com`.
- Implement as a struct implementing the `LlmResponseParser` trait defined in story 005.
- Test fixtures needed: single tool_use (non-streaming), multiple tool_use (non-streaming), single tool_use (streaming), multiple tool_use (streaming), mixed text + tool_use (both modes).

## Dependencies

### Requires

- 004-sse-stream-reassembly (SSE chunk reassembly logic used by streaming path)
- 005-denial-rewrite-synthesis (`LlmResponseParser` trait definition; `ToolCallDetection` type)

### Enables

- 005-denial-rewrite-synthesis (Anthropic-specific denial result format for rewrite/synthesis paths)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Response contains only `text` content blocks (no tool calls) | Parser returns empty `Vec<ToolCallDetection>`; response forwarded unchanged |
| Response contains mixed `text` and `tool_use` blocks interleaved | Only `tool_use` blocks extracted; text blocks ignored; block ordering preserved |
| `tool_use` block with empty `input` object (`{}`) | Parsed as valid tool call with no arguments |
| Streaming: `input_json_delta` fragments that form invalid JSON when concatenated prematurely | Parser buffers all fragments until `content_block_stop`; only then attempts JSON parse |
| Streaming: `content_block_stop` arrives without any prior `input_json_delta` events for a tool_use block | Tool call emitted with empty input (`{}`) |
| Anthropic returns an `error` response (type `"error"`) | Parser detects error type; skips tool call detection; forwards error response unchanged |
| Response has `stop_reason: "tool_use"` but the content array is empty | No tool calls detected; response forwarded unchanged |
| Streaming: multiple `tool_use` blocks in a single response, interleaved at the content block level | Each block tracked independently by index; all emitted as separate `ToolCallDetection` entries |
| `tool_use` block with deeply nested `input` object | Input preserved as-is; parser does not interpret input structure beyond JSON validity |
| Response uses an unexpected content block type (e.g., future `image` type) | Unknown block types ignored; no error raised |

## Out of Scope

- Evaluation of extracted tool calls through the enforcement pipeline (handled by unit 002 integration)
- Denial result rewriting/synthesis for Anthropic format (story 005)
- SSE byte-boundary reassembly (story 004; this story assumes well-formed SSE events)
- Anthropic batch API responses (V1 targets the Messages API real-time endpoint only)
- Anthropic extended thinking blocks (not relevant to tool call detection)
