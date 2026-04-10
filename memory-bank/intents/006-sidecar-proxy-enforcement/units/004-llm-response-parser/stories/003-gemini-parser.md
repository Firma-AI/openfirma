---
id: 003-gemini-parser
unit: 004-llm-response-parser
intent: 006-sidecar-proxy-enforcement
status: draft
priority: must
created: 2026-04-05T12:00:00Z
assigned_bolt: null
implemented: false
---

# Story: 003-gemini-parser

## User Story

**As the** response-path evaluator
**I want to** detect Gemini functionCall instructions in both streaming and non-streaming responses
**So that** each tool call can be independently evaluated by the enforcement pipeline

## Acceptance Criteria

- [ ] **Given** a non-streaming Gemini API response containing `functionCall` objects within `candidates[].content.parts[]`, **When** the response body is parsed, **Then** the parser extracts each function call (name, args) as an independent `ToolCallDetection`
- [ ] **Given** a streaming Gemini API response (newline-delimited JSON array) containing `functionCall` parts across streamed chunks, **When** the chunks are processed incrementally, **Then** the parser detects and extracts each function call as a `ToolCallDetection`
- [ ] **Given** an outbound request whose target host is `generativelanguage.googleapis.com`, **When** the response arrives, **Then** the Gemini parser is automatically selected via provider detection (no manual configuration required)
- [ ] **Given** recorded real Gemini API responses (both streaming and non-streaming, single and multi-function), **When** the parser is run against each fixture, **Then** all function calls are correctly detected with matching names and arguments

## Technical Notes

- Gemini's response structure differs significantly from OpenAI and Anthropic. The response contains `candidates[]`, each with `content.parts[]`. Each part may be a `text` part or a `functionCall` part. A `functionCall` part has `name` (string) and `args` (object).
- Non-streaming: the full JSON body contains the complete `candidates` array. Parse `candidates[0].content.parts[]` and extract entries where `functionCall` is present.
- Streaming: Gemini uses a different streaming format than OpenAI/Anthropic. Instead of SSE `data:` lines, Gemini streams a JSON array where each element is a `GenerateContentResponse`. The stream opens with `[`, individual response objects are separated by commas and newlines, and the stream closes with `]`. Each streamed object may contain partial or complete `functionCall` parts.
- In practice, Gemini tends to deliver `functionCall` parts as complete objects within a single streamed array element rather than splitting them across elements. However, the parser must handle the case where the JSON array element itself is split across HTTP chunks (handled by story 004).
- Provider detection: match target host against `generativelanguage.googleapis.com`. Consider also matching `aiplatform.googleapis.com` for Vertex AI Gemini endpoints.
- Implement as a struct implementing the `LlmResponseParser` trait defined in story 005.
- Test fixtures needed: single functionCall (non-streaming), multiple functionCall parts (non-streaming), single functionCall (streaming), multiple functionCall (streaming), mixed text + functionCall parts.

## Dependencies

### Requires

- 004-sse-stream-reassembly (chunk reassembly logic adapted for Gemini's JSON array streaming format)
- 005-denial-rewrite-synthesis (`LlmResponseParser` trait definition; `ToolCallDetection` type)

### Enables

- 005-denial-rewrite-synthesis (Gemini-specific denial result format for rewrite/synthesis paths)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Response contains only `text` parts (no function calls) | Parser returns empty `Vec<ToolCallDetection>`; response forwarded unchanged |
| Response contains mixed `text` and `functionCall` parts in the same `content.parts` array | Only `functionCall` parts extracted; text parts ignored |
| `functionCall` with empty `args` object (`{}`) | Parsed as valid function call with no arguments |
| Multiple candidates in the response (n > 1 generation) | Only `candidates[0]` is parsed (consistent with single-candidate enforcement model) |
| `finishReason: "STOP"` with no function calls | No tool calls detected; response forwarded unchanged |
| Streaming: JSON array element split across HTTP chunks | Deferred to story 004 (chunk reassembly); this parser assumes complete JSON objects |
| Gemini returns an error response (HTTP 4xx/5xx with error JSON) | Parser detects error status; skips function call detection; forwards error response unchanged |
| `functionCall` with `args` containing nested objects and arrays | Args preserved as-is; parser does not interpret argument structure beyond JSON validity |
| Response from Vertex AI endpoint (`aiplatform.googleapis.com`) | Provider detected if host matching is configured; same parser logic applies |
| `functionCall` part with missing `name` field | Treated as malformed; logged as warning; skipped (not emitted as ToolCallDetection) |
| Streaming response with `promptFeedback` block (safety filter) before candidates | `promptFeedback` ignored; parser only inspects `candidates` content |

## Out of Scope

- Evaluation of extracted function calls through the enforcement pipeline (handled by unit 002 integration)
- Denial result rewriting/synthesis for Gemini format (story 005)
- Byte-boundary chunk reassembly for Gemini's JSON array stream (story 004)
- Gemini's code execution tool results (V1 targets function calling only)
- Gemini grounding metadata and search results
- Google AI Studio vs. Vertex AI authentication differences (handled at credential injection layer, unit 005)
