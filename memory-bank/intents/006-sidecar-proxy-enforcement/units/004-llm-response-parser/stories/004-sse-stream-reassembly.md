---
id: 004-sse-stream-reassembly
unit: 004-llm-response-parser
intent: 006-sidecar-proxy-enforcement
status: draft
priority: must
created: 2026-04-05T12:00:00Z
assigned_bolt: null
implemented: false
---

# Story: 004-sse-stream-reassembly

## User Story

**As the** response-path evaluator
**I want to** correctly reassemble tool calls that are split across multiple SSE chunks
**So that** no tool call is missed due to arbitrary chunking boundaries

## Acceptance Criteria

- [ ] **Given** a streaming LLM response where a tool call's data is spread across multiple SSE `data:` events, **When** the events are processed, **Then** the tool call fragments are correctly reassembled before being passed to the provider parser for enforcement evaluation
- [ ] **Given** a streaming response where partial JSON fragments arrive across chunk boundaries (e.g., an SSE `data:` line is split mid-JSON between two HTTP chunks), **When** the raw byte stream is processed, **Then** the partial data is buffered until a complete SSE event is formed
- [ ] **Given** a streaming response containing multiple tool calls in a single response, **When** all events are processed, **Then** each tool call is independently reassembled and yielded as a separate detection
- [ ] **Given** a streaming response where HTTP chunks split at arbitrary byte positions (mid-JSON key, mid-SSE event boundary `\n\n`, mid-`data:` prefix), **When** the byte stream is processed, **Then** the reassembly layer produces correct, complete SSE events regardless of chunk boundaries
- [ ] **Given** a malformed or excessively long stream that never completes a valid SSE event, **When** the buffer exceeds a configurable size limit, **Then** the buffer is flushed/discarded with a warning log, and the response is forwarded without further response-path evaluation (fail-open on parse failure, request-path enforcement still applies)

## Technical Notes

- This story implements the low-level SSE and streaming reassembly layer that sits beneath the provider-specific parsers (stories 001-003). It does not interpret tool call semantics -- it ensures that provider parsers receive well-formed, complete data units to parse.
- **SSE format (OpenAI, Anthropic)**: The `text/event-stream` format consists of events separated by `\n\n`. Each event has one or more fields (`event:`, `data:`, `id:`, `retry:`). The reassembly layer must handle:
  - Chunks that split mid-event (no `\n\n` terminator yet)
  - Chunks that split mid-field (e.g., `dat` in one chunk, `a: {"tool...` in the next)
  - Chunks that contain multiple complete events
  - Chunks that end exactly on an event boundary
- **Gemini JSON array streaming**: Gemini uses a different format -- a streamed JSON array `[{...},{...},...]`. The reassembly layer must handle:
  - JSON objects split across chunks (e.g., chunk ends mid-object)
  - Array delimiters (`[`, `,`, `]`) split across chunks
  - A top-level JSON array parser that yields complete objects as they are received
- The reassembly layer should be implemented as a generic `StreamReassembler` (or similar) with format-specific modes: `SseMode` for OpenAI/Anthropic and `JsonArrayMode` for Gemini.
- The `SseBuffer` maintains an internal byte buffer. Incoming HTTP body chunks are appended to the buffer. The buffer is scanned for complete SSE events (delimited by `\n\n`). Complete events are yielded to the provider parser; incomplete data remains in the buffer.
- Buffer overflow protection: configurable maximum buffer size (default 1 MB). If the buffer exceeds this limit without yielding a complete event, the stream is considered malformed. The buffer is discarded, a warning is logged, and the remaining response is forwarded without response-path evaluation.
- The reassembly layer operates on raw bytes (`&[u8]`), not decoded strings, to avoid premature UTF-8 validation failures on chunk boundaries.
- Pingora delivers response body data via the `response_body_filter` hook as `Option<Bytes>` chunks. The reassembly layer is invoked within this hook.

## Dependencies

### Requires

- None (foundational streaming infrastructure; this is the lowest layer of the response parser stack)

### Enables

- 001-openai-parser (provides well-formed SSE events for OpenAI streaming parsing)
- 002-anthropic-parser (provides well-formed SSE events for Anthropic streaming parsing)
- 003-gemini-parser (provides well-formed JSON array elements for Gemini streaming parsing)
- 005-denial-rewrite-synthesis (reassembly layer used during in-flight rewriting of streaming responses)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Chunk boundary falls exactly on `\n\n` event separator | Both events yielded correctly; no data lost |
| Chunk boundary splits `\n\n` as `\n` + `\n` across two chunks | Buffer holds partial separator; completes on next chunk; event yielded |
| Chunk boundary splits `data:` prefix (e.g., `da` + `ta: {...}\n\n`) | Buffer accumulates until complete event is formed; yielded correctly |
| Single chunk contains multiple complete SSE events | All complete events yielded in order; any trailing partial data buffered |
| Empty `data:` line (`data:\n\n`) | Yielded as empty event; provider parser handles interpretation |
| SSE comment lines (`:` prefix, used as keep-alive) | Passed through or ignored per SSE spec; not treated as data events |
| `data: [DONE]` termination event (OpenAI convention) | Yielded as a normal event; provider parser recognizes termination semantics |
| Extremely small chunks (1-2 bytes each) | Reassembly still produces correct events; performance may degrade but correctness maintained |
| Chunk contains a complete event followed by exactly zero bytes of the next event | Complete event yielded; buffer is empty; no spurious partial event |
| Gemini JSON array: chunk splits mid-JSON string containing escaped characters | JSON parser correctly handles escapes; does not misinterpret `\"` as string end |
| Gemini JSON array: chunk splits between array comma and next object | Comma buffered; next object accumulated from subsequent chunk |
| Buffer reaches max size without a complete event | Buffer discarded; warning logged; stream forwarded without response-path evaluation |
| Response is not SSE or JSON array (e.g., non-streaming JSON accidentally sent with Transfer-Encoding: chunked) | Reassembly layer detects non-streaming content type; passes through to non-streaming parser path |
| Connection drops mid-stream (incomplete final event) | Incomplete buffer discarded; partial tool call not emitted; logged as warning |
| Concurrent streams from different requests | Each request maintains its own independent reassembly buffer; no cross-contamination |

## Out of Scope

- Provider-specific tool call semantic interpretation (stories 001-003)
- Denial result rewriting within the stream (story 005)
- Non-streaming response parsing (provider parsers handle full JSON directly)
- HTTP chunked transfer-encoding decoding (Pingora handles this before `response_body_filter`)
- Response body decompression (gzip/br decoding should be handled at the proxy layer before reassembly)
