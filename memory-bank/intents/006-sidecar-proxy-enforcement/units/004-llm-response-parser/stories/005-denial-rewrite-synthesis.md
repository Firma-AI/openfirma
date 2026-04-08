---
id: 005-denial-rewrite-synthesis
unit: 004-llm-response-parser
intent: 006-sidecar-proxy-enforcement
status: draft
priority: must
created: 2026-04-05T12:00:00Z
assigned_bolt: null
implemented: false
---

# Story: 005-denial-rewrite-synthesis

## User Story

**As an** AI agent runtime
**I want** denied LLM tool calls to appear as provider-native structured denial results (not HTTP errors)
**So that** my agent loop can read the denial reason and reason about it

## Acceptance Criteria

- [ ] **Given** a tool call that is denied by the enforcement pipeline (DENY decision) and the response is being processed via the rewrite path, **When** the denial is applied, **Then** the original provider payload is rewritten in-flight to replace the denied tool call with a tool result block containing `firma_decision: DENY` and `reason` fields, formatted in the provider's native response structure
- [ ] **Given** a tool call that is denied by the enforcement pipeline and the response is being processed via the synthesis path, **When** the denial is applied, **Then** an equivalent provider-native tool-result message is synthesized and injected into the response stream, containing `firma_decision: DENY` and `reason` fields
- [ ] **Given** a tool call that is allowed by the enforcement pipeline (ALLOW decision), **When** the response is forwarded, **Then** the response body is byte-identical to the original upstream response (zero modification)
- [ ] **Given** a response from an unknown or unsupported LLM provider, **When** the response is processed, **Then** it is forwarded to the agent without any response-path evaluation or modification (request-path enforcement still applies)
- [ ] **Given** the rewrite path implementation, **When** tested independently with recorded provider responses, **Then** the rewritten response is valid JSON in the provider's expected format and parseable by standard provider SDKs
- [ ] **Given** the synthesis path implementation, **When** tested independently with recorded provider responses, **Then** the synthesized denial message is valid in the provider's expected format and parseable by standard provider SDKs
- [ ] **Given** the `LlmResponseParser` trait, **When** a community developer wants to add a new provider parser, **Then** the trait interface, required methods, and expected behaviors are documented with examples

## Technical Notes

- **Two denial paths**: The system supports two distinct mechanisms for surfacing denials to the agent runtime. Both must be implemented and tested independently:
  - **Rewrite path**: The original LLM response is intercepted and modified in-flight. The denied tool call instruction is replaced with a structured tool result that communicates the denial. This works for both streaming and non-streaming responses. For streaming, the modified events replace the original tool call events in the SSE stream.
  - **Synthesis path**: Instead of modifying the original response, a new provider-native message is constructed from scratch and injected. This is useful when rewriting is impractical (e.g., the original response has already been partially forwarded) or as an alternative implementation strategy.

- **Provider-native denial formats**:
  - **OpenAI**: For non-streaming, rewrite `choices[0].message.tool_calls[N]` to remove the denied call and append a synthetic assistant message with a tool result. For streaming, emit modified SSE events. The denial should appear as if the tool returned a result: `{"firma_decision": "DENY", "reason": "POLICY_DENIED", "detail": "..."}` in a tool result content structure.
  - **Anthropic**: Replace the denied `tool_use` content block with a `tool_result` block containing `{"firma_decision": "DENY", "reason": "...", "detail": "..."}` as the content. The `tool_use_id` must match the denied block's `id` for the agent to correctly associate the denial.
  - **Gemini**: Replace the denied `functionCall` part with a `functionResponse` part containing `{"firma_decision": "DENY", "reason": "...", "detail": "..."}` in the `response` field, with the matching function `name`.

- **Partial allow/deny in multi-tool responses**: When a response contains multiple tool calls and only some are denied, the allowed tool calls must be forwarded unchanged while only the denied ones are rewritten/synthesized. The response structure must remain valid.

- **`LlmResponseParser` trait design**:
  ```
  trait LlmResponseParser {
      fn provider_id(&self) -> &str;
      fn detect(host: &str, headers: &Headers) -> Option<Box<dyn LlmResponseParser>>;
      fn parse_non_streaming(&self, body: &[u8]) -> Result<Vec<ToolCallDetection>>;
      fn parse_streaming_event(&mut self, event: &SseEvent) -> Result<Vec<ToolCallDetection>>;
      fn rewrite_denial_non_streaming(&self, body: &[u8], denials: &[DenialInfo]) -> Result<Vec<u8>>;
      fn rewrite_denial_streaming(&self, event: &SseEvent, denials: &[DenialInfo]) -> Result<Vec<SseEvent>>;
      fn synthesize_denial(&self, denial: &DenialInfo) -> Result<Vec<u8>>;
  }
  ```
  The exact trait signature will be refined during domain modeling, but the above captures the key operations.

- **Trait documentation**: The `LlmResponseParser` trait must include comprehensive doc comments covering: the purpose of each method, expected input/output formats, error handling contract, how provider detection works, and a walkthrough example of implementing a parser for a hypothetical new provider.

- **Streaming rewrite complexity**: Rewriting a streaming response in-flight is the hardest part of this story. When a tool call is detected across multiple SSE events and then denied, the parser must either: (a) buffer the tool call events and replace them once the decision is made, or (b) emit the events and then inject a corrective denial event afterward. Option (a) introduces latency for allowed calls; option (b) may confuse some agent runtimes. The implementation should use option (a) with buffering scoped only to tool call events, not the entire stream.

## Dependencies

### Requires

- 001-openai-parser (OpenAI-specific parsing logic and format knowledge)
- 002-anthropic-parser (Anthropic-specific parsing logic and format knowledge)
- 003-gemini-parser (Gemini-specific parsing logic and format knowledge)
- 004-sse-stream-reassembly (streaming reassembly layer for in-flight rewriting)
- Unit 002-enforcement-pipeline (enforcement decision for each extracted tool call)

### Enables

- Unit 001-proxy-core integration (response body filter wired into Pingora lifecycle)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Multi-tool response: some allowed, some denied | Allowed tool calls forwarded unchanged; denied ones replaced with denial results; response structure remains valid |
| All tool calls in a multi-tool response are denied | All tool calls replaced with denial results; response is still a valid provider-format message |
| All tool calls in a multi-tool response are allowed | Response forwarded byte-identical |
| Streaming: denial decision arrives after some tool call SSE events have been buffered | Buffered events replaced with denial events; subsequent events adjusted accordingly |
| Streaming: ALLOW decision for a buffered tool call | Buffered events released to the agent unchanged |
| Non-streaming response too large to buffer for rewriting (>10 MB) | Response forwarded without response-path evaluation; warning logged; request-path enforcement still applies |
| Provider response format has changed (unexpected JSON structure) | Parse error caught; response forwarded unchanged; warning logged; request-path enforcement still applies |
| Denial reason contains special characters or long text | Reason truncated to reasonable length; special characters escaped properly for JSON embedding |
| Rewrite produces invalid JSON (implementation bug) | Validation check catches invalid output; falls back to synthesis path; if both fail, response forwarded with warning |
| Synthesis path invoked but tool call ID is unknown (streaming race) | Synthesis uses a generated placeholder ID with clear Firma prefix for debuggability |
| Agent reconnects and replays a request whose previous response was partially rewritten | Each request is independent; no state carried across requests; fresh evaluation |
| Response has `Content-Length` header that no longer matches after rewrite | `Content-Length` header removed; response sent as `Transfer-Encoding: chunked` or with corrected length |

## Out of Scope

- Enforcement decision logic (Stage 1, Stage 2 evaluation owned by unit 002-enforcement-pipeline)
- HTTP-level proxy denial responses for request-path denials (unit 001-proxy-core, story 004)
- Audit event emission for tool call denials (unit 006-audit-observability; enforcement pipeline emits audit events)
- Caching of denial decisions across requests
- Agent-side SDK or library for parsing Firma denial results
- Provider format versioning or migration (V1 targets current API formats as of implementation date)
