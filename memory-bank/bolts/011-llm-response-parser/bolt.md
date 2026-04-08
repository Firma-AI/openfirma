---
id: 011-llm-response-parser
unit: 004-llm-response-parser
intent: 006-sidecar-proxy-enforcement
type: ddd-construction-bolt
status: planned
stories:
  - 001-openai-parser
  - 002-anthropic-parser
  - 003-gemini-parser
  - 004-sse-stream-reassembly
  - 005-denial-rewrite-synthesis
created: 2026-04-05T12:00:00Z
started: null
completed: null
current_stage: null
stages_completed: []

requires_bolts: [008-enforcement-pipeline]
enables_bolts: []
requires_units: []
blocks: false

complexity:
  avg_complexity: 3
  avg_uncertainty: 3
  max_dependencies: 2
  testing_scope: 3
---

# Bolt: 011-llm-response-parser

## Overview

Single bolt for the LLM response parser — all three provider parsers, SSE stream reassembly, and denial rewriting/synthesis.

## Objective

Build the response-path evaluation system: OpenAI, Anthropic, and Gemini parsers for both streaming (SSE) and non-streaming responses, chunked SSE reassembly for cross-chunk tool calls, and provider-native denial result rewriting and synthesis.

## Stories Included

- **001-openai-parser**: OpenAI function_call/tool_calls, streaming + non-streaming (Must)
- **002-anthropic-parser**: Anthropic tool_use blocks, streaming + non-streaming (Must)
- **003-gemini-parser**: Gemini functionCall, streaming + non-streaming (Must)
- **004-sse-stream-reassembly**: Chunked SSE reassembly for cross-chunk tool calls (Must)
- **005-denial-rewrite-synthesis**: Provider-native denial result rewriting and synthesis (Must)

## Bolt Type

**Type**: DDD Construction Bolt
**Definition**: `.specsmd/aidlc/templates/construction/bolt-types/ddd-construction-bolt.md`

## Stages

- [ ] **1. Domain Model**: Pending → ddd-01-domain-model.md
- [ ] **2. Technical Design**: Pending → ddd-02-technical-design.md
- [ ] **3. Implementation**: Pending → src/firma-sidecar/
- [ ] **4. Test & Verify**: Pending → ddd-03-test-report.md

## Dependencies

### Requires
- 008-enforcement-pipeline (tool calls evaluated through Stage 1 + Stage 2)

### Enables
- None (integrated into proxy-core response filter)

## Success Criteria

- [ ] OpenAI parser detects function_call and tool_calls (streaming + non-streaming)
- [ ] Anthropic parser detects tool_use blocks (streaming + non-streaming)
- [ ] Gemini parser detects functionCall (streaming + non-streaming)
- [ ] Cross-chunk tool calls correctly reassembled
- [ ] On DENY: provider-native structured denial result
- [ ] On ALLOW: byte-identical forwarding
- [ ] Tests against recorded real LLM responses for all providers
- [ ] Both rewrite and synthesis denial paths tested

## Notes

- Most technically treacherous bolt — highest uncertainty score
- Recorded real LLM responses are essential test fixtures
- SSE chunking at arbitrary byte boundaries is the core challenge
- 5 stories at the limit but domain cohesion demands single bolt
