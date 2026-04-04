---
id: 004-proxy-denial-response-format
unit: 001-proxy-core
intent: 006-sidecar-proxy-enforcement
status: draft
priority: must
created: 2026-04-05T12:00:00Z
assigned_bolt: null
implemented: false
---

# Story: 004-proxy-denial-response-format

## User Story

**As an** AI agent runtime
**I want** proxy-path denial responses to follow a structured JSON format with clear reason codes
**So that** I can programmatically handle enforcement denials and surface meaningful information to the agent loop

## Acceptance Criteria

- [ ] **Given** a Stage 1 or Stage 2 denial, **When** the proxy returns the denial to the agent, **Then** the response body is valid JSON containing: `firma_decision` (string, always `"DENY"`), `reason` (reason code string), `detail` (human-readable explanation), `request_id` (UUID v7), and `timestamp` (ISO 8601)
- [ ] **Given** a Stage 1 denial (e.g., expired token), **When** the proxy responds, **Then** the HTTP status code is `403 Forbidden`
- [ ] **Given** a Stage 2 denial (e.g., policy denied), **When** the proxy responds, **Then** the HTTP status code is `403 Forbidden`
- [ ] **Given** a malformed request (e.g., missing required headers, unparseable body), **When** the proxy responds, **Then** the HTTP status code is `400 Bad Request` with reason code `MALFORMED_REQUEST`
- [ ] **Given** an internal Sidecar failure (e.g., policy bundle stale, authority unavailable), **When** the proxy responds, **Then** the HTTP status code is `503 Service Unavailable` with the appropriate reason code
- [ ] **Given** all defined reason codes, **When** a denial occurs for each reason, **Then** the correct reason code is used: `TOKEN_INVALID`, `TOKEN_EXPIRED`, `TOKEN_REVOKED`, `POLICY_DENIED`, `BUDGET_EXCEEDED`, `SCOPE_VIOLATION`, `RISK_THRESHOLD`, `TOOL_NOT_IN_SCOPE`, `UNCLASSIFIED_INTENT`, `MALFORMED_REQUEST`, `AUTHORITY_UNAVAILABLE`, `POLICY_BUNDLE_STALE`, `CREDENTIAL_INJECTION_FAILED`, `CONNECTOR_TIMEOUT`
- [ ] **Given** an ALLOW decision from the enforcement pipeline, **When** the upstream response is returned, **Then** the response passes through to the agent unchanged (no Firma envelope wrapping)

## Technical Notes

- The denial response JSON schema:
  ```json
  {
    "firma_decision": "DENY",
    "reason": "POLICY_DENIED",
    "detail": "Cedar policy evaluation denied action llm.chat on resource api.openai.com",
    "request_id": "0192d4e0-7b1a-7f3e-9a4b-1c2d3e4f5a6b",
    "timestamp": "2026-04-05T12:00:00.000Z"
  }
  ```
- UUID v7 for `request_id` provides time-ordered, globally unique identifiers — use the `uuid` crate with `v7` feature
- The `Content-Type` header on all denial responses must be `application/json`
- Reason code to HTTP status mapping:
  - **403**: `TOKEN_INVALID`, `TOKEN_EXPIRED`, `TOKEN_REVOKED`, `POLICY_DENIED`, `BUDGET_EXCEEDED`, `SCOPE_VIOLATION`, `RISK_THRESHOLD`, `TOOL_NOT_IN_SCOPE`, `UNCLASSIFIED_INTENT`
  - **400**: `MALFORMED_REQUEST`
  - **503**: `AUTHORITY_UNAVAILABLE`, `POLICY_BUNDLE_STALE`, `CREDENTIAL_INJECTION_FAILED`, `CONNECTOR_TIMEOUT`
- Implement as a reusable function/module (e.g., `DenialResponse::from_reason(reason, detail) -> HttpResponse`) so that all components producing denials use the same format
- The `detail` field should be informative for debugging but must not leak sensitive internal state (no stack traces, no credential values, no full policy text)
- This format applies only to proxy-path denials (direct HTTP calls denied); tool-path denials (LLM response rewriting) follow provider-native formats defined in unit 004

## Dependencies

### Requires

- None (can be implemented as a standalone response formatting module)

### Enables

- All enforcement stories that produce DENY decisions (they call this module to format the response)
- 001-http-proxy-listener and 002-https-mitm-interception (proxy hooks return denial responses using this format)

## Edge Cases

| Scenario | Expected Behavior |
| -------- | ----------------- |
| Multiple denial reasons apply (e.g., token expired AND policy denied) | Return the first denial encountered in pipeline order (Stage 1 before Stage 2); only one reason code per response |
| Detail message contains non-ASCII characters | JSON is UTF-8; ensure proper encoding; no escaping issues |
| Agent sends Accept header requesting non-JSON (e.g., `text/xml`) | Always return JSON regardless of Accept header; Firma denial format is not content-negotiated |
| Request ID generation fails (UUID v7 clock issue) | Fall back to UUID v4; never omit the request_id field |
| Very long detail message | Truncate at a reasonable limit (e.g., 1024 characters) to prevent oversized responses |
| ALLOW response from upstream is itself a 403 | Pass through unchanged; only Firma-generated denials use the Firma JSON format |

## Out of Scope

- Tool-path denial format (provider-native structured tool results; unit 004-llm-response-parser)
- Audit event emission for denials (unit 006-audit-observability)
- Internationalization / localization of detail messages
- Custom denial response templates
