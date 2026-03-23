# Firma OSS

Firma OSS is the open-source release of the Firma security architecture, containing the Execution Envelope SDK and Connector Plugin Kit.

## Components

### Execution Envelope Protocol (`execution_envelope.proto`)

Defines the core protocol messages for the Firma execution flow:

- **ExecutionIntent**: action, resource, params
- **ExecutionMetadata**: session_id, agent_id, timestamp, trace_id, budget_consumed, risk_score
- **ExecutionEnvelope**: intent, capability (PASETO v4 / JWT RS256), metadata, provenance. **This is the core protocol unit that flows through the entire system.**
- **ConnectorResponse**: status_code, body, headers, latency_micros, response_size_bytes

### Connector Plugin Kit (`firma_connector`)

A Rust crate providing:

- **Connector trait**: Async trait for implementing protocol-specific connectors
- **ConnectorError**: Error enum with NotFound, TargetError, Timeout, and Internal variants
- **Global registry**: Thread-safe connector registration and lookup

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Agent     │────▶│   Sidecar   │────▶│  Connector │────▶│  External   │
│             │     │  (Gate)     │     │             │     │   System    │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
                           │                                       ▲
                           ▼                                       │
                    ┌─────────────┐                                 │
                    │  Authority  │─────────────────────────────────┘
                    │ (pre-flight)│
                    └─────────────┘
```

- **Authority**: Evaluates Cedar policies at issuance (pre-flight). **Defines the permission perimeter** — the Gate can only operate within that boundary and can never extend it.
- **Gate (Sidecar)**: Evaluates Cedar policies at runtime for each call. Operates in two stages:
  - **Stage 1 (Capability Validation)**: Crypto verification + revocation check. No network calls.
  - **Stage 2 (Cedar + Constraints)**: Full Cedar policy evaluation (CEE - Capability Enforced Execution).
- **Connector**: Protocol translation and technical constraints only. **Hard boundary: No business/policy logic in connectors.** Business logic must remain in Cedar/Authority/Gate, otherwise the model breaks over time.

## Key Design Principles

1. **Cedar runs in two places**: Authority (issuance) and Gate (runtime)
2. **Capability tokens**: PASETO v4 or JWT RS256, opaque to the proto
3. **Provenance**: Reserved nullable field; V1 does not implement hash chain
4. **Connectors**: Technical constraints only (rate limits, schema validation). Business logic stays in Cedar/Authority/Gate

## Usage

```rust
use firma_connector::{register, get, Connector, ConnectorError, ExecutionEnvelope};
use std::sync::Arc;
use async_trait::async_trait;

struct MyConnector;

#[async_trait]
impl Connector for MyConnector {
    fn name(&self) -> &'static str {
        "my_connector"
    }

    async fn dispatch(
        &self,
        env: &ExecutionEnvelope,
    ) -> Result<ConnectorResponse, ConnectorError> {
        // Protocol-specific implementation
        todo!()
    }
}

register("my_connector", Arc::new(MyConnector));
let connector = get("my_connector");
```

## License

Apache 2.0
