# Audit Log Consumption

## Audit guarantees

Every enforcement decision (ALLOW, DENY, or pass-through) emits exactly one
audit event. Events are signed with an ECDSA P-256 key configured separately
from the capability signing key (configured under `[audit]`). The signature
covers all event fields via SHA-256; tampered events fail verification. Events
are emitted asynchronously over an internal channel so that signing is off the
enforcement hot path and does not contribute to enforcement latency.

## Sinks

### stdout

Events are written as newline-delimited JSON to stdout. Suitable for
container or systemd log collection via standard log-forwarding infrastructure.
No durability guarantees beyond what the host log pipeline provides; suitable
for development or systems where an external log collector provides durability.

### file

Events are appended to a local file. Low write overhead; durability depends on
the fsync behavior of the underlying OS and filesystem. No rotation is built in
— use `logrotate` or an equivalent tool to manage file growth and retention.

### grpc

Events are streamed via gRPC to a remote sink. Provides the highest durability
when the remote sink is reliable and persistent. Back-pressure is applied;
events are dropped if the internal channel is full and the sink is unreachable.
Monitor the sink for connectivity gaps to avoid silent event loss.

### wal

Write-ahead log sink. Events are written to a local WAL before acknowledgment,
providing crash-consistent durability even if the process exits uncleanly.
Higher write overhead than `file`; suited for high-assurance deployments where
every audit record must survive a process crash.

## Event schema

| Field                    | Type    | Description                                                     |
| ------------------------ | ------- | --------------------------------------------------------------- |
| `event_id`               | UUID v7 | Unique event identifier (time-ordered)                          |
| `session_id`             | string  | Session identifier from the enforcement context                 |
| `token_id`               | string  | Capability token ID                                             |
| `agent_id`               | string  | Agent identifier from the capability claims                     |
| `action`                 | string  | Normalized `action_class` (e.g., `communication.external.send`) |
| `resource`               | string  | Normalized resource string                                      |
| `decision`               | int     | 1 = ALLOW, 2 = DENY                                             |
| `deny_reason`            | string  | Human-readable deny reason (empty on ALLOW)                     |
| `enforcement_latency_us` | uint    | Enforcement pipeline latency in microseconds                    |
| `context_hash`           | string  | SHA-256 of the capability context at issuance                   |
| `bundle_version`         | string  | Policy bundle version at evaluation time                        |
| `timestamp`              | uint    | Nanoseconds since Unix epoch                                    |
| `signature`              | bytes   | DER-encoded ECDSA P-256 signature over all preceding fields     |

## Consuming events

Recommended ingestion pipelines:

- **stdout → Vector → S3/object store**: Low-latency ingestion into durable
  object storage for SIEM query. Vector handles batching, compression, and
  back-pressure.
- **gRPC sink → Kafka**: High-throughput streaming; allows multiple downstream
  consumers such as alerting, archival, and analytics to subscribe independently.
- **WAL → batch export**: For airgapped or high-assurance deployments where
  events must be durably captured locally before forwarding to an external
  system.

## Verification

To verify the signature chain offline:

1. Load the audit signing public key (ECDSA P-256, configured under
   `[audit.signing_key]`).
2. For each event, reconstruct the signing payload: SHA-256 over all fields
   except `signature`, separated by newlines, in declaration order.
3. Verify the DER-encoded signature in the `signature` field against the
   reconstructed payload using the public key. Any mismatch indicates tampering.

## Retention

Retention is operator responsibility. Minimum recommended retention is 90 days.
For compliance use cases, retain audit logs for the duration of the maximum
token TTL plus the investigation window defined by your security policy.
