//! Concrete audit sink implementations.

mod file;
mod grpc;
mod metadata;
mod stdout;
mod wal;

pub use self::file::FileAuditSink;
pub use self::grpc::GrpcAuditSink;
pub use self::stdout::StdoutAuditSink;
pub use self::wal::WalAuditSink;

use crate::audit::ExecutionEvent;

/// Converts the persisted audit representation into its gRPC transport form.
fn execution_event_to_proto(value: ExecutionEvent) -> firma_protobuf::v1::ExecutionEvent {
    firma_protobuf::v1::ExecutionEvent {
        event_id: value.event_id,
        session_id: value.session_id,
        token_id: value.token_id,
        agent_id: value.agent_id,
        action: value.action,
        resource: value.resource,
        decision: value.decision as i32,
        deny_reason: value.deny_reason,
        enforcement_latency_us: value.enforcement_latency_us,
        context_hash: value.context_hash,
        bundle_version: value.bundle_version,
        timestamp: value.timestamp.map(|nanos| {
            #[expect(
                clippy::cast_possible_truncation,
                reason = "timestamp seconds fit i64 for supported event times"
            )]
            let seconds = (nanos / 1_000_000_000) as i64;
            let sub_nanos = (nanos % 1_000_000_000) as i32;
            prost_types::Timestamp {
                seconds,
                nanos: sub_nanos,
            }
        }),
        signature: value.signature,
        dispatch_status: value.dispatch_status,
        dispatch_latency_us: value.dispatch_latency_us,
        response_size: value.response_size,
        sandbox_id: value.sandbox_id,
        provenance: value.provenance,
        thread_id: value.thread_id,
        parent_action_id: value.parent_action_id,
    }
}
