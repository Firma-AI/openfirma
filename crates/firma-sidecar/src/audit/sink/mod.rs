//! Concrete audit sink implementations.

mod file;
mod grpc;
mod grpc_integration_tests;
mod metadata;
mod stdout;
mod submission;
mod wal;

pub use self::file::FileAuditSink;
pub use self::grpc::GrpcAuditSink;
pub use self::stdout::StdoutAuditSink;
pub use self::wal::WalAuditSink;

use std::path::Path;

use crate::audit::ExecutionEvent;

/// Create `dir` and its missing parents, private to this user on Unix.
///
/// Every sink that puts events on disk goes through here: the events name
/// resources, agents, and tokens, so the directory holding them must not be
/// group- or world-readable.
fn create_private_dir_all(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(dir)
}

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
        run_evidence: value.run_evidence.map(|evidence| evidence.0),
    }
}
