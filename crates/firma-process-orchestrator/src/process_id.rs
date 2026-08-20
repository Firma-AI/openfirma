//! Process identity conversion for children owned by the orchestrator.

use firma_runtime_state::UserProcessId;

/// Extension methods for direct children spawned by the orchestrator.
pub trait ChildExt {
    /// Return the non-zero platform process ID assigned to this child.
    fn process_id(&self) -> UserProcessId;
}

impl ChildExt for std::process::Child {
    #[expect(
        clippy::expect_used,
        reason = "supported platforms assign valid non-zero process IDs to spawned children"
    )]
    fn process_id(&self) -> UserProcessId {
        UserProcessId::new(self.id())
            .expect("spawned child process IDs are valid on supported platforms")
    }
}
