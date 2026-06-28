use super::UserProcessId;

/// Extension methods for spawned child processes.
pub trait ChildExt {
    /// Return the child process ID as a [`UserProcessId`].
    ///
    /// # Panics
    ///
    /// Panics if a supported platform reports PID `0` for a spawned child.
    /// Unix and Windows spawned child process IDs are non-zero.
    fn process_id(&self) -> UserProcessId;
}

impl ChildExt for std::process::Child {
    #[expect(clippy::expect_used)]
    fn process_id(&self) -> UserProcessId {
        UserProcessId::new(self.id())
            .expect("spawned child process IDs are non-zero on supported platforms")
    }
}
