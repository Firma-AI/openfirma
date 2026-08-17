use std::time::{Duration, Instant};

/// Polls `observe` synchronously until it returns a value or `timeout` elapses.
///
/// Callers retain ownership of scenario-specific deadlines and observations. This helper only
/// provides bounded retry timing; it never substitutes an unconditional sleep for a readiness,
/// propagation, output, or expiry condition.
pub(crate) fn wait_for<T>(
    description: &str,
    timeout: Duration,
    mut observe: impl FnMut() -> Option<T>,
) -> T {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(value) = observe() {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {description}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
