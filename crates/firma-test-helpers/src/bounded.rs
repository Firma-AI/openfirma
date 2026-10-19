//! Bounded execution for tests that run an in-process Authority.
//!
//! A stall must fail with the step that stalled rather than run into the
//! harness timeout without diagnostics. Test bodies run as a task on a
//! multi-threaded runtime, so the test thread still enforces the body deadline
//! when a worker is blocked. Runtime teardown is bounded as well, because a
//! blocked worker would otherwise hang it and hide the failure.

use std::future::{Future, IntoFuture};
use std::time::{Duration, Instant};

use anyhow::anyhow;
use tempfile::TempDir;

const BODY_LIMIT: Duration = Duration::from_secs(120);
const TEARDOWN_LIMIT: Duration = Duration::from_secs(10);

/// Run `body` to completion within 120 seconds, then shut the runtime down
/// within 10 seconds.
///
/// Authority and step logs go to the captured test output, so a failure shows
/// the last step that started. A panic in `body` is resumed after teardown.
///
/// # Errors
///
/// Returns the error from `body`, or an error if the runtime cannot be built,
/// `body` exceeds its deadline, or teardown exceeds its deadline.
pub fn run(body: impl Future<Output = anyhow::Result<()>> + Send + 'static) -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let outcome =
        runtime.block_on(async { tokio::time::timeout(BODY_LIMIT, tokio::spawn(body)).await });
    let teardown = Instant::now();
    runtime.shutdown_timeout(TEARDOWN_LIMIT);
    let result = match outcome {
        Err(_) => Err(anyhow!(
            "test body did not finish within {BODY_LIMIT:?}; the last started step stalled"
        )),
        Ok(Err(error)) => match error.try_into_panic() {
            Ok(payload) => std::panic::resume_unwind(payload),
            Err(error) => Err(error.into()),
        },
        Ok(Ok(result)) => result,
    };
    if teardown.elapsed() >= TEARDOWN_LIMIT {
        result?;
        return Err(anyhow!(
            "runtime teardown did not finish within {TEARDOWN_LIMIT:?}"
        ));
    }
    result
}

/// Remove a fixture directory as a named step.
///
/// Removal runs on a blocking thread, so the step deadline still fires if the
/// filesystem stalls it. Removal errors are ignored, as in [`TempDir`]'s
/// `Drop`.
///
/// # Errors
///
/// Returns an error if removal does not finish within 10 seconds.
pub async fn remove_dir(dir: TempDir) -> anyhow::Result<()> {
    let removal = tokio::task::spawn_blocking(move || drop(dir));
    step(
        "remove the fixture directory",
        Duration::from_secs(10),
        removal,
    )
    .await??;
    Ok(())
}

/// Await `future` as the named test step.
///
/// # Errors
///
/// Returns an error naming the step if `future` does not finish within
/// `limit`.
pub async fn step<F: IntoFuture>(
    name: &str,
    limit: Duration,
    future: F,
) -> anyhow::Result<F::Output> {
    tracing::info!(step = name, "test step started");
    tokio::time::timeout(limit, future)
        .await
        .map_err(|_| anyhow!("test step '{name}' did not finish within {limit:?}"))
}
