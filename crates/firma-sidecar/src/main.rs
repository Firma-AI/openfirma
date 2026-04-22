use firma_sidecar::policy_watcher::{PolicyWatcherConfig, new_policy_watch_pair};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tracing::info!("firma-sidecar starting");

    // Create the policy watch channel seeded with the fail-closed sentinel.
    // Stage 2 denies all requests until the first bundle is delivered.
    let (_policy_rx, policy_watcher) =
        new_policy_watch_pair(PolicyWatcherConfig::default());

    // Spawn the background bundle consumer. It connects to the Authority,
    // streams PolicyBundleUpdates, and swaps the active evaluator on delivery.
    // Reconnects with exponential backoff on any stream error.
    tokio::spawn(policy_watcher.run());

    tracing::info!(
        authority = %PolicyWatcherConfig::default().authority_endpoint,
        "policy bundle watcher started; enforcement fail-closed until first bundle",
    );

    // TODO: construct EnforcementPipeline with ConstraintEnforcer::new(_policy_rx)
    // and start the HTTP proxy interceptor.
}
