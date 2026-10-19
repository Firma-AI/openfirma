use firma_config_schema::sidecar::InterceptorMode;

use super::support::{Fixture, Logs, bundle, push, rule};

fn matching(version: &str) -> firma_protobuf::v1::PolicyBundle {
    let mut composio = rule("code.read");
    composio.host = "*.composio.dev".into();
    bundle(version, vec![rule("code.read"), composio])
}

#[tokio::test]
async fn only_accepted_coverage_transitions_warn_and_refreshes_stay_quiet() -> anyhow::Result<()> {
    let logs = Logs::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let mut fixture = Fixture::start_configured(|config| {
        config.interceptor.mode = InterceptorMode::HttpProxy;
        config.interceptor.https_mitm.enabled = false;
    })
    .await?;
    let (_, tx) = fixture.connection().await?;
    let warning = "HTTPS MITM is inactive; Composio traffic";
    push(&tx, matching("1")).await?;
    logs.wait("enforcement snapshot swapped", 1).await?;
    assert_eq!(logs.count(warning)?, 1);
    push(&tx, matching("1")).await?;
    logs.wait("enforcement snapshot swapped", 2).await?;
    assert_eq!(logs.count(warning)?, 1);
    let mut rejected = matching("bad");
    rejected.ttl_seconds = 0;
    push(&tx, rejected).await?;
    logs.wait("enforcement snapshot compilation failed", 1)
        .await?;
    push(&tx, matching("2")).await?;
    logs.wait("enforcement snapshot swapped", 3).await?;
    assert_eq!(logs.count(warning)?, 1);
    push(&tx, bundle("3", vec![rule("code.read")])).await?;
    logs.wait("enforcement snapshot swapped", 4).await?;
    push(&tx, matching("4")).await?;
    logs.wait("enforcement snapshot swapped", 5).await?;
    assert_eq!(logs.count(warning)?, 2);
    fixture.applied("4").await?;
    Ok(())
}

#[tokio::test]
async fn adequate_mitm_and_non_proxy_modes_do_not_warn() -> anyhow::Result<()> {
    let logs = Logs::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    for (index, mode) in [InterceptorMode::HttpProxy, InterceptorMode::Grpc]
        .into_iter()
        .enumerate()
    {
        let mut fixture = Fixture::start_configured(|config| {
            config.interceptor.mode = mode;
            config.interceptor.https_mitm.enabled = mode == InterceptorMode::HttpProxy;
        })
        .await?;
        let (_, tx) = fixture.connection().await?;
        push(&tx, matching("covered")).await?;
        logs.wait("enforcement snapshot swapped", index + 1).await?;
        assert_eq!(logs.count("Composio traffic")?, 0);
    }
    Ok(())
}
