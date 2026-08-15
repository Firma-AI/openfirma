use chrono::Duration;
use firma_authority::RevocationStore;
use firma_identifiers::TokenId;

#[tokio::test]
async fn persistence_round_trips_canonical_ctok_id() {
    let directory = tempfile::tempdir().expect("create temporary directory");
    let path = directory.path().join("revocations.txt");
    let token_id = TokenId::generate();
    let store = RevocationStore::try_new(&path, Duration::hours(1)).expect("create store");

    store
        .revoke(token_id, "integration test")
        .await
        .expect("persist revocation");

    let content = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            let content = tokio::fs::read_to_string(&path)
                .await
                .expect("read revocation file");
            if !content.is_empty() {
                break content;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("revocation write must become visible");
    assert!(content.starts_with(&format!("{token_id}\t")));
    assert!(content.starts_with("ctok_"));

    let reloaded = tokio::task::spawn_blocking(move || {
        RevocationStore::try_new(&path, Duration::hours(1)).expect("reload store")
    })
    .await
    .expect("join reload task");
    assert!(reloaded.is_revoked(token_id).await);
}
