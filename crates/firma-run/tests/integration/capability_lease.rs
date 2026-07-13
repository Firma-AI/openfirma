use firma_run::capability::read_capability_token;
use firma_run::config::CapabilitySource;

#[test]
fn disabled_source_yields_no_token() {
    let token =
        read_capability_token(&CapabilitySource::Disabled).expect("disabled source never fails");

    assert!(token.is_none());
}

#[test]
fn file_source_reads_trimmed_token() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let token_path = tempdir.path().join("token.txt");
    std::fs::write(&token_path, "token-v1\n").expect("write token");

    let token = read_capability_token(&CapabilitySource::File { path: token_path })
        .expect("read token file");

    assert_eq!(token, Some("token-v1".to_string()));
}

#[test]
fn empty_file_source_fails_closed() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let token_path = tempdir.path().join("token.txt");
    std::fs::write(&token_path, "  \n").expect("write token");

    let err = read_capability_token(&CapabilitySource::File { path: token_path })
        .expect_err("empty capability file must fail closed");

    assert!(err.to_string().contains("is empty"));
}

#[test]
fn missing_file_source_fails_closed() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let token_path = tempdir.path().join("does-not-exist.txt");

    let err = read_capability_token(&CapabilitySource::File { path: token_path })
        .expect_err("unreadable capability file must fail closed");

    assert!(err.to_string().contains("does-not-exist.txt"));
}
