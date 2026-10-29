use super::state_layout::empty_state_beside;
use firma_sidecar::config::{
    HttpsMitmConfigError, InterceptorConfigError, SidecarConfig, SidecarConfigError,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn load(
    https_mitm: &str,
) -> Result<Result<SidecarConfig, SidecarConfigError>, Box<dyn std::error::Error>> {
    let tmpdir = tempfile::tempdir()?;
    let config_path = tmpdir.path().join("sidecar.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
[authority]
url = "http://127.0.0.1:50051"
[interceptor.https_mitm]
{https_mitm}
"#
        ),
    )?;
    Ok(SidecarConfig::load_from_path(
        &config_path,
        &empty_state_beside(&config_path),
    ))
}

#[test]
fn active_mitm_rejects_a_zero_certificate_ttl() -> TestResult {
    let error = load("enabled = true\ncert_ttl = \"0s\"")?
        .expect_err("active interception needs a positive leaf certificate TTL");

    std::assert_matches!(
        error,
        SidecarConfigError::Interceptor(InterceptorConfigError::HttpsMitm(
            HttpsMitmConfigError::ZeroCertTtl
        ))
    );
    insta::assert_snapshot!(error.to_string(), @"interceptor: interceptor.https_mitm.cert_ttl must be > 0");
    Ok(())
}

#[test]
fn active_mitm_rejects_a_zero_certificate_cache_capacity() -> TestResult {
    let error = load("enabled = true\ncert_cache_capacity = 0")?
        .expect_err("active interception needs a positive leaf certificate cache");

    std::assert_matches!(
        error,
        SidecarConfigError::Interceptor(InterceptorConfigError::HttpsMitm(
            HttpsMitmConfigError::ZeroCertCacheCapacity
        ))
    );
    insta::assert_snapshot!(error.to_string(), @"interceptor: interceptor.https_mitm.cert_cache_capacity must be > 0");
    Ok(())
}

#[test]
fn inactive_mitm_accepts_zero_certificate_settings() -> TestResult {
    // Disabled outright, and enabled with nothing to intercept.
    for selection in ["enabled = false", "enabled = true\nintercept_hosts = []"] {
        let config = load(&format!(
            "{selection}\ncert_ttl = \"0s\"\ncert_cache_capacity = 0"
        ))??;

        assert!(
            !config.interceptor.https_mitm.is_active(),
            "{selection} must leave interception inactive"
        );
    }
    Ok(())
}
