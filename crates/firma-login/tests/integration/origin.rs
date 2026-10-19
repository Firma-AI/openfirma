use firma_login::{ControlPlaneOrigin, ControlPlaneOriginError, OriginValidationMode};
use url::Url;

fn url(value: &str) -> Result<Url, url::ParseError> {
    Url::parse(value)
}

fn url_with_user_information(value: &str) -> Result<Url, Box<dyn std::error::Error>> {
    let mut url = url(value)?;
    url.set_username("operator")
        .map_err(|()| std::io::Error::other("test URL does not support a username"))?;
    url.set_password(Some("test-only"))
        .map_err(|()| std::io::Error::other("test URL does not support a password"))?;

    Ok(url)
}

#[test]
fn accepts_https_origin_with_an_optional_port() -> Result<(), Box<dyn std::error::Error>> {
    let origin = ControlPlaneOrigin::new(
        url("https://control.firma.example:8443/")?,
        OriginValidationMode::Production,
    )?;

    assert_eq!(
        origin.as_url().as_str(),
        "https://control.firma.example:8443/"
    );
    Ok(())
}

#[test]
fn rejects_origin_without_a_host() -> Result<(), Box<dyn std::error::Error>> {
    let error =
        ControlPlaneOrigin::new(url("file:///etc/firma")?, OriginValidationMode::Production).err();

    assert!(matches!(error, Some(ControlPlaneOriginError::MissingHost)));
    Ok(())
}

#[test]
fn rejects_unsupported_scheme() -> Result<(), Box<dyn std::error::Error>> {
    let error = ControlPlaneOrigin::new(
        url("ftp://control.firma.example/")?,
        OriginValidationMode::Production,
    )
    .err();

    assert!(matches!(
        error,
        Some(ControlPlaneOriginError::UnsupportedScheme)
    ));
    Ok(())
}

#[test]
fn rejects_user_information() -> Result<(), Box<dyn std::error::Error>> {
    let error = ControlPlaneOrigin::new(
        url_with_user_information("https://control.firma.example/")?,
        OriginValidationMode::Production,
    )
    .err();

    assert!(matches!(error, Some(ControlPlaneOriginError::UserInfo)));
    Ok(())
}

#[test]
fn rejects_user_information_before_other_invalid_origin_parts()
-> Result<(), Box<dyn std::error::Error>> {
    let error = ControlPlaneOrigin::new(
        url_with_user_information("ftp://control.firma.example/login?tenant=example#section")?,
        OriginValidationMode::Production,
    )
    .err();

    assert!(matches!(error, Some(ControlPlaneOriginError::UserInfo)));
    Ok(())
}

#[test]
fn rejects_non_root_path() -> Result<(), Box<dyn std::error::Error>> {
    let error = ControlPlaneOrigin::new(
        url("https://control.firma.example/login")?,
        OriginValidationMode::Production,
    )
    .err();

    assert!(matches!(error, Some(ControlPlaneOriginError::Path)));
    Ok(())
}

#[test]
fn rejects_query_string() -> Result<(), Box<dyn std::error::Error>> {
    let error = ControlPlaneOrigin::new(
        url("https://control.firma.example/?tenant=example")?,
        OriginValidationMode::Production,
    )
    .err();

    assert!(matches!(error, Some(ControlPlaneOriginError::Query)));
    Ok(())
}

#[test]
fn rejects_fragment() -> Result<(), Box<dyn std::error::Error>> {
    let error = ControlPlaneOrigin::new(
        url("https://control.firma.example/#section")?,
        OriginValidationMode::Production,
    )
    .err();

    assert!(matches!(error, Some(ControlPlaneOriginError::Fragment)));
    Ok(())
}

#[test]
fn rejects_http_in_production() -> Result<(), Box<dyn std::error::Error>> {
    let error = ControlPlaneOrigin::new(
        url("http://127.0.0.1:3000/")?,
        OriginValidationMode::Production,
    )
    .err();

    assert!(matches!(
        error,
        Some(ControlPlaneOriginError::RequiresHttps)
    ));
    Ok(())
}

#[test]
fn development_mode_accepts_loopback_http() -> Result<(), Box<dyn std::error::Error>> {
    let origin = ControlPlaneOrigin::new(
        url("http://[::1]:3000/")?,
        OriginValidationMode::DevelopmentLoopback,
    )?;

    assert_eq!(origin.as_url().host_str(), Some("[::1]"));
    Ok(())
}

#[test]
fn development_mode_accepts_ipv4_loopback_http() -> Result<(), Box<dyn std::error::Error>> {
    let origin = ControlPlaneOrigin::new(
        url("http://127.0.0.1:3000/")?,
        OriginValidationMode::DevelopmentLoopback,
    )?;

    assert_eq!(origin.as_url().host_str(), Some("127.0.0.1"));
    Ok(())
}

#[test]
fn development_mode_accepts_localhost_http() -> Result<(), Box<dyn std::error::Error>> {
    let origin = ControlPlaneOrigin::new(
        url("http://localhost:3000/")?,
        OriginValidationMode::DevelopmentLoopback,
    )?;

    assert_eq!(origin.as_url().host_str(), Some("localhost"));
    Ok(())
}

#[test]
fn development_mode_rejects_non_loopback_http() -> Result<(), Box<dyn std::error::Error>> {
    let error = ControlPlaneOrigin::new(
        url("http://control.firma.example/")?,
        OriginValidationMode::DevelopmentLoopback,
    )
    .err();

    assert!(matches!(
        error,
        Some(ControlPlaneOriginError::DevelopmentHttpRequiresLoopback)
    ));
    Ok(())
}
