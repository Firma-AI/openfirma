use std::net::SocketAddr;

use super::state_layout::empty_state_beside;
use firma_sidecar::config::{AuthorityEndpoint, SidecarConfig};

fn load_authority(body: &str) -> Result<SidecarConfig, String> {
    let dir = tempfile::tempdir().map_err(|error| error.to_string())?;
    let path = dir.path().join("firma.toml");
    std::fs::write(&path, body).map_err(|error| error.to_string())?;
    SidecarConfig::load_from_path(&path, &empty_state_beside(&path))
        .map_err(|error| error.to_string())
}

#[test]
fn a_sidecar_requires_an_explicit_authority_endpoint() {
    for body in ["", "[authority]\nurl = ''", "[authority]\nurl = '   '"] {
        let error = load_authority(body).expect_err("Authority endpoint is mandatory");
        insta::allow_duplicates! { insta::assert_snapshot!(error, @"authority: sidecar.authority.url is required"); }
    }
}

#[test]
fn connect_addr_defaults_absent_and_parses_ip_families() {
    let default =
        load_authority("[authority]\nurl = 'http://localhost:50051'\n").expect("default config");
    assert_eq!(default.authority.connect_addr, None);

    for address in ["127.0.0.1:41000", "[::1]:42000"] {
        let config = load_authority(&format!(
            "[authority]\nurl = 'https://authority.example:443'\nconnect_addr = '{address}'\nca_cert_paths = ['ca.pem']\n"
        ))
        .expect("valid connect address");
        assert_eq!(
            config.authority.connect_addr,
            Some(address.parse::<SocketAddr>().expect("fixture address"))
        );
    }
}

#[test]
fn connect_addr_requires_url_and_nonzero_port() {
    let missing_url = load_authority("[authority]\nconnect_addr = '127.0.0.1:41000'\n")
        .expect_err("connect address without URL must fail");
    assert_eq!(missing_url, "authority: sidecar.authority.url is required");

    let zero_port = load_authority(
        "[authority]\nurl = 'http://localhost:50051'\nconnect_addr = '127.0.0.1:0'\n",
    )
    .expect_err("zero connect port must fail");
    assert_eq!(zero_port, "authority: connect_addr port must be > 0");

    let missing_logical_host =
        load_authority("[authority]\nurl = 'http://:50051'\nconnect_addr = '127.0.0.1:41000'\n")
            .expect_err("connect address must not make a hostless logical URL valid");
    assert_eq!(missing_logical_host, "authority: url must include a host");
}

#[test]
fn connect_addr_rejects_unspecified_ip() {
    for address in ["0.0.0.0:41000", "[::]:41000"] {
        let error = load_authority(&format!(
            "[authority]\nurl = 'http://localhost:50051'\nconnect_addr = '{address}'\n"
        ))
        .expect_err("unspecified connect IP must fail");
        assert_eq!(error, "authority: connect_addr IP must not be unspecified");
    }
}

#[test]
fn plaintext_locality_uses_physical_connect_address() {
    let error = load_authority(
        "[authority]\nurl = 'http://localhost:50051'\nconnect_addr = '192.0.2.10:50051'\n",
    )
    .expect_err("remote plaintext destination must require opt-in");
    assert_eq!(
        error,
        "authority.url uses insecure http:// for a non-loopback host; either switch to https:// or set authority.allow_insecure_remote_authority = true"
    );

    load_authority(
        "[authority]\nurl = 'http://localhost:50051'\nconnect_addr = '192.0.2.10:50051'\nallow_insecure_remote_authority = true\n",
    )
    .expect("explicit remote plaintext opt-in");

    load_authority(
        "[authority]\nurl = 'http://localhost:50051'\nconnect_addr = '[::ffff:127.0.0.1]:50051'\n",
    )
    .expect("an IPv4 loopback route written as IPv4-mapped IPv6 stays on this host");
}

/// A trailing dot makes `localhost.` this machine, where the local CA
/// applies, but not a plaintext loopback destination: that rule stays the
/// strict one.
#[test]
fn a_trailing_dot_localhost_is_this_host_but_not_a_plaintext_loopback() {
    let plaintext = load_authority("[authority]\nurl = 'http://localhost.:50051'\n")
        .expect_err("plain http to a trailing-dot localhost must not be read as loopback");
    assert_eq!(
        plaintext,
        "authority.url uses insecure http:// for a non-loopback host; either switch to https:// or set authority.allow_insecure_remote_authority = true"
    );

    let https = load_authority("[authority]\nurl = 'https://localhost.:9443'\n")
        .expect_err("https to a trailing-dot localhost is on this host, so it needs the local CA");
    assert!(
        https.starts_with(
            "authority.ca_cert_paths must be set when authority.url uses https:// on this host"
        ),
        "{https}"
    );
}

/// The audit URL is the Authority's origin when scheme, host and effective
/// port agree, whatever the spelling: case, a trailing dot, the default port
/// and the IPv4-mapped form of a loopback address do not count.
#[test]
fn an_audit_url_has_the_authority_origin_up_to_its_spelling() {
    for (authority, audit, same) in [
        ("https://h", "https://h:443", true),
        ("https://H.", "https://h", true),
        ("http://h:80", "http://h", true),
        (
            "https://[::ffff:127.0.0.1]:9443",
            "https://127.0.0.1:9443",
            true,
        ),
        ("http://h:443", "https://h", false),
        ("https://h", "https://h:8443", false),
        ("https://h", "https://h.example", false),
    ] {
        let endpoint = AuthorityEndpoint::new(authority, None).expect("fixture endpoint");
        let uri: hyper::Uri = audit.parse().expect("fixture uri");
        assert_eq!(
            endpoint.has_origin_of(&uri),
            same,
            "{authority} against {audit}"
        );
    }
}
