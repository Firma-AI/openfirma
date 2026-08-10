use std::net::SocketAddr;

use firma_sidecar::config::SidecarConfig;

fn load_authority(body: &str) -> Result<SidecarConfig, String> {
    let dir = tempfile::tempdir().map_err(|error| error.to_string())?;
    let path = dir.path().join("firma.toml");
    std::fs::write(&path, body).map_err(|error| error.to_string())?;
    SidecarConfig::load_from_path(&path)
}

#[test]
fn connect_addr_defaults_absent_and_parses_ip_families() {
    let default = load_authority("").expect("default config");
    assert_eq!(default.authority.connect_addr, None);

    for address in ["127.0.0.1:41000", "[::1]:42000"] {
        let config = load_authority(&format!(
            "[authority]\nurl = 'https://authority.example:443'\nconnect_addr = '{address}'\nca_cert_path = 'ca.pem'\n"
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
    assert_eq!(
        missing_url,
        "authority: connect_addr requires url to be set"
    );

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
}
