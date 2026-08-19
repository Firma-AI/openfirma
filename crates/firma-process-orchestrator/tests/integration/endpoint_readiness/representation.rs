use super::*;

#[test]
fn endpoint_state_representation_round_trips_and_preserves_tcp_bytes() {
    let tcp = ComponentEndpoint::Tcp("127.0.0.1:41000".parse().expect("TCP endpoint"));
    assert_eq!(tcp.to_string(), "127.0.0.1:41000");
    assert_eq!(tcp.to_string().parse::<ComponentEndpoint>(), Ok(tcp));
    let decoded: OwnedEndpointRecord =
        toml::from_str("endpoint = \"127.0.0.1:41000\"\n").expect("deserialize TCP endpoint");
    assert_eq!(
        decoded.endpoint,
        ComponentEndpoint::Tcp("127.0.0.1:41000".parse().expect("TCP endpoint"))
    );

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt as _;

        let unix = unix_endpoint("/tmp/firma socket.sock");
        assert_eq!(unix.to_string(), "unix:/tmp/firma socket.sock");
        assert_eq!(
            unix.to_string().parse::<ComponentEndpoint>(),
            Ok(unix.clone())
        );
        assert_eq!(
            toml::to_string(&EndpointRecord { endpoint: &unix }).expect("serialize Unix endpoint"),
            "endpoint = \"unix:/tmp/firma socket.sock\"\n"
        );
        assert!(UnixEndpoint::new("/tmp/firma\n.sock").is_err());
        assert!(UnixEndpoint::new("/tmp/firma\0.sock").is_err());
        assert!(
            UnixEndpoint::new(PathBuf::from(std::ffi::OsString::from_vec(
                b"/tmp/firma-\xff.sock".to_vec()
            )))
            .is_err()
        );
    }
}

#[test]
fn publication_is_atomic_and_no_clobber() {
    let dir = tempfile::tempdir().expect("publication dir");
    let path = dir.path().join("endpoint.toml");
    let first = "127.0.0.1:41000".parse().expect("first endpoint");
    publish_startup_report(&path, &ComponentEndpoint::Tcp(first)).expect("initial publication");
    let original = std::fs::read_to_string(&path).expect("read initial publication");

    let error = publish_startup_report(
        &path,
        &ComponentEndpoint::Tcp("127.0.0.1:42000".parse().expect("second endpoint")),
    )
    .expect_err("publication must not replace an existing path");
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(
        std::fs::read_to_string(path).expect("read retained publication"),
        original
    );
}
