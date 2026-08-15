use super::*;

#[test]
fn dynamic_publication_replaces_stale_canonical_only_after_validation() {
    let fixture = Fixture::new(ChildBehavior::Publish(loopback_ephemeral()));
    std::fs::create_dir_all(&fixture.state_dir).expect("create state dir");
    std::fs::write(fixture.state_dir.join("worker.listen"), "127.0.0.1:1\n")
        .expect("write stale canonical endpoint");
    let stale_publication = fixture.state_dir.join(".startup-stale/0.toml");
    std::fs::create_dir_all(stale_publication.parent().expect("stale parent"))
        .expect("create stale generation");
    publish_startup_report(
        &stale_publication,
        &ComponentEndpoint::Tcp("127.0.0.1:2".parse().expect("stale endpoint")),
    )
    .expect("write stale publication");

    let mut stack = fixture
        .spawn("127.0.0.1:0".parse().expect("requested endpoint"))
        .expect("dynamic child-published readiness");

    let effective = fixture.canonical_endpoint("worker");
    assert_eq!(effective.ip().to_string(), "127.0.0.1");
    assert_ne!(effective.port(), 0);
    assert!(
        stale_publication.exists(),
        "new generation touched stale state"
    );
    assert_current_publications_absent(&fixture.state_dir);

    stack.shutdown(Duration::ZERO).expect("shutdown fixture");
}

#[test]
fn wildcard_bind_publications_are_probed_and_published_as_family_matching_loopback() {
    for (bind_ip, dial_ip) in [("0.0.0.0", "127.0.0.1"), ("::", "::1")] {
        for fixed_port in [false, true] {
            let requested = if fixed_port {
                reserve_endpoint_for_ip(bind_ip)
            } else {
                format_endpoint(bind_ip, 0)
            };
            let fixture = Fixture::new(ChildBehavior::Publish(requested));
            let mut stack = fixture.spawn(requested).expect("wildcard readiness");
            let canonical = fixture.canonical_endpoint("worker");

            assert_eq!(canonical.ip().to_string(), dial_ip);
            assert_ne!(canonical.port(), 0);
            if fixed_port {
                assert_eq!(canonical.port(), requested.port());
            }
            std::net::TcpStream::connect(canonical).expect("dial canonical wildcard endpoint");
            stack.shutdown(Duration::ZERO).expect("shutdown fixture");
        }
    }
}

#[test]
fn wildcard_publication_is_validated_before_dial_normalization() {
    let fixture = Fixture::new(ChildBehavior::Publish(loopback_ephemeral()));
    fixture.assert_platform_rejection(
        "0.0.0.0:0".parse().expect("wildcard request"),
        "does not match requested IP",
    );
}

#[test]
fn non_wildcard_publication_is_unchanged() {
    let fixture = Fixture::new(ChildBehavior::Publish(loopback_ephemeral()));
    let mut stack = fixture
        .spawn("127.0.0.1:0".parse().expect("loopback request"))
        .expect("loopback readiness");
    let canonical = std::fs::read_to_string(fixture.state_dir.join("worker.listen"))
        .expect("read loopback canonical endpoint");
    assert!(canonical.starts_with("127.0.0.1:"));
    stack.shutdown(Duration::ZERO).expect("shutdown fixture");
}

#[test]
fn fixed_publication_requires_the_exact_requested_endpoint() {
    let requested = reserve_endpoint();
    let fixture = Fixture::new(ChildBehavior::Publish(requested));
    let mut stack = fixture
        .spawn(requested)
        .expect("fixed endpoint attestation");
    assert_eq!(
        std::fs::read_to_string(fixture.state_dir.join("worker.listen"))
            .expect("read canonical endpoint"),
        format!("{requested}\n")
    );
    stack.shutdown(Duration::ZERO).expect("shutdown fixture");

    let requested_listener = TcpListener::bind(loopback_ephemeral()).expect("reserve endpoint");
    let requested = requested_listener.local_addr().expect("reserved endpoint");
    let mismatch = Fixture::new(ChildBehavior::Publish(loopback_ephemeral()));
    mismatch.assert_platform_rejection(requested, "does not match requested");
    drop(requested_listener);
}

#[test]
fn configured_tcp_readiness_preserves_fixed_endpoint_behavior() {
    let requested = reserve_endpoint();
    let fixture = Fixture::new(ChildBehavior::Configured(requested));
    let mut stack = fixture
        .spawn_with_readiness(Readiness::Configured(ComponentEndpoint::Tcp(requested)))
        .expect("configured TCP readiness");

    assert_eq!(
        std::fs::read_to_string(fixture.state_dir.join("worker.listen"))
            .expect("read configured canonical endpoint"),
        format!("{requested}\n")
    );
    assert_current_publications_absent(&fixture.state_dir);
    stack.shutdown(Duration::ZERO).expect("shutdown fixture");
}

#[test]
fn configured_ipv4_wildcard_publishes_and_retains_connectable_endpoint() {
    let requested = reserve_endpoint_for_ip("0.0.0.0");
    let fixture = Fixture::new(ChildBehavior::Configured(requested));
    let mut stack = fixture
        .spawn_with_readiness(Readiness::Configured(ComponentEndpoint::Tcp(requested)))
        .expect("configured wildcard readiness");
    let effective = ComponentEndpoint::Tcp(SocketAddr::from((
        std::net::Ipv4Addr::LOCALHOST,
        requested.port(),
    )));

    assert_eq!(
        stack
            .handle()
            .component("worker")
            .expect("worker handle")
            .endpoint(),
        &effective
    );
    assert_eq!(
        std::fs::read_to_string(fixture.state_dir.join("worker.listen"))
            .expect("read configured canonical endpoint"),
        format!("{effective}\n")
    );
    let ComponentEndpoint::Tcp(effective) = effective else {
        unreachable!("effective endpoint is TCP");
    };
    std::net::TcpStream::connect(effective).expect("dial configured wildcard endpoint");
    stack.shutdown(Duration::ZERO).expect("shutdown fixture");
}
