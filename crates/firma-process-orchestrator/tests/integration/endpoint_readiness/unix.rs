use super::*;

#[cfg(unix)]
#[test]
fn configured_unix_readiness_publishes_canonical_endpoint() {
    let relative = Utf8PathBuf::from("worker% socket.sock");
    let fixture = Fixture::new(ChildBehavior::ConfiguredUnix(relative.clone()));
    let socket = fixture.dir.path().join(relative.as_std_path());
    let mut stack = fixture
        .spawn_with_readiness(Readiness::Configured(unix_endpoint(socket.clone())))
        .expect("configured Unix readiness");

    assert_eq!(
        std::fs::read_to_string(fixture.state_dir.join("worker.listen"))
            .expect("read configured canonical endpoint"),
        format!("{}\n", unix_endpoint(socket.clone()))
    );
    assert_eq!(
        std::fs::read_to_string(fixture.state_dir.join("worker.listen"))
            .expect("read canonical endpoint")
            .strip_suffix('\n')
            .expect("writer newline")
            .parse::<ComponentEndpoint>(),
        Ok(unix_endpoint(socket))
    );
    stack.shutdown(Duration::ZERO).expect("shutdown fixture");
}

#[cfg(unix)]
#[test]
fn child_published_unix_readiness_publishes_connectable_canonical_endpoint() {
    let fixture = Fixture::new(ChildBehavior::PublishUnix);
    let socket = fixture.socket_path();
    let expected = unix_endpoint(socket.clone());
    let mut stack = fixture
        .spawn_endpoint(&expected)
        .expect("child-published Unix readiness");

    assert_eq!(
        std::fs::read_to_string(fixture.state_dir.join("worker.listen"))
            .expect("read canonical Unix endpoint"),
        format!("{expected}\n")
    );
    assert_eq!(
        stack
            .handle()
            .component("worker")
            .expect("worker handle")
            .endpoint(),
        &expected
    );
    std::os::unix::net::UnixStream::connect(socket).expect("connect published Unix endpoint");
    stack.shutdown(Duration::ZERO).expect("shutdown fixture");
}

#[cfg(unix)]
#[test]
fn configured_unix_readiness_fails_closed_when_socket_is_unreachable() {
    let fixture = Fixture::new(ChildBehavior::ConfiguredUnixUnavailable);
    let endpoint = unix_endpoint(fixture.socket_path());
    let timeouts = LifecycleTimeouts {
        component_readiness: Duration::from_millis(150),
        ..LifecycleTimeouts::default()
    };
    let started = std::time::Instant::now();
    let Err(error) =
        fixture.spawn_with_readiness_and_timeouts(Readiness::Configured(endpoint), timeouts)
    else {
        panic!("unreachable Unix socket must fail readiness");
    };
    assert!(matches!(
        error,
        StartError::Orchestrator(OrchestratorError::Readiness { .. })
    ));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_rollback_clean(&fixture.state_dir);
}

#[cfg(unix)]
#[test]
fn zero_timeout_does_not_attempt_unavailable_unix_readiness() {
    let fixture = Fixture::new(ChildBehavior::ConfiguredUnixUnavailable);
    let endpoint = unix_endpoint(fixture.socket_path());
    let timeouts = LifecycleTimeouts {
        component_readiness: Duration::ZERO,
        ..LifecycleTimeouts::default()
    };
    let started = std::time::Instant::now();
    let result =
        fixture.spawn_with_readiness_and_timeouts(Readiness::Configured(endpoint), timeouts);

    assert!(matches!(
        result,
        Err(StartError::Orchestrator(
            OrchestratorError::Readiness { .. }
        ))
    ));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_rollback_clean(&fixture.state_dir);
}

#[cfg(unix)]
#[test]
fn unrepresentable_unix_publications_fail_as_invalid_reports() {
    let endpoint = unix_endpoint(PathBuf::from(format!("/tmp/{}", "x".repeat(200))));
    let record = format!("protocol_version = 2\nendpoint = \"{endpoint}\"\n");

    let invalid_expected = Fixture::new(ChildBehavior::Raw(record.clone()));
    invalid_expected
        .assert_endpoint_platform_rejection(&endpoint, "invalid expected Unix endpoint");

    let invalid_published = Fixture::new(ChildBehavior::Raw(record));
    invalid_published.assert_endpoint_platform_rejection(
        &unix_endpoint(invalid_published.socket_path()),
        "invalid published Unix endpoint",
    );
}
