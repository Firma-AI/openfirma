use super::*;

#[test]
fn malformed_and_invalid_publications_fail_closed() {
    let cases = [
        ("not = valid = toml", "invalid startup report"),
        (
            "protocol_version = 1\nendpoint = \"127.0.0.1:41000\"\n",
            "unsupported protocol version 1",
        ),
        (
            "protocol_version = 3\nendpoint = \"127.0.0.1:41000\"\n",
            "unsupported protocol version 3",
        ),
        (
            "protocol_version = 2\nendpoint = \"127.0.0.2:41000\"\n",
            "does not match requested IP",
        ),
        (
            "protocol_version = 2\nendpoint = \"127.0.0.1:0\"\n",
            "effective port is zero",
        ),
    ];
    for (record, expected) in cases {
        let fixture = Fixture::new(ChildBehavior::Raw(record.to_string()));
        fixture.assert_platform_rejection(loopback_ephemeral(), expected);
    }

    let symlink = Fixture::new(ChildBehavior::Symlink);
    symlink.assert_platform_rejection(loopback_ephemeral(), "invalid startup report");

    for (behavior, expected) in [
        (ChildBehavior::Directory, "not a regular file"),
        (
            ChildBehavior::Raw("x".repeat(4_097)),
            "exceeds the size limit",
        ),
    ] {
        let fixture = Fixture::new(behavior);
        fixture.assert_platform_rejection(loopback_ephemeral(), expected);
    }
}

#[test]
fn child_exit_before_or_after_publication_fails_and_rolls_back() {
    let before = Fixture::new(ChildBehavior::ExitBeforePublication);
    before.assert_process_exit(loopback_ephemeral());

    let after = Fixture::new(ChildBehavior::PublishWithoutListener(loopback_ephemeral()));
    after.assert_process_exit(loopback_ephemeral());
}

#[test]
fn publication_and_probe_share_the_configured_timeout_budget() {
    let fixture = Fixture::new(ChildBehavior::DelayedPublishWithoutListener(
        loopback_ephemeral(),
    ));
    let marker = fixture.marker.clone();
    let state_dir = fixture.state_dir.clone();
    let startup = std::thread::spawn(move || {
        fixture.spawn_endpoint_with_timeouts(
            &ComponentEndpoint::Tcp(loopback_ephemeral()),
            LifecycleTimeouts {
                component_readiness: Duration::from_secs(3),
                ..LifecycleTimeouts::default()
            },
        )
    });

    wait_for_file(&marker);
    let published = std::time::Instant::now();
    let result = startup.join().expect("join startup");
    let elapsed_after_publication = published.elapsed();

    assert!(matches!(
        result,
        Err(StartError::Orchestrator(OrchestratorError::Readiness {
            timeout_secs: 3,
            ..
        }))
    ));
    assert!(
        elapsed_after_publication < Duration::from_secs(2),
        "elapsed after publication: {elapsed_after_publication:?}"
    );
    assert_rollback_clean(&state_dir);
}

#[test]
fn canonical_endpoint_remains_absent_while_probe_is_unvalidated() {
    let fixture = Fixture::new(ChildBehavior::PublishWithoutListener(loopback_ephemeral()));
    let marker = fixture.marker.clone();
    let state_dir = fixture.state_dir.clone();
    let startup = std::thread::spawn(move || {
        fixture.spawn("127.0.0.1:0".parse().expect("requested endpoint"))
    });

    wait_for_file(&marker);
    assert!(
        !state_dir.join("worker.listen").exists(),
        "canonical endpoint appeared before a successful TCP probe"
    );
    let startup_result = startup.join().expect("join startup");
    let Err(error) = startup_result else {
        panic!("listener-free publication must fail");
    };
    assert!(matches!(
        error,
        StartError::Orchestrator(OrchestratorError::ReadinessProcessExited { .. })
    ));
    assert_rollback_clean(&state_dir);
}

#[test]
fn later_plan_failure_sees_prior_endpoint_and_rolls_it_back() {
    let fixture = Fixture::new(ChildBehavior::Publish(loopback_ephemeral()));
    let topology = StackTopology::new(["first", "second"]).expect("valid topology");
    let requested_addr = "127.0.0.1:0".parse().expect("requested endpoint");
    let result = spawn_stack_from_plan(
        &topology,
        |context| {
            if context.name() == "first" {
                let publication = context.child_published(ComponentEndpoint::Tcp(requested_addr));
                let command = fixture.command(Some(publication.startup_report_path()));
                return Ok(ComponentSpec {
                    command,
                    readiness: publication.into_readiness(),
                });
            }
            let ready = context
                .ready_endpoint("first")
                .expect("first endpoint must be available to second planner");
            let ready = match ready {
                ComponentEndpoint::Tcp(ready) => ready,
                #[cfg(unix)]
                ComponentEndpoint::Unix(_) => {
                    panic!("dynamic child publication must remain TCP");
                }
            };
            assert_ne!(ready.port(), 0);
            assert_eq!(
                std::fs::read_to_string(fixture.state_dir.join("first.listen"))
                    .expect("canonical first endpoint")
                    .trim(),
                ready.to_string()
            );
            Err(SecondPlanFailure)
        },
        &fixture.state_dir,
        LifecycleTimeouts::default(),
    );

    assert!(matches!(result, Err(StartError::Plan(SecondPlanFailure))));
    assert_rollback_clean_named(&fixture.state_dir, &["first", "second"]);
}
