use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::audit::{AuditDecision, AuditEvent, correlated_event};
use crate::harness::TestWorld;
use crate::upstream::{HttpProbe, ProbeBehavior};

const RESPONSE_BEFORE_REFRESH: &str = "firma-e2e-before-refresh\n";
const RESPONSE_AFTER_REFRESH: &str = "firma-e2e-after-refresh\n";
const ACTION: &str = "communication.internal.send";
const SHORT_TTL_SECONDS: i64 = 6;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct CapabilitySeed {
    raw_token: String,
    token_id: String,
    agent_id: String,
    session_id: String,
    issued_at: DateTime<Utc>,
    expiry: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct SidecarIdentity {
    sandbox_id: String,
    agent_id: String,
    session_id: String,
    pid: u32,
    started_at: String,
}

#[test]
fn issued_capability_must_verify_with_configured_authority_key() {
    let world = TestWorld::new();
    let wrong_key = world.path("wrong-authority.pub");
    std::fs::write(&wrong_key, [0x5a; 32]).expect("write mismatched Authority public key");
    configure_capability(&world, Some(&wrong_key));

    let nonce = format!("untrusted-{}", uuid::Uuid::new_v4().simple());
    let attempted = world.workspace_path().join("untrusted-attempted");
    let probe = HttpProbe::start(&nonce, ProbeBehavior::MustNotConnect);
    let script = format!(
        "printf attempted > '{}'; curl --fail-with-body --silent --show-error --max-time 10 '{}'",
        attempted.display(),
        probe.url()
    );

    let output = world.run_firma(
        "generic",
        Some(&world.config_path()),
        &world.workspace_path(),
        &["--authority", "local", "--sidecar", "local"],
        "/bin/sh",
        ["-c", &script],
    );

    assert!(
        !output.success(),
        "mismatched key unexpectedly launched:\n{output}"
    );
    assert!(
        output
            .stderr
            .contains("issued token failed local verification"),
        "failure must classify the unverified Authority token:\n{output}"
    );
    assert!(
        !attempted.exists(),
        "wrapped command ran before capability verification"
    );
    assert!(
        probe.finish().is_none(),
        "unverified token reached upstream"
    );
    assert!(
        !world.audit_path().exists(),
        "unverified token must not enter Sidecar enforcement"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the uninterrupted-run proof keeps its ordered stimuli and observations in one causal sequence"
)]
fn capability_refresh_hot_loads_in_one_uninterrupted_run_and_fails_closed() {
    let world = TestWorld::new();
    configure_capability(&world, None);

    let before_nonce = format!("before-{}", uuid::Uuid::new_v4().simple());
    let after_nonce = format!("after-{}", uuid::Uuid::new_v4().simple());
    let expired_nonce = format!("expired-{}", uuid::Uuid::new_v4().simple());
    let before_probe = HttpProbe::start(
        &before_nonce,
        ProbeBehavior::Respond(RESPONSE_BEFORE_REFRESH),
    );
    let after_probe =
        HttpProbe::start(&after_nonce, ProbeBehavior::Respond(RESPONSE_AFTER_REFRESH));
    let expired_probe = HttpProbe::start(&expired_nonce, ProbeBehavior::MustNotConnect);
    let before_url = before_probe.url();
    let after_url = after_probe.url();
    let expired_url = expired_probe.url();
    let before_probe_resource = server_resource(&before_url);
    let after_probe_resource = server_resource(&after_url);
    let expired_probe_resource = server_resource(&expired_url);
    let before_attempt = world.workspace_path().join("before-attempted");
    let after_gate = world.workspace_path().join("after-gate");
    let after_attempt = world.workspace_path().join("after-attempted");
    let expired_gate = world.workspace_path().join("expired-gate");
    let expired_attempt = world.workspace_path().join("expired-attempted");
    let script = wrapped_refresh_script(
        &before_url,
        &after_url,
        &expired_url,
        &before_attempt,
        &after_gate,
        &after_attempt,
        &expired_gate,
        &expired_attempt,
    );

    std::thread::scope(|scope| {
        let run = scope.spawn(|| {
            world.run_firma(
                "generic",
                Some(&world.config_path()),
                &world.workspace_path(),
                &["--authority", "local", "--sidecar", "local"],
                "/bin/sh",
                ["-c", &script],
            )
        });

        let seed_path = wait_for("initial capability seed", Duration::from_secs(15), || {
            only_file(&world.path("state/capabilities"))
        });
        let initial_seed = wait_for_seed(&seed_path, "initial capability seed");
        assert_eq!(
            (initial_seed.expiry - initial_seed.issued_at).num_seconds(),
            SHORT_TTL_SECONDS,
            "controlled Authority must clamp the capability to the short TTL"
        );

        wait_for(
            "first wrapped request stimulus",
            Duration::from_secs(15),
            || before_attempt.exists().then_some(()),
        );
        let before_capture = before_probe
            .finish()
            .expect("first governed request reached probe");
        assert_eq!(before_capture.path, format!("/{before_nonce}"));

        let marker_dir = wait_for("Sidecar marker", Duration::from_secs(15), || {
            only_directory(&world.path("state/run"))
        });
        let identity_before = read_toml::<SidecarIdentity>(&marker_dir.join("metadata.toml"));
        let pid_before = std::fs::read_to_string(marker_dir.join("sidecar.pid"))
            .expect("read initial Sidecar PID");

        let refreshed_seed = wait_for(
            "different refreshed capability seed",
            Duration::from_secs(15),
            || {
                let seed = read_toml_if_complete::<CapabilitySeed>(&seed_path)?;
                (seed.token_id != initial_seed.token_id).then_some(seed)
            },
        );
        assert_ne!(refreshed_seed.raw_token, initial_seed.raw_token);
        assert_ne!(refreshed_seed.issued_at, initial_seed.issued_at);
        assert_eq!(refreshed_seed.agent_id, initial_seed.agent_id);
        assert_eq!(refreshed_seed.session_id, initial_seed.session_id);

        wait_for(
            "Sidecar capability hot-load",
            Duration::from_secs(10),
            || {
                std::fs::read_to_string(marker_dir.join("sidecar.log"))
                    .ok()
                    .filter(|log| log.contains("capability map hot-reloaded"))
            },
        );
        let identity_after_refresh =
            read_toml::<SidecarIdentity>(&marker_dir.join("metadata.toml"));
        let pid_after_refresh = std::fs::read_to_string(marker_dir.join("sidecar.pid"))
            .expect("read Sidecar PID after refresh");
        assert_eq!(identity_after_refresh, identity_before);
        assert_eq!(pid_after_refresh, pid_before);

        // Make all later refresh responses unverifiable to the refresher. The
        // already-running Sidecar retains its in-memory verifier and current
        // valid token, which then fails closed on its own expiry.
        let authority_public_key = world.path("state/authority.pub");
        wait_for(
            "owned Authority public key",
            Duration::from_secs(10),
            || authority_public_key.is_file().then_some(()),
        );
        std::fs::write(&authority_public_key, [0xa5; 32])
            .expect("replace Authority public key with mismatched key");

        wait_until_after(initial_seed.expiry, Duration::from_secs(10));
        std::fs::write(&after_gate, b"continue").expect("release post-refresh request");
        wait_for(
            "post-refresh wrapped request stimulus",
            Duration::from_secs(10),
            || after_attempt.exists().then_some(()),
        );
        let after_capture = after_probe
            .finish()
            .expect("post-refresh governed request reached probe");
        assert_eq!(after_capture.path, format!("/{after_nonce}"));

        wait_for(
            "unverified refresh rejection",
            Duration::from_secs(10),
            || {
                std::fs::read_to_string(marker_dir.join("run.log"))
                    .ok()
                    .filter(|log| log.contains("issued token failed local verification"))
            },
        );
        wait_until_after(refreshed_seed.expiry, Duration::from_secs(10));
        std::fs::write(&expired_gate, b"continue").expect("release expired-token request");
        wait_for(
            "expired-token wrapped request stimulus",
            Duration::from_secs(10),
            || expired_attempt.exists().then_some(()),
        );

        let output = run.join().expect("join governed firma run");
        assert!(output.success(), "governed refresh run failed:\n{output}");
        assert!(
            output.stdout.contains(RESPONSE_BEFORE_REFRESH)
                && output.stdout.contains(RESPONSE_AFTER_REFRESH),
            "both intended requests must return upstream responses:\n{output}"
        );
        assert!(
            expired_probe.finish().is_none(),
            "expired token reached upstream after unverified refresh"
        );

        let before_event =
            correlated_event(&world.audit_path(), &initial_seed.session_id, &before_nonce);
        let after_event =
            correlated_event(&world.audit_path(), &initial_seed.session_id, &after_nonce);
        let expired_event = correlated_event(
            &world.audit_path(),
            &initial_seed.session_id,
            &expired_nonce,
        );
        assert_allowed_event(
            &before_event,
            &initial_seed,
            &identity_before,
            &before_probe_resource,
        );
        assert_allowed_event(
            &after_event,
            &refreshed_seed,
            &identity_before,
            &after_probe_resource,
        );
        assert_eq!(expired_event.session_id, identity_before.session_id);
        assert_eq!(expired_event.sandbox_id, identity_before.sandbox_id);
        assert_eq!(expired_event.agent_id, "");
        assert_eq!(expired_event.token_id, "");
        assert_eq!(expired_event.action, "raw.http.GET");
        assert_eq!(expired_event.resource, expired_probe_resource);
        assert_eq!(expired_event.decision, AuditDecision::Deny);
        assert_eq!(
            expired_event.deny_reason,
            format!("token expired: token expired: {}", refreshed_seed.token_id)
        );
        assert_eq!(expired_event.dispatch_status, 0);
    });
}

fn configure_capability(world: &TestWorld, public_key_path: Option<&Path>) {
    let config_path = world.config_path();
    let config = std::fs::read_to_string(&config_path).expect("read generated config");
    let config = config.replace(
        "max_ttl_seconds = 3600",
        &format!("max_ttl_seconds = {SHORT_TTL_SECONDS}"),
    );
    assert!(
        config.contains(&format!("max_ttl_seconds = {SHORT_TTL_SECONDS}")),
        "expected generated Authority TTL"
    );
    let public_key = public_key_path.map_or_else(String::new, |path| {
        format!("public_key_path = {:?}\n", path.display().to_string())
    });
    let config = format!(
        "{config}\n[run.profiles.generic.capability]\n{public_key}refresh_ratio = 0.5\ngrace_seconds = 1\n"
    );
    std::fs::write(config_path, config).expect("write capability test config");
}

#[expect(
    clippy::too_many_arguments,
    reason = "the script's observable files are explicit test evidence"
)]
fn wrapped_refresh_script(
    before_url: &str,
    after_url: &str,
    expired_url: &str,
    before_attempt: &Path,
    after_gate: &Path,
    after_attempt: &Path,
    expired_gate: &Path,
    expired_attempt: &Path,
) -> String {
    format!(
        "printf attempted > '{before_attempt}'; \
         curl --fail-with-body --silent --show-error --max-time 10 '{before_url}'; \
         i=0; while [ ! -f '{after_gate}' ] && [ $i -lt 200 ]; do sleep 0.05; i=$((i+1)); done; \
         [ -f '{after_gate}' ] || exit 90; \
         printf attempted > '{after_attempt}'; \
         curl --fail-with-body --silent --show-error --max-time 10 '{after_url}'; \
         i=0; while [ ! -f '{expired_gate}' ] && [ $i -lt 200 ]; do sleep 0.05; i=$((i+1)); done; \
         [ -f '{expired_gate}' ] || exit 91; \
         printf attempted > '{expired_attempt}'; \
         if curl --fail-with-body --silent --show-error --max-time 10 '{expired_url}'; then exit 92; fi",
        before_attempt = before_attempt.display(),
        after_gate = after_gate.display(),
        after_attempt = after_attempt.display(),
        expired_gate = expired_gate.display(),
        expired_attempt = expired_attempt.display(),
    )
}

fn assert_allowed_event(
    event: &AuditEvent,
    seed: &CapabilitySeed,
    identity: &SidecarIdentity,
    resource: &str,
) {
    assert_eq!(event.session_id, identity.session_id);
    assert_eq!(event.sandbox_id, identity.sandbox_id);
    assert_eq!(event.agent_id, seed.agent_id);
    assert_eq!(event.token_id, seed.token_id);
    assert_eq!(event.action, ACTION);
    assert_eq!(event.resource, resource);
    assert_eq!(event.decision, AuditDecision::Allow);
    assert_eq!(event.deny_reason, "");
    assert_eq!(event.dispatch_status, 200);
}

fn server_resource(url: &str) -> String {
    url.strip_prefix("http://")
        .expect("test URL uses plain HTTP")
        .to_string()
}

fn wait_for<T>(description: &str, timeout: Duration, mut observe: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(value) = observe() {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {description}"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn wait_until_after(timestamp: DateTime<Utc>, timeout: Duration) {
    wait_for("capability expiry", timeout, || {
        (Utc::now() > timestamp + chrono::Duration::milliseconds(250)).then_some(())
    });
}

fn wait_for_seed(path: &Path, description: &str) -> CapabilitySeed {
    wait_for(description, Duration::from_secs(10), || {
        read_toml_if_complete(path)
    })
}

fn read_toml<T: for<'de> Deserialize<'de>>(path: &Path) -> T {
    let body = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    toml::from_str(&body).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn read_toml_if_complete<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|body| toml::from_str(&body).ok())
}

fn only_file(directory: &Path) -> Option<PathBuf> {
    only_entry(directory, Path::is_file)
}

fn only_directory(directory: &Path) -> Option<PathBuf> {
    only_entry(directory, Path::is_dir)
}

fn only_entry(directory: &Path, predicate: impl Fn(&Path) -> bool) -> Option<PathBuf> {
    let entries = std::fs::read_dir(directory).ok()?;
    let mut matches = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| predicate(path));
    let only = matches.next()?;
    matches.next().is_none().then_some(only)
}
