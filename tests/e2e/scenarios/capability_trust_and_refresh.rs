use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::Deserialize;
use toml_edit::{DocumentMut, Item, Table, value};

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

struct ProbeRequest {
    nonce: String,
    probe: HttpProbe,
    url: String,
    resource: String,
    attempted: PathBuf,
    gate: PathBuf,
}

struct ObservedRequest {
    nonce: String,
    resource: String,
}

struct InitialBaseline {
    seed_path: PathBuf,
    seed: CapabilitySeed,
    marker_dir: PathBuf,
    identity: SidecarIdentity,
    pid: String,
    authority_public_key: PathBuf,
    request: ObservedRequest,
}

impl ProbeRequest {
    fn start(world: &TestWorld, name: &str, behavior: ProbeBehavior) -> Self {
        let nonce = format!("{name}-{}", uuid::Uuid::new_v4().simple());
        let probe = HttpProbe::start(&nonce, behavior);
        let url = probe.url();
        Self {
            resource: server_resource(&url),
            attempted: world.workspace_path().join(format!("{name}-attempted")),
            gate: world.workspace_path().join(format!("{name}-gate")),
            nonce,
            probe,
            url,
        }
    }

    fn wait_for_attempt(&self, description: &str, timeout: Duration) {
        wait_for(description, timeout, || {
            self.attempted.exists().then_some(())
        });
    }

    fn release(&self, description: &str) {
        std::fs::write(&self.gate, b"continue").unwrap_or_else(|error| {
            panic!("{description}: {error}");
        });
    }

    fn observe(self, description: &str, timeout: Duration) -> ObservedRequest {
        self.wait_for_attempt(description, timeout);
        let capture = self.probe.finish().unwrap_or_else(|| {
            panic!("{description} did not reach its probe");
        });
        assert_eq!(capture.path, format!("/{}", self.nonce));
        ObservedRequest {
            nonce: self.nonce,
            resource: self.resource,
        }
    }
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

    let before = ProbeRequest::start(
        &world,
        "before",
        ProbeBehavior::Respond(RESPONSE_BEFORE_REFRESH),
    );
    let after = ProbeRequest::start(
        &world,
        "after",
        ProbeBehavior::Respond(RESPONSE_AFTER_REFRESH),
    );
    let expired = ProbeRequest::start(&world, "expired", ProbeBehavior::MustNotConnect);
    let script = wrapped_refresh_script(&before, &after, &expired);

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

        let InitialBaseline {
            seed_path,
            seed: initial_seed,
            marker_dir,
            identity: identity_before,
            pid: pid_before,
            authority_public_key,
            request: before,
        } = observe_initial_baseline(&world, before);

        // Capture one changed refresh, then immediately replace the key so later tokens fail.
        let refreshed_seed = wait_for(
            "different refreshed capability seed",
            Duration::from_secs(15),
            || {
                let seed = read_toml_if_complete::<CapabilitySeed>(&seed_path)?;
                (seed.token_id != initial_seed.token_id).then_some(seed)
            },
        );
        std::fs::write(&authority_public_key, [0xa5; 32])
            .expect("replace Authority public key with mismatched key");
        assert_ne!(refreshed_seed.raw_token, initial_seed.raw_token);
        assert_ne!(refreshed_seed.issued_at, initial_seed.issued_at);
        assert_eq!(refreshed_seed.agent_id, initial_seed.agent_id);
        assert_eq!(refreshed_seed.session_id, initial_seed.session_id);

        // After the original token expires, the captured refresh must still authorize this request.
        wait_until_after(initial_seed.expiry, Duration::from_secs(10));
        assert_eq!(
            read_toml::<CapabilitySeed>(&seed_path),
            refreshed_seed,
            "no later valid token may supersede the captured changed refresh before its proof request"
        );
        after.release("release post-refresh request");
        let after = after.observe(
            "post-refresh wrapped request stimulus",
            Duration::from_secs(10),
        );
        let after_event = wait_for_audit_event(
            &world.audit_path(),
            &initial_seed.session_id,
            &after.nonce,
            Duration::from_secs(20),
        );
        assert_allowed_event(
            &after_event,
            &refreshed_seed,
            &identity_before,
            &after.resource,
        );
        assert_sidecar_unchanged(&marker_dir, &identity_before, &pid_before);

        // Later refreshes must be rejected; once the captured token expires, fail closed.
        wait_for(
            "unverified refresh rejection",
            Duration::from_secs(20),
            || {
                std::fs::read_to_string(marker_dir.join("run.log"))
                    .ok()
                    .filter(|log| log.contains("issued token failed local verification"))
            },
        );
        assert_eq!(
            read_toml::<CapabilitySeed>(&seed_path),
            refreshed_seed,
            "a rejected refresh must not replace the captured changed seed"
        );
        wait_until_after(refreshed_seed.expiry, Duration::from_secs(10));
        assert_eq!(
            read_toml::<CapabilitySeed>(&seed_path),
            refreshed_seed,
            "no later valid token may supersede the rejected refresh before fail-closed proof"
        );
        expired.release("release expired-token request");
        expired.wait_for_attempt(
            "expired-token wrapped request stimulus",
            Duration::from_secs(10),
        );

        let output = run.join().expect("join governed firma run");
        assert!(output.success(), "governed refresh run failed:\n{output}");
        assert!(
            output.stdout.contains(RESPONSE_BEFORE_REFRESH)
                && output.stdout.contains(RESPONSE_AFTER_REFRESH),
            "both intended requests must return upstream responses:\n{output}"
        );
        assert!(
            expired.probe.finish().is_none(),
            "expired token reached upstream after unverified refresh"
        );

        let before_event =
            correlated_event(&world.audit_path(), &initial_seed.session_id, &before.nonce);
        let expired_event = correlated_event(
            &world.audit_path(),
            &initial_seed.session_id,
            &expired.nonce,
        );
        assert_allowed_event(
            &before_event,
            &initial_seed,
            &identity_before,
            &before.resource,
        );
        assert_expired_event(
            &expired_event,
            &refreshed_seed,
            &identity_before,
            &expired.resource,
        );
    });
}

fn observe_initial_baseline(world: &TestWorld, before: ProbeRequest) -> InitialBaseline {
    let seed_path = wait_for("initial capability seed", Duration::from_secs(15), || {
        only_file(&world.path("state/capabilities"))
    });
    let seed = wait_for_seed(&seed_path, "initial capability seed");
    assert_eq!(
        (seed.expiry - seed.issued_at).num_seconds(),
        SHORT_TTL_SECONDS,
        "controlled Authority must clamp the capability to the short TTL"
    );
    let request = before.observe("first wrapped request stimulus", Duration::from_secs(15));

    let marker_dir = wait_for("Sidecar marker", Duration::from_secs(15), || {
        only_directory(&world.path("state/run"))
    });
    let identity = read_toml::<SidecarIdentity>(&marker_dir.join("metadata.toml"));
    let pid =
        std::fs::read_to_string(marker_dir.join("sidecar.pid")).expect("read initial Sidecar PID");
    let authority_public_key = world.path("state/authority.pub");
    assert!(
        authority_public_key.is_file(),
        "owned Authority public key must exist before observing a changed refresh"
    );

    InitialBaseline {
        seed_path,
        seed,
        marker_dir,
        identity,
        pid,
        authority_public_key,
        request,
    }
}

fn configure_capability(world: &TestWorld, public_key_path: Option<&Path>) {
    let config_path = world.config_path();
    let body = std::fs::read_to_string(&config_path).expect("read generated config");
    let mut config = body.parse::<DocumentMut>().expect("parse generated config");

    let authority = config["authority"]
        .as_table_mut()
        .expect("generated config has an Authority table");
    authority["max_ttl_seconds"] = value(SHORT_TTL_SECONDS);

    let generic = config["run"]["profiles"]["generic"]
        .as_table_mut()
        .expect("generated config has the generic run profile");
    if !generic.contains_key("capability") {
        generic.insert("capability", Item::Table(Table::new()));
    }
    let capability = generic["capability"]
        .as_table_mut()
        .expect("generic profile capability is a table");
    if let Some(path) = public_key_path {
        capability["public_key_path"] = value(path.display().to_string());
    }
    capability["refresh_ratio"] = value(0.5);
    capability["grace_seconds"] = value(1);

    std::fs::write(config_path, config.to_string()).expect("write capability test config");
}

fn wrapped_refresh_script(
    before: &ProbeRequest,
    after: &ProbeRequest,
    expired: &ProbeRequest,
) -> String {
    format!(
        "printf attempted > '{before_attempt}'; \
         curl --fail-with-body --silent --show-error --max-time 10 '{before_url}'; \
         i=0; while [ ! -f '{after_gate}' ] && [ $i -lt 400 ]; do sleep 0.05; i=$((i+1)); done; \
         [ -f '{after_gate}' ] || exit 90; \
         printf attempted > '{after_attempt}'; \
         curl --fail-with-body --silent --show-error --max-time 10 '{after_url}'; \
         i=0; while [ ! -f '{expired_gate}' ] && [ $i -lt 400 ]; do sleep 0.05; i=$((i+1)); done; \
         [ -f '{expired_gate}' ] || exit 91; \
         printf attempted > '{expired_attempt}'; \
         if curl --fail-with-body --silent --show-error --max-time 10 '{expired_url}'; then exit 92; fi",
        before_attempt = before.attempted.display(),
        before_url = before.url,
        after_gate = after.gate.display(),
        after_attempt = after.attempted.display(),
        after_url = after.url,
        expired_gate = expired.gate.display(),
        expired_attempt = expired.attempted.display(),
        expired_url = expired.url,
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

fn assert_expired_event(
    event: &AuditEvent,
    seed: &CapabilitySeed,
    identity: &SidecarIdentity,
    resource: &str,
) {
    assert_eq!(event.session_id, identity.session_id);
    assert_eq!(event.sandbox_id, identity.sandbox_id);
    assert_eq!(event.agent_id, "");
    assert_eq!(event.token_id, "");
    assert_eq!(event.action, "raw.http.GET");
    assert_eq!(event.resource, resource);
    assert_eq!(event.decision, AuditDecision::Deny);
    assert_eq!(
        event.deny_reason,
        format!("token expired: token expired: {}", seed.token_id)
    );
    assert_eq!(event.dispatch_status, 0);
}

fn assert_sidecar_unchanged(marker_dir: &Path, identity: &SidecarIdentity, pid: &str) {
    assert_eq!(
        read_toml::<SidecarIdentity>(&marker_dir.join("metadata.toml")),
        *identity
    );
    assert_eq!(
        std::fs::read_to_string(marker_dir.join("sidecar.pid"))
            .expect("read Sidecar PID after refresh"),
        pid
    );
}

fn wait_for_audit_event(path: &Path, session: &str, nonce: &str, timeout: Duration) -> AuditEvent {
    wait_for("correlated audit event", timeout, || {
        let audit = std::fs::read_to_string(path).ok()?;
        audit.lines().find_map(|line| {
            let event = serde_json::from_str::<AuditEvent>(line).ok()?;
            (event.session_id == session && event.resource.contains(nonce)).then_some(event)
        })
    })
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
