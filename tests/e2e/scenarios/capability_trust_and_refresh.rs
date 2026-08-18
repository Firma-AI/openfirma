use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use toml_edit::{DocumentMut, Item, Table, value};

use crate::audit::{AuditDecision, AuditEvent};
use crate::harness::{LiveIdentity, TestWorld};
use crate::poll::wait_for;
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
        !world.path("state/audit.jsonl").exists(),
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
    let mut run = world.start_live_governed();
    let identity = run.identity();
    let seed_path = wait_for("initial capability seed", Duration::from_secs(15), || {
        only_file(&world.path("state/capabilities"))
    });
    let initial_seed = wait_for_seed(&seed_path, "initial capability seed");
    assert_eq!(
        (initial_seed.expiry - initial_seed.issued_at).num_seconds(),
        SHORT_TTL_SECONDS,
        "controlled Authority must clamp the capability to the short TTL"
    );
    assert_eq!(initial_seed.agent_id, identity.agent_id);
    assert_eq!(initial_seed.session_id, identity.session_id);

    let authority_public_key = world.path("state/authority.pub");
    assert!(
        authority_public_key.is_file(),
        "owned Authority public key must exist before observing a changed refresh"
    );

    let before_nonce = format!("before-{}", uuid::Uuid::new_v4().simple());
    let before_probe = HttpProbe::start(
        &before_nonce,
        ProbeBehavior::Respond(RESPONSE_BEFORE_REFRESH),
    );
    let before_url = before_probe.url();
    let before_resource = before_probe.resource();
    assert_eq!(run.request(&before_nonce, &before_url), 0);
    let before_capture = before_probe
        .finish()
        .expect("initial request reached upstream");
    assert_eq!(before_capture.method, "GET");
    assert_eq!(before_capture.path, format!("/{before_nonce}"));
    let before_event = run.audit_event(&before_nonce, Duration::from_secs(20));
    assert_allowed_event(&before_event, &initial_seed, &identity, &before_resource);
    assert_eq!(run.identity(), identity);

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
    let after_nonce = format!("after-{}", uuid::Uuid::new_v4().simple());
    let after_probe =
        HttpProbe::start(&after_nonce, ProbeBehavior::Respond(RESPONSE_AFTER_REFRESH));
    let after_url = after_probe.url();
    let after_resource = after_probe.resource();
    assert_eq!(run.request(&after_nonce, &after_url), 0);
    let after_capture = after_probe
        .finish()
        .expect("post-refresh request reached upstream");
    assert_eq!(after_capture.method, "GET");
    assert_eq!(after_capture.path, format!("/{after_nonce}"));
    let after_event = run.audit_event(&after_nonce, Duration::from_secs(20));
    assert_allowed_event(&after_event, &refreshed_seed, &identity, &after_resource);
    assert_eq!(run.identity(), identity);

    // Later refreshes must be rejected; once the captured token expires, fail closed.
    let sidecar_log = world
        .path("state/run")
        .join(&identity.sandbox_id)
        .join("run.log");
    wait_for(
        "unverified refresh rejection",
        Duration::from_secs(20),
        || {
            std::fs::read_to_string(&sidecar_log)
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
    let expired_nonce = format!("expired-{}", uuid::Uuid::new_v4().simple());
    let expired_probe = HttpProbe::start(&expired_nonce, ProbeBehavior::MustNotConnect);
    let expired_url = expired_probe.url();
    let expired_resource = expired_probe.resource();
    assert_eq!(run.request(&expired_nonce, &expired_url), 22);
    assert!(
        expired_probe.finish().is_none(),
        "expired token reached upstream after unverified refresh"
    );
    let expired_event = run.audit_event(&expired_nonce, Duration::from_secs(20));
    assert_expired_event(
        &expired_event,
        &refreshed_seed,
        &identity,
        &expired_resource,
    );
    assert_eq!(run.identity(), identity);

    let output = run.finish();
    assert!(output.success(), "governed refresh run failed:\n{output}");
    assert!(
        output.stdout.contains(RESPONSE_BEFORE_REFRESH)
            && output.stdout.contains(RESPONSE_AFTER_REFRESH),
        "both intended requests must return upstream responses:\n{output}"
    );
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

fn assert_allowed_event(
    event: &AuditEvent,
    seed: &CapabilitySeed,
    identity: &LiveIdentity,
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
    identity: &LiveIdentity,
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

fn only_entry(directory: &Path, predicate: impl Fn(&Path) -> bool) -> Option<PathBuf> {
    let entries = std::fs::read_dir(directory).ok()?;
    let mut matches = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| predicate(path));
    let only = matches.next()?;
    matches.next().is_none().then_some(only)
}
