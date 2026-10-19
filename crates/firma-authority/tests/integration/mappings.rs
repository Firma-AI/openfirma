use std::fmt::Write as _;
use std::num::NonZeroU32;
use std::path::Path;
use std::time::Duration;

use firma_authority::{AuthorityConfig, AuthorityConfigBuilder, CedarPolicyStore, Server};
use firma_config_schema::authority::AuthorityConfig as Schema;
use firma_protobuf::v1::authority_service_client::AuthorityServiceClient;
use firma_protobuf::v1::{
    PolicyBundle, PolicyBundleCapability, PolicyBundleUpdate, WatchPolicyBundleRequest,
};
use firma_runtime_state::RuntimeLayout;

use firma_test_helpers::bounded::{self as support, step};

const BUNDLE_TTL: NonZeroU32 = NonZeroU32::new(30).unwrap();

fn config(root: &Path, mapping: &Path) -> anyhow::Result<AuthorityConfig> {
    let policies = root.join("policies");
    std::fs::create_dir_all(&policies)?;
    std::fs::write(
        policies.join("permit.cedar"),
        "permit(principal, action, resource);",
    )?;
    let keys = firma_authority::write_keypair(&root.join("authority.key"))?;
    AuthorityConfigBuilder::new(
        Schema {
            listen_addr: "127.0.0.1:0".into(),
            policy_dir: policies.clone(),
            issuance_policy_dir: policies,
            mapping_rules_paths: vec![mapping.to_path_buf()],
            key_file: Some(keys.secret),
            bundle_ttl: Duration::from_secs(10).try_into()?,
            ..Schema::default()
        },
        &RuntimeLayout::from_root(root),
    )
    .without_tls()
    .build()
    .map_err(Into::into)
}

fn rules(action: &str) -> String {
    format!(
        "[[rules]]\nmethod = 'GET'\nhost = 'API.TEST.:443'\npath = '/request'\naction_class = '{action}'\n"
    )
}

const STEP_LIMIT: Duration = Duration::from_secs(10);

struct RunningAuthority {
    client: AuthorityServiceClient<tonic::transport::Channel>,
    shutdown: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

async fn start(config: AuthorityConfig) -> anyhow::Result<RunningAuthority> {
    let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = Server::try_new(config, async {
        let _ = shutdown_rx.await;
    });
    let server = step("start the Authority", STEP_LIMIT, server).await??;
    let endpoint = format!("http://127.0.0.1:{}", server.port());
    let task = tokio::spawn(server.run());
    let client = AuthorityServiceClient::connect(endpoint);
    let client = step("connect to the Authority", STEP_LIMIT, client).await??;
    Ok(RunningAuthority {
        client,
        shutdown,
        task,
    })
}

impl RunningAuthority {
    async fn watch(
        &mut self,
        current_version: String,
        supported_capabilities: Vec<i32>,
    ) -> anyhow::Result<Result<tonic::Streaming<PolicyBundleUpdate>, tonic::Status>> {
        let response = self.client.watch_policy_bundle(WatchPolicyBundleRequest {
            current_version,
            credentials: None,
            supported_capabilities,
        });
        let response = step("open a policy bundle watch", STEP_LIMIT, response).await?;
        Ok(response.map(tonic::Response::into_inner))
    }

    async fn watch_snapshots(
        &mut self,
        current_version: String,
    ) -> anyhow::Result<tonic::Streaming<PolicyBundleUpdate>> {
        let capabilities = vec![PolicyBundleCapability::ActionMappingSnapshotV1 as i32];
        Ok(self.watch(current_version, capabilities).await??)
    }

    async fn stop(self) -> anyhow::Result<()> {
        drop(self.client);
        self.shutdown
            .send(())
            .map_err(|()| anyhow::anyhow!("server stopped"))?;
        step("stop the Authority", STEP_LIMIT, self.task).await???;
        Ok(())
    }
}

async fn next(stream: &mut tonic::Streaming<PolicyBundleUpdate>) -> anyhow::Result<PolicyBundle> {
    step(
        "receive a snapshot",
        Duration::from_secs(12),
        stream.message(),
    )
    .await??
    .and_then(|update| update.bundle)
    .ok_or_else(|| anyhow::anyhow!("missing enforcement bundle"))
}

fn assert_rule(bundle: &PolicyBundle, action: &str) -> anyhow::Result<()> {
    let snapshot = bundle
        .mappings
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing mappings"))?;
    assert_eq!(snapshot.format_version, 1);
    assert!(snapshot.default_protected);
    assert_eq!(snapshot.rules.len(), 1);
    assert_eq!(snapshot.rules[0].host, "api.test");
    assert_eq!(snapshot.rules[0].method.as_deref(), Some("GET"));
    assert_eq!(snapshot.rules[0].path.as_deref(), Some("/request"));
    assert_eq!(snapshot.rules[0].action_class, action);
    Ok(())
}

#[test]
fn mapping_replacements_publish_complete_versions_and_invalid_reload_retains_generation()
-> anyhow::Result<()> {
    support::run(async {
        let root = tempfile::tempdir()?;
        let mapping = root.path().join("mappings.toml");
        std::fs::write(&mapping, rules("code.read"))?;
        let mut schema = config(root.path(), &mapping)?.to_schema()?;
        // Each check below that a write left the generation unchanged waits for
        // one refresh (half the TTL). A short TTL keeps those waits cheap while
        // staying well above the reload latency they must cover.
        schema.bundle_ttl = Duration::from_secs(2).try_into()?;
        // Exercise serialization and builder extraction, as Run does at spawn.
        let body = toml::to_string(&schema)?;
        let config =
            AuthorityConfigBuilder::from_toml_str(&body, &RuntimeLayout::from_root(root.path()))?
                .without_tls()
                .build()?;
        let mut authority = start(config).await?;
        for supported_capabilities in [Vec::new(), vec![999]] {
            let error = authority
                .watch(String::new(), supported_capabilities)
                .await?
                .err()
                .ok_or_else(|| anyhow::anyhow!("unsupported consumer admitted"))?;
            assert_eq!(error.code(), tonic::Code::FailedPrecondition);
            assert_eq!(
                error.message(),
                "complete enforcement snapshots require action mapping support"
            );
        }
        let mut stream = authority.watch_snapshots(String::new()).await?;
        let initial = next(&mut stream).await?;
        assert_rule(&initial, "code.read")?;
        let mut accepted = initial;
        for action in ["code.write", "code.review.read"] {
            let replacement = root.path().join("replacement.toml");
            std::fs::write(&replacement, rules(action))?;
            std::fs::rename(&replacement, &mapping)?;
            let previous = accepted.version.clone();
            let replaced = async {
                loop {
                    let candidate = next(&mut stream).await?;
                    if candidate.version != previous {
                        break Ok::<_, anyhow::Error>(candidate);
                    }
                }
            };
            accepted = step("receive the replacement", Duration::from_secs(12), replaced).await??;
            assert_rule(&accepted, action)?;
            assert_ne!(accepted.version, previous);
            assert_eq!(accepted.policies, initial_policy());
        }
        for invalid in [
            "[[rules]]\nhost = '*. '\naction_class = 'code.read'\n".to_string(),
            format!("{}{}", rules("code.read"), rules("code.write")),
        ] {
            std::fs::write(&mapping, invalid)?;
            let refreshed = next(&mut stream).await?;
            assert_eq!(refreshed, accepted);
        }
        let mut oversized = String::new();
        let path = "x".repeat(4096);
        for index in 0..4200 {
            write!(
                oversized,
                "[[rules]]\nhost = 'host{index}.test'\npath = '{path}'\naction_class = 'code.read'\n"
            )?;
        }
        std::fs::write(&mapping, oversized)?;
        let error = CedarPolicyStore::load_with_mappings(
            &root.path().join("policies"),
            None,
            NonZeroU32::new(10).unwrap(),
            vec![mapping.clone()],
        )
        .err()
        .ok_or_else(|| anyhow::anyhow!("oversized complete generation accepted"))?;
        assert_eq!(
            error.to_string(),
            "enforcement snapshot exceeds the 16 MiB stream limit"
        );
        // Both startup admission and later refresh use the same complete-message budget.
        assert_eq!(next(&mut stream).await?, accepted);
        assert_eq!(next(&mut stream).await?, accepted);
        drop(stream);
        authority.stop().await?;
        support::remove_dir(root).await
    })
}

fn initial_policy() -> Vec<u8> {
    b"permit(principal, action, resource);".to_vec()
}

#[test]
fn complete_stream_size_budget_matches_prost_at_the_inclusive_limit() -> anyhow::Result<()> {
    use prost::Message as _;

    let root = tempfile::tempdir()?;
    let mapping = root.path().join("empty.toml");
    std::fs::write(&mapping, "rules = []\n")?;
    let mut policies = "permit(principal, action, resource);\n//".to_string();
    let mut update = firma_protobuf::v1::PolicyBundleUpdate {
        bundle: Some(PolicyBundle {
            version: "v".repeat(64),
            policies: policies.as_bytes().to_vec(),
            entity_schema: firma_core::cedar::FIRMA_SCHEMA.as_bytes().to_vec(),
            ttl_seconds: 30,
            mappings: Some(firma_protobuf::v1::ActionMappingSnapshot {
                format_version: 1,
                default_protected: true,
                rules: Vec::new(),
            }),
        }),
        updated_at: Some(prost_types::Timestamp {
            seconds: i64::MIN,
            nanos: i32::MIN,
        }),
        policy_set: None,
    };
    let limit = 16 * 1024 * 1024;
    // Crossing the bundle length delimiter adds bytes too; prost is the oracle.
    policies.push_str(&"x".repeat(limit - update.encoded_len() - 10));
    loop {
        update
            .bundle
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("fixture bundle"))?
            .policies = policies.as_bytes().to_vec();
        if update.encoded_len() >= limit {
            break;
        }
        policies.push('x');
    }
    assert_eq!(update.encoded_len(), limit);
    let policy_path = root.path().join("permit.cedar");
    std::fs::write(&policy_path, &policies)?;
    CedarPolicyStore::load_with_mappings(root.path(), None, BUNDLE_TTL, vec![mapping.clone()])?;

    policies.push('x');
    update
        .bundle
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("fixture bundle"))?
        .policies = policies.as_bytes().to_vec();
    assert_eq!(update.encoded_len(), limit + 1);
    std::fs::write(&policy_path, policies)?;
    let error = CedarPolicyStore::load_with_mappings(root.path(), None, BUNDLE_TTL, vec![mapping])
        .err()
        .ok_or_else(|| anyhow::anyhow!("over-limit stream message admitted"))?;
    insta::assert_snapshot!(error.to_string(), @"enforcement snapshot exceeds the 16 MiB stream limit");
    Ok(())
}

#[test]
fn direct_store_construction_validates_sources() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let missing_sources =
        CedarPolicyStore::load_with_mappings(root.path(), None, BUNDLE_TTL, Vec::new())
            .err()
            .ok_or_else(|| anyhow::anyhow!("accepted absent sources"))?;
    insta::assert_snapshot!(missing_sources.to_string(), @"authority.mapping_rules_paths must contain at least one mapping file");
    let mapping = root.path().join("explicit-empty.toml");
    std::fs::write(
        root.path().join("permit.cedar"),
        "permit(principal, action, resource);",
    )?;
    std::fs::write(&mapping, "rules = []\n")?;
    let store =
        CedarPolicyStore::load_with_mappings(root.path(), None, NonZeroU32::MIN, vec![mapping])?;
    // Construction admits explicit deny-all without inventing a mapping source.
    drop(store);
    Ok(())
}

#[test]
fn unchanged_snapshots_refresh_before_short_ttls_expire() -> anyhow::Result<()> {
    support::run(async {
        for ttl in [1, 2] {
            let root = tempfile::tempdir()?;
            let mapping = root.path().join("mappings.toml");
            std::fs::write(&mapping, rules("code.read"))?;
            let mut schema = config(root.path(), &mapping)?.to_schema()?;
            schema.bundle_ttl = Duration::from_secs(ttl).try_into()?;
            let config =
                AuthorityConfigBuilder::new(schema, &RuntimeLayout::from_root(root.path()))
                    .without_tls()
                    .build()?;
            let mut authority = start(config).await?;
            let mut stream = authority.watch_snapshots(String::new()).await?;
            let initial = next(&mut stream).await?;
            assert_eq!(u64::from(initial.ttl_seconds), ttl);
            for _ in 0..2 {
                let refresh = next(&mut stream);
                let refreshed =
                    step("receive the refresh", Duration::from_secs(ttl), refresh).await??;
                assert_eq!(refreshed, initial);
            }
            drop(stream);
            authority.stop().await?;
            support::remove_dir(root).await?;
        }
        Ok(())
    })
}

#[test]
fn authored_catch_all_promotion_and_malformed_ports_fail_before_publication() -> anyhow::Result<()>
{
    let root = tempfile::tempdir()?;
    std::fs::write(
        root.path().join("permit.cedar"),
        "permit(principal, action, resource);",
    )?;
    let mapping = root.path().join("mapping.toml");
    for (host, expected) in [
        (
            "*.",
            "host pattern '*.' would normalize to the bare catch-all '*'; write '*' explicitly if that is intended",
        ),
        (
            "*:443",
            "host pattern '*:443' would normalize to the bare catch-all '*'; write '*' explicitly if that is intended",
        ),
        (
            "*.:8443",
            "host pattern '*.:8443' would normalize its name to the catch-all '*'; write the '*' explicitly if that is intended",
        ),
    ] {
        std::fs::write(
            &mapping,
            format!("[[rules]]\nhost = '{host}'\naction_class = 'code.read'\n"),
        )?;
        let error = CedarPolicyStore::load_with_mappings(
            root.path(),
            None,
            BUNDLE_TTL,
            vec![mapping.clone()],
        )
        .err()
        .ok_or_else(|| anyhow::anyhow!("accepted catch-all promotion {host}"))?;
        assert_eq!(error.root_cause().to_string(), expected);
    }
    for host in [
        "api.test:bad",
        "api.test:0",
        "api.test:8443:*",
        "api.test:******",
    ] {
        std::fs::write(
            &mapping,
            format!("[[rules]]\nhost = '{host}'\naction_class = 'code.read'\n"),
        )?;
        let error = CedarPolicyStore::load_with_mappings(
            root.path(),
            None,
            BUNDLE_TTL,
            vec![mapping.clone()],
        )
        .err()
        .ok_or_else(|| anyhow::anyhow!("accepted invalid port {host}"))?;
        let expected = if host == "api.test:8443:*" {
            "host pattern 'api.test:8443:*' is not a valid authority; use at most one port suffix and bracket IPv6 literals"
        } else {
            "invalid normalized host"
        };
        assert_eq!(error.root_cause().to_string(), expected);
    }
    Ok(())
}

/// The `current_version` a reconnecting Sidecar reports is advisory: the
/// protocol promises a complete initial snapshot on every connection, because
/// receipt is what renews the consumer's freshness deadline. Withholding it
/// until the half-TTL refresh lets a snapshot that was fresh at reconnect
/// expire before the next send, and the Sidecar denies everything meanwhile.
#[test]
fn reconnect_with_the_current_version_still_receives_the_initial_snapshot() -> anyhow::Result<()> {
    support::run(async {
        let root = tempfile::tempdir()?;
        let mapping = root.path().join("mappings.toml");
        std::fs::write(&mapping, rules("code.read"))?;
        let mut authority = start(config(root.path(), &mapping)?).await?;
        let mut first = authority.watch_snapshots(String::new()).await?;
        let accepted = next(&mut first).await?;
        drop(first);

        let mut reconnected = authority.watch_snapshots(accepted.version.clone()).await?;
        // The configured TTL is 10 s, so a half-TTL refresh cannot arrive in time.
        let initial = reconnected.message();
        let initial = step(
            "receive the snapshot after reconnecting",
            Duration::from_secs(1),
            initial,
        )
        .await??
        .and_then(|update| update.bundle)
        .ok_or_else(|| anyhow::anyhow!("missing enforcement bundle"))?;
        assert_eq!(initial, accepted);

        drop(reconnected);
        authority.stop().await?;
        support::remove_dir(root).await
    })
}

/// Startup and hot-reload failures are the operator's only signal that a
/// mapping edit was rejected, so they must name the authored file that broke
/// the generation, not only the rule-level cause.
#[test]
fn rejected_mapping_rules_name_their_source_file() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::write(
        root.path().join("permit.cedar"),
        "permit(principal, action, resource);",
    )?;
    let valid = root.path().join("valid.toml");
    std::fs::write(&valid, rules("code.read"))?;
    let invalid = root.path().join("invalid.toml");
    std::fs::write(
        &invalid,
        "[[rules]]\nhost = 'other.test'\naction_class = 'code.read'\n\n\
         [[rules]]\nhost = 'api.test:0'\naction_class = 'code.read'\n",
    )?;
    let duplicate = root.path().join("duplicate.toml");
    std::fs::write(&duplicate, rules("code.write"))?;

    for (culprit, cause) in [
        (&invalid, "invalid normalized host"),
        (&duplicate, "duplicate mapping matcher"),
    ] {
        let paths = vec![valid.clone(), culprit.clone()];
        let error = CedarPolicyStore::load_with_mappings(root.path(), None, BUNDLE_TTL, paths)
            .err()
            .ok_or_else(|| anyhow::anyhow!("invalid mapping generation accepted"))?;
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains(&culprit.display().to_string()),
            "error does not name {}: {rendered}",
            culprit.display()
        );
        assert!(rendered.contains(cause), "cause lost: {rendered}");
    }
    Ok(())
}

/// Former Sidecar mapping files move verbatim into
/// `[authority].mapping_rules_paths`. The Sidecar accepted `path = ""` as a
/// rule that matches no request (corpus
/// `match-empty-path-pattern-matches-no-normalized-path`), so publishing it as
/// an omitted, any-path matcher would classify traffic the Sidecar used to
/// deny. Such a rule is still validated and still duplicates an omitted path,
/// but it never reaches the snapshot.
#[tokio::test]
async fn authored_empty_path_rules_match_nothing_instead_of_every_path() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let mapping = root.path().join("mappings.toml");
    std::fs::write(
        &mapping,
        format!(
            "[[rules]]\nmethod = 'GET'\nhost = 'api.test'\npath = ''\naction_class = 'code.write'\n{}",
            rules("code.read")
        ),
    )?;
    let config = config(root.path(), &mapping)?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = Server::try_new(config, async {
        let _ = shutdown_rx.await;
    })
    .await?;
    let endpoint = format!("http://127.0.0.1:{}", server.port());
    let task = tokio::spawn(server.run());
    let mut client = AuthorityServiceClient::connect(endpoint).await?;
    let mut stream = client
        .watch_policy_bundle(WatchPolicyBundleRequest {
            current_version: String::new(),
            credentials: None,
            supported_capabilities: vec![PolicyBundleCapability::ActionMappingSnapshotV1 as i32],
        })
        .await?
        .into_inner();
    assert_rule(&next(&mut stream).await?, "code.read")?;

    drop(stream);
    drop(client);
    shutdown_tx
        .send(())
        .map_err(|()| anyhow::anyhow!("server stopped"))?;
    tokio::time::timeout(Duration::from_secs(5), task).await???;

    std::fs::write(
        &mapping,
        "[[rules]]\nhost = 'api.test'\naction_class = 'code.read'\n\n\
         [[rules]]\nhost = 'api.test'\npath = ''\naction_class = 'code.write'\n",
    )?;
    let error = CedarPolicyStore::load_with_mappings(
        &root.path().join("policies"),
        None,
        BUNDLE_TTL,
        vec![mapping],
    )
    .err()
    .ok_or_else(|| anyhow::anyhow!("empty path did not duplicate the omitted path"))?;
    assert!(
        format!("{error:#}").contains("duplicate mapping matcher"),
        "{error:#}"
    );
    Ok(())
}

/// Mounted configuration (for example a Kubernetes `ConfigMap`) reaches each
/// mapping file through a `..data` symlink, here through a subdirectory link,
/// and publishes each update by retargeting `..data` and deleting the previous
/// revision. No event in the file's own directory names the change, and a
/// watch registered through the link follows the deleted revision.
#[cfg(unix)]
#[test]
fn retargeting_a_mounted_mapping_publishes_every_update() -> anyhow::Result<()> {
    use std::os::unix::fs::symlink;

    support::run(async {
        let root = tempfile::tempdir()?;
        let mount = root.path().join("mount");
        let revisions = [
            ("..v1", "code.read"),
            ("..v2", "code.write"),
            ("..v3", "code.review.read"),
        ];
        for (revision, action) in revisions {
            std::fs::create_dir_all(mount.join(revision).join("mappings"))?;
            std::fs::write(
                mount.join(revision).join("mappings/rules.toml"),
                rules(action),
            )?;
        }
        symlink("..v1", mount.join("..data"))?;
        symlink("..data/mappings", mount.join("mappings"))?;
        let mapping = mount.join("mappings/rules.toml");
        let mut authority = start(config(root.path(), &mapping)?).await?;
        let mut stream = authority.watch_snapshots(String::new()).await?;
        let mut accepted = next(&mut stream).await?;
        assert_rule(&accepted, "code.read")?;

        for pair in revisions.windows(2) {
            let [(previous, _), (revision, action)] = pair else {
                unreachable!("windows of two");
            };
            symlink(revision, mount.join("..data_tmp"))?;
            std::fs::rename(mount.join("..data_tmp"), mount.join("..data"))?;
            std::fs::remove_dir_all(mount.join(previous))?;
            let version = accepted.version.clone();
            let replaced = async {
                loop {
                    let candidate = next(&mut stream).await?;
                    if candidate.version != version {
                        break Ok::<_, anyhow::Error>(candidate);
                    }
                }
            };
            accepted = step(
                "receive the retargeted rules",
                Duration::from_secs(12),
                replaced,
            )
            .await??;
            assert_rule(&accepted, action)?;
        }

        drop(stream);
        authority.stop().await?;
        support::remove_dir(root).await
    })
}
