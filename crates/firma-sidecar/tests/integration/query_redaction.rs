use firma_core::ActionParams;
use firma_http::{Authority, HeaderMap, Method};
use firma_sidecar::config::{MappingRuleConfig, MappingRulesFile};
use firma_sidecar::pipeline::{ActionClassRegistry, IntentNormalizer, MappingTable, RawRequest};

fn request(path: &str) -> RawRequest {
    RawRequest {
        method: Method::GET,
        host: Authority::from_static("example.test"),
        path: path.to_string(),
        headers: HeaderMap::new(),
        body: None,
        is_https: true,
    }
}

#[test]
fn encoded_query_names_mask_values_without_rewriting_keys_or_dispatch_query() -> anyhow::Result<()>
{
    let table = MappingTable::from_config(
        &MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some(Method::GET),
                host: "example.test".to_string(),
                path: Some("/repos/*".to_string()),
                action_class: "communication.external.read".to_string(),
            }],
        },
        &ActionClassRegistry::v0_1(),
    )?;
    let raw_query = "%74oken=first&%41PI_KEY=second&%2574oken=public&my%74oken=public&ok=a+b&signature=signed&bearer=bearer-secret&token=last";
    let raw_path = format!("/repos/x?{raw_query}");
    let envelope = IntentNormalizer::new(table)
        .normalize(&request(&raw_path))
        .map_err(|decision| anyhow::anyhow!("expected classified request: {decision:?}"))?;

    assert_eq!(
        envelope.intent().resource["path"],
        "/repos/x?%74oken=[REDACTED]&%41PI_KEY=[REDACTED]&%2574oken=public&my%74oken=public&ok=a+b&signature=[REDACTED]&bearer=[REDACTED]&token=[REDACTED]"
    );
    assert_eq!(envelope.intent().raw_action_ref, format!("GET {raw_path}"));
    let ActionParams::Http(params) = &envelope.intent().params else {
        anyhow::bail!("expected HTTP params");
    };
    assert_eq!(params.query["%74oken"], "first");
    assert_eq!(params.query["%41PI_KEY"], "second");
    assert_eq!(params.query["ok"], "a+b");
    Ok(())
}

#[tokio::test]
async fn pre_normalization_audit_masks_encoded_names_after_each_supported_boundary()
-> anyhow::Result<()> {
    let pipeline = super::pipeline_fixture::pipeline()?;

    for prefix in ["?", "&", " ", "(", "[", "'", "\""] {
        let path = format!("/unmapped?ok=1{prefix}%74oken=hidden&safe=public");
        let (decision, audit) = pipeline.enforce(&request(&path), "session").await;
        assert!(
            matches!(
                decision,
                firma_sidecar::pipeline::EnforcementDecision::Deny { .. }
            ),
            "expected pre-normalization denial for {prefix:?}: {decision:?}"
        );
        assert_eq!(
            audit.resource(),
            format!("example.test/unmapped?ok=1{prefix}%74oken=[REDACTED]&safe=public")
        );
        assert!(
            audit
                .deny_reason()
                .contains(&format!("{prefix}%74oken=[REDACTED]&safe=public"))
        );
        assert!(!audit.deny_reason().contains("hidden"));
    }

    let path = "/unmapped?my%74oken=public&%2574oken=public&%74oken=hidden&signature=signed&key=key-secret&ok=1";
    let (_, audit) = pipeline.enforce(&request(path), "session").await;
    assert_eq!(
        audit.resource(),
        "example.test/unmapped?my%74oken=public&%2574oken=public&%74oken=[REDACTED]&signature=[REDACTED]&key=[REDACTED]&ok=1"
    );
    assert!(!audit.deny_reason().contains("hidden"));
    assert!(!audit.deny_reason().contains("signed"));
    assert!(!audit.deny_reason().contains("key-secret"));

    // A non-sensitive value may contain '=' without becoming another name or
    // making normalization repeatedly scan the growing value prefix.
    let value = "=".repeat(65_536);
    let path = format!("/unmapped?visible={value}&token=hidden&ok=1");
    let (_, audit) = pipeline.enforce(&request(&path), "session").await;
    assert_eq!(
        audit.resource(),
        format!("example.test/unmapped?visible={value}&token=[REDACTED]&ok=1")
    );
    assert!(!audit.deny_reason().contains("hidden"));
    Ok(())
}
