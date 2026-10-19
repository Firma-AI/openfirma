use firma_core::DenyReason;
use firma_sidecar::pipeline::EnforcementDecision;

use super::support::{Fixture, bundle, push, request, rule};

#[tokio::test]
async fn punctuation_names_redact_literal_and_encoded_queries_in_envelopes_and_audit()
-> anyhow::Result<()> {
    let mut fixture = Fixture::start().await?;
    let (_, tx) = fixture.connection().await?;
    push(&tx, bundle("query-names", vec![rule("code.read")])).await?;
    fixture.applied("query-names").await?;
    for query in [
        "auth[token]=bracket-secret&private(query)=paren-secret&private?query=query-secret&visible=value",
        "auth%5Btoken%5D=bracket-secret&private%28query%29=paren-secret&private%3Fquery=query-secret&visible=value",
    ] {
        let mut raw = request();
        raw.path = format!("/resource?{query}");
        let expected = raw
            .path
            .replace("bracket-secret", "[REDACTED]")
            .replace("paren-secret", "[REDACTED]");
        let expected = expected.replace("query-secret", "[REDACTED]");
        let (decision, audit) = fixture.observe(&raw).await?;
        let EnforcementDecision::Allow { envelope, .. } = decision else {
            anyhow::bail!("expected authorized envelope");
        };
        assert_eq!(envelope.intent().resource["path"], expected);
        assert_eq!(audit.resource, format!("example.test{expected}"));

        raw.host = "unmapped.test".parse()?;
        let (decision, audit) = fixture.observe(&raw).await?;
        std::assert_matches!(
            decision,
            EnforcementDecision::Deny {
                reason: DenyReason::UnclassifiedIntent,
                ..
            }
        );
        assert_eq!(audit.resource, format!("unmapped.test{expected}"));
        assert!(!audit.deny_reason.contains("bracket-secret"));
        assert!(!audit.deny_reason.contains("paren-secret"));
        assert!(!audit.deny_reason.contains("query-secret"));
        assert!(audit.deny_reason.contains("[REDACTED]"));
    }
    Ok(())
}
