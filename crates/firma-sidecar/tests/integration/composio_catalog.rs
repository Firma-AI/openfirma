//! Coverage for the reviewed Composio catalogs shipped with the Sidecar.

use firma_sidecar::composio::ComposioCatalogs;

/// Every pinned toolkit is reviewed, complete, and reachable by exact slug.
///
/// The loader rejects unmapped slugs, unknown classes, and source/mapping
/// drift, so a successful load is the guarantee that no shipped Composio tool
/// reaches enforcement without a manually assigned action class.
#[test]
fn builtin_catalogs_expose_every_reviewed_tool() -> anyhow::Result<()> {
    let catalogs = ComposioCatalogs::builtin()?;

    assert_eq!(catalogs.len(), 279);
    assert!(!catalogs.is_empty());

    let expected = [
        ("GMAIL_SEND_EMAIL", "gmail", "communication.external.send"),
        ("GMAIL_LIST_CSE_KEYPAIRS", "gmail", "credential.read"),
        (
            "GOOGLECALENDAR_DELETE_EVENT",
            "googlecalendar",
            "calendar.delete",
        ),
        (
            "GOOGLECALENDAR_ACL_INSERT",
            "googlecalendar",
            "account.permission.change",
        ),
        ("SLACK_SEND_MESSAGE", "slack", "communication.external.send"),
        ("SLACK_READ_AUDIT_LOGS", "slack", "security.alert.read"),
    ];
    for (slug, toolkit, action_class) in expected {
        let entry = catalogs
            .lookup(slug)
            .ok_or_else(|| anyhow::anyhow!("{slug} is missing from the shipped catalogs"))?;
        assert_eq!(entry.toolkit, toolkit);
        assert_eq!(entry.version, "20260721_00");
        assert_eq!(entry.action_class, action_class);
    }

    assert!(catalogs.lookup("GMAIL_SEND_EMAIL_V2").is_none());
    Ok(())
}
