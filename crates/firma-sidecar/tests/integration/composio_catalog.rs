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

    assert_eq!(catalogs.len(), 335);
    assert!(!catalogs.is_empty());

    let expected = [
        (
            "GMAIL_SEND_EMAIL",
            "gmail",
            "20260721_00",
            "communication.external.send",
        ),
        (
            "GMAIL_LIST_CSE_KEYPAIRS",
            "gmail",
            "20260721_00",
            "credential.read",
        ),
        (
            "GOOGLECALENDAR_DELETE_EVENT",
            "googlecalendar",
            "20260721_00",
            "calendar.delete",
        ),
        (
            "GOOGLECALENDAR_ACL_INSERT",
            "googlecalendar",
            "20260721_00",
            "account.permission.change",
        ),
        (
            "SLACK_SEND_MESSAGE",
            "slack",
            "20260721_00",
            "communication.external.send",
        ),
        (
            "SLACK_READ_AUDIT_LOGS",
            "slack",
            "20260721_00",
            "security.alert.read",
        ),
        (
            "SLACK_CREATE_CANVAS",
            "slack",
            "20260721_00",
            "document.write",
        ),
        (
            "SLACK_INVITE_USER_TO_CHANNEL",
            "slack",
            "20260721_00",
            "account.permission.change",
        ),
        (
            "NOTION_CREATE_NOTION_PAGE",
            "notion",
            "20260730_00",
            "document.write",
        ),
        (
            "NOTION_ARCHIVE_NOTION_PAGE",
            "notion",
            "20260730_00",
            "document.delete",
        ),
        (
            "NOTION_UPDATE_SCHEMA_DATABASE",
            "notion",
            "20260730_00",
            "document.schema.write",
        ),
        (
            "NOTION_CREATE_COMMENT",
            "notion",
            "20260730_00",
            "communication.external.send",
        ),
    ];
    for (slug, toolkit, version, action_class) in expected {
        let entry = catalogs
            .lookup(slug)
            .ok_or_else(|| anyhow::anyhow!("{slug} is missing from the shipped catalogs"))?;
        assert_eq!(entry.toolkit, toolkit);
        assert_eq!(entry.version, version);
        assert_eq!(entry.action_class, action_class);
    }

    assert!(catalogs.lookup("GMAIL_SEND_EMAIL_V2").is_none());
    Ok(())
}
