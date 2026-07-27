use firma_tui::control::{PolicyState, read_policy_state};

use crate::support;

const INLINE_DISABLED_POLICY: &str = r#"
@id("block_health_checks")
forbid (
    principal,
    action,
    resource
) when {
    true
} when { false }; // openfirma-control:disabled
"#;

const NEGATED_TRUE_CONDITION_WITH_MANAGED_COMMENT_POLICY: &str = r#"
@id("block_health_checks")
forbid (
    principal,
    action,
    resource
) when {
    true
} when { !true }; // openfirma-control:disabled
"#;

const CONDITIONAL_FALSE_CONDITION_WITH_MANAGED_COMMENT_POLICY: &str = r#"
@id("block_health_checks")
forbid (
    principal,
    action,
    resource
) when {
    true
} when { if true then false else false }; // openfirma-control:disabled
"#;

const MULTI_POLICY: &str = r#"
@id("first_policy")
forbid (
    principal,
    action,
    resource
);

@id("second_policy")
forbid (
    principal,
    action,
    resource
) when { false }; // openfirma-control:disabled
"#;

#[test]
fn inline_managed_disable_condition_reads_as_disabled() -> anyhow::Result<()> {
    let (_temp, path) = support::temp_policy_file(INLINE_DISABLED_POLICY)?;

    assert_eq!(
        read_policy_state(&path, "block_health_checks"),
        PolicyState::Disabled
    );

    Ok(())
}

#[test]
fn negated_true_condition_with_managed_comment_is_enabled() -> anyhow::Result<()> {
    let (_temp, path) =
        support::temp_policy_file(NEGATED_TRUE_CONDITION_WITH_MANAGED_COMMENT_POLICY)?;

    assert_eq!(
        read_policy_state(&path, "block_health_checks"),
        PolicyState::Enabled
    );

    Ok(())
}

#[test]
fn conditional_false_condition_with_managed_comment_is_enabled() -> anyhow::Result<()> {
    let (_temp, path) =
        support::temp_policy_file(CONDITIONAL_FALSE_CONDITION_WITH_MANAGED_COMMENT_POLICY)?;

    assert_eq!(
        read_policy_state(&path, "block_health_checks"),
        PolicyState::Enabled
    );

    Ok(())
}

#[test]
fn generated_policy_id_mapping_finds_later_policy_condition() -> anyhow::Result<()> {
    let (_temp, path) = support::temp_policy_file(MULTI_POLICY)?;

    assert_eq!(
        read_policy_state(&path, "first_policy"),
        PolicyState::Enabled
    );
    assert_eq!(
        read_policy_state(&path, "second_policy"),
        PolicyState::Disabled
    );

    Ok(())
}
