use std::fs;

use cedar_policy::PolicySet;
use firma_tui::control::{PolicyState, read_policy_state, set_policy_state, set_policy_states};

use crate::support;

const POLICY: &str = r#"
@id("block_health_checks")
forbid (
    principal,
    action,
    resource
) when {
    true
};
"#;

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

const INLINE_ENABLED_POLICY: &str = r#"
@id("block_health_checks")
forbid (
    principal,
    action,
    resource
) when {
    true
};
"#;

const COMPACT_DISABLED_POLICY: &str = r#"
@id("block_health_checks")
forbid (
    principal,
    action,
    resource
) when {
    true
} when {false};// openfirma-control:disabled
"#;

const USER_FALSE_POLICY: &str = r#"
@id("block_health_checks")
forbid (
    principal,
    action,
    resource
) when {
    true
} when { false };
"#;

const USER_COMMENTED_FALSE_POLICY: &str = r#"
@id("block_health_checks")
forbid (
    principal,
    action,
    resource
) when {
    true
} when { false }; // user comment
"#;

const TRUE_CONDITION_WITH_MANAGED_COMMENT_POLICY: &str = r#"
@id("block_health_checks")
forbid (
    principal,
    action,
    resource
) when {
    true
} when { true }; // openfirma-control:disabled
"#;

const TRUE_CONDITION_DISABLED_POLICY: &str = r#"
@id("block_health_checks")
forbid (
    principal,
    action,
    resource
) when {
    true
} when { false }; // openfirma-control:disabled
"#;

const FALSE_OR_FALSE_CONDITION_WITH_MANAGED_COMMENT_POLICY: &str = r#"
@id("block_health_checks")
forbid (
    principal,
    action,
    resource
) when {
    true
} when { false || false }; // openfirma-control:disabled
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

const POLICY_WITH_SEMICOLON_IN_EXPRESSION: &str = r#"
@id("block_health_checks")
forbid (
    principal,
    action,
    resource
) when {
    "a;b" == "a;b"
};
"#;

const POLICY_WITH_SEMICOLON_IN_EXPRESSION_DISABLED: &str = r#"
@id("block_health_checks")
forbid (
    principal,
    action,
    resource
) when {
    "a;b" == "a;b"
} when { false }; // openfirma-control:disabled
"#;

const STANDALONE_DISABLED_POLICY: &str = r#"
@id("block_health_checks")
forbid (
    principal,
    action,
    resource
) when {
    true
}
when { false }; // openfirma-control:disabled
"#;

const STANDALONE_ENABLED_POLICY: &str = r#"
@id("block_health_checks")
forbid (
    principal,
    action,
    resource
) when {
    true
};
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

const TWO_ENABLED_POLICIES: &str = r#"
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
);
"#;

const TWO_DISABLED_POLICIES: &str = r#"
@id("first_policy")
forbid (
    principal,
    action,
    resource
) when { false }; // openfirma-control:disabled

@id("second_policy")
forbid (
    principal,
    action,
    resource
) when { false }; // openfirma-control:disabled
"#;

#[test]
fn managed_disable_condition_roundtrips_through_disk_state() -> anyhow::Result<()> {
    let (_temp, path) = support::temp_policy_file(POLICY)?;

    assert!(read_policy_state(&path, "block_health_checks").is_enabled());

    set_policy_state(&path, "block_health_checks", PolicyState::Disabled)?;

    assert_eq!(
        read_policy_state(&path, "block_health_checks"),
        PolicyState::Disabled
    );

    assert_eq!(fs::read_to_string(&path)?, INLINE_DISABLED_POLICY);

    set_policy_state(&path, "block_health_checks", PolicyState::Enabled)?;

    assert!(read_policy_state(&path, "block_health_checks").is_enabled());

    let enabled_source = fs::read_to_string(&path)?;
    assert!(!enabled_source.contains("openfirma-control:disabled"));

    Ok(())
}

#[test]
fn disabled_rewrite_persists_parseable_cedar() -> anyhow::Result<()> {
    let (_temp, path) = support::temp_policy_file(POLICY)?;

    set_policy_state(&path, "block_health_checks", PolicyState::Disabled)?;

    assert_parses_as_cedar(&fs::read_to_string(&path)?)
}

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
fn inline_managed_disable_condition_removes_clause_and_restores_semicolon() -> anyhow::Result<()> {
    let (_temp, path) = support::temp_policy_file(INLINE_DISABLED_POLICY)?;

    set_policy_state(&path, "block_health_checks", PolicyState::Enabled)?;

    assert_eq!(fs::read_to_string(&path)?, INLINE_ENABLED_POLICY);

    Ok(())
}

#[test]
fn compact_managed_disable_condition_removes_clause_and_restores_semicolon() -> anyhow::Result<()> {
    let (_temp, path) = support::temp_policy_file(COMPACT_DISABLED_POLICY)?;

    assert_eq!(
        read_policy_state(&path, "block_health_checks"),
        PolicyState::Disabled
    );

    set_policy_state(&path, "block_health_checks", PolicyState::Enabled)?;

    assert_eq!(fs::read_to_string(&path)?, INLINE_ENABLED_POLICY);

    Ok(())
}

#[test]
fn enabled_rewrite_persists_parseable_cedar() -> anyhow::Result<()> {
    let (_temp, path) = support::temp_policy_file(COMPACT_DISABLED_POLICY)?;

    set_policy_state(&path, "block_health_checks", PolicyState::Enabled)?;

    assert_parses_as_cedar(&fs::read_to_string(&path)?)
}

#[test]
fn bare_false_condition_is_user_owned_and_preserved() -> anyhow::Result<()> {
    let (_temp, path) = support::temp_policy_file(USER_FALSE_POLICY)?;

    assert_eq!(
        read_policy_state(&path, "block_health_checks"),
        PolicyState::Enabled
    );

    set_policy_state(&path, "block_health_checks", PolicyState::Enabled)?;

    assert_eq!(fs::read_to_string(&path)?, USER_FALSE_POLICY);

    Ok(())
}

#[test]
fn false_condition_with_user_comment_is_user_owned_and_preserved() -> anyhow::Result<()> {
    let (_temp, path) = support::temp_policy_file(USER_COMMENTED_FALSE_POLICY)?;

    assert_eq!(
        read_policy_state(&path, "block_health_checks"),
        PolicyState::Enabled
    );

    set_policy_state(&path, "block_health_checks", PolicyState::Enabled)?;

    assert_eq!(fs::read_to_string(&path)?, USER_COMMENTED_FALSE_POLICY);

    Ok(())
}

#[test]
fn true_condition_with_managed_comment_is_enabled_and_can_be_disabled() -> anyhow::Result<()> {
    let (_temp, path) = support::temp_policy_file(TRUE_CONDITION_WITH_MANAGED_COMMENT_POLICY)?;

    assert_eq!(
        read_policy_state(&path, "block_health_checks"),
        PolicyState::Enabled
    );

    set_policy_state(&path, "block_health_checks", PolicyState::Disabled)?;

    assert_eq!(fs::read_to_string(&path)?, TRUE_CONDITION_DISABLED_POLICY);
    assert_eq!(
        read_policy_state(&path, "block_health_checks"),
        PolicyState::Disabled
    );

    Ok(())
}

#[test]
fn true_condition_with_managed_comment_can_be_normalized_to_enabled() -> anyhow::Result<()> {
    let (_temp, path) = support::temp_policy_file(TRUE_CONDITION_WITH_MANAGED_COMMENT_POLICY)?;

    set_policy_state(&path, "block_health_checks", PolicyState::Enabled)?;

    assert_eq!(fs::read_to_string(&path)?, INLINE_ENABLED_POLICY);
    assert_eq!(
        read_policy_state(&path, "block_health_checks"),
        PolicyState::Enabled
    );

    Ok(())
}

#[test]
fn compound_false_with_managed_comment_can_be_disabled() -> anyhow::Result<()> {
    let (_temp, path) =
        support::temp_policy_file(FALSE_OR_FALSE_CONDITION_WITH_MANAGED_COMMENT_POLICY)?;

    assert_eq!(
        read_policy_state(&path, "block_health_checks"),
        PolicyState::Enabled
    );

    set_policy_state(&path, "block_health_checks", PolicyState::Disabled)?;

    assert_eq!(fs::read_to_string(&path)?, TRUE_CONDITION_DISABLED_POLICY);

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
fn disable_rewrite_uses_policy_source_span_for_terminator() -> anyhow::Result<()> {
    let (_temp, path) = support::temp_policy_file(POLICY_WITH_SEMICOLON_IN_EXPRESSION)?;

    set_policy_state(&path, "block_health_checks", PolicyState::Disabled)?;

    assert_eq!(
        fs::read_to_string(&path)?,
        POLICY_WITH_SEMICOLON_IN_EXPRESSION_DISABLED
    );
    assert_eq!(
        read_policy_state(&path, "block_health_checks"),
        PolicyState::Disabled
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

#[test]
fn standalone_managed_disable_condition_removes_line_and_restores_semicolon() -> anyhow::Result<()>
{
    let (_temp, path) = support::temp_policy_file(STANDALONE_DISABLED_POLICY)?;

    set_policy_state(&path, "block_health_checks", PolicyState::Enabled)?;

    assert_eq!(fs::read_to_string(&path)?, STANDALONE_ENABLED_POLICY);

    Ok(())
}

#[test]
fn batch_rewrite_disables_multiple_policies_with_one_valid_cedar_output() -> anyhow::Result<()> {
    let (_temp, path) = support::temp_policy_file(TWO_ENABLED_POLICIES)?;

    set_policy_states(
        &path,
        &["first_policy".to_string(), "second_policy".to_string()],
        PolicyState::Disabled,
    )?;

    let source = fs::read_to_string(&path)?;
    assert_parses_as_cedar(&source)?;
    assert_eq!(source.matches("openfirma-control:disabled").count(), 2);
    assert_eq!(
        read_policy_state(&path, "first_policy"),
        PolicyState::Disabled
    );
    assert_eq!(
        read_policy_state(&path, "second_policy"),
        PolicyState::Disabled
    );

    Ok(())
}

#[test]
fn batch_rewrite_enables_multiple_policies_and_removes_managed_conditions() -> anyhow::Result<()> {
    let (_temp, path) = support::temp_policy_file(TWO_DISABLED_POLICIES)?;

    set_policy_states(
        &path,
        &["first_policy".to_string(), "second_policy".to_string()],
        PolicyState::Enabled,
    )?;

    let source = fs::read_to_string(&path)?;
    assert_parses_as_cedar(&source)?;
    assert!(!source.contains("openfirma-control:disabled"));
    assert_eq!(
        read_policy_state(&path, "first_policy"),
        PolicyState::Enabled
    );
    assert_eq!(
        read_policy_state(&path, "second_policy"),
        PolicyState::Enabled
    );

    Ok(())
}

#[test]
fn batch_rewrite_missing_id_does_not_overwrite_file() -> anyhow::Result<()> {
    let (_temp, path) = support::temp_policy_file(TWO_ENABLED_POLICIES)?;

    let error = set_policy_states(
        &path,
        &["first_policy".to_string(), "missing_policy".to_string()],
        PolicyState::Disabled,
    )
    .err()
    .ok_or_else(|| anyhow::anyhow!("missing policy id rewrite unexpectedly succeeded"))?;

    assert_eq!(
        error.to_string(),
        "policy id `missing_policy` was not found"
    );
    assert_eq!(fs::read_to_string(&path)?, TWO_ENABLED_POLICIES);

    Ok(())
}

fn assert_parses_as_cedar(source: &str) -> anyhow::Result<()> {
    let _policy_set = source.parse::<PolicySet>()?;
    Ok(())
}
