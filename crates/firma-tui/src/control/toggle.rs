//! Cedar source operations for Policy Control.
//!
//! Policies are addressed by their Cedar `@id(...)` annotation. Disabling a
//! policy keeps the source valid by adding one managed `when { false }`
//! condition, and enabling removes only that managed condition.
//!
//! The code edits source spans instead of formatting a `PolicySet` back to
//! Cedar. This keeps comments, ordering, and operator formatting intact while
//! still validating the full candidate before it reaches disk.

use std::{collections::HashMap, fmt, fs, io, path::Path, str::FromStr as _};

use cedar_policy_core::{
    ast::{AnyId, PolicyID},
    parser::{self, cst},
};

use crate::control::error::{ErrorMessage, PolicyRewriteError};

const DISABLE_COMMENT: &str = "// openfirma-control:disabled";
const POLICY_ID_ANNOTATION: &str = "id";

/// State of one Cedar policy as seen by Policy Control.
///
/// `Enabled` and `Disabled` are the only states that can be requested for a
/// rewrite. The remaining values explain why a state could not be read from
/// disk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyState {
    /// The policy exists and does not have the managed disable condition.
    Enabled,
    /// The policy exists and has the managed disable condition.
    Disabled,
    /// The referenced Cedar file does not exist.
    MissingFile,
    /// The Cedar file exists, but the requested `@id(...)` was not found.
    MissingId,
    /// The Cedar source could not be interpreted well enough to read state.
    InvalidPolicy,
    /// The Cedar file exists, but could not be read.
    ReadError,
}

impl PolicyState {
    /// Returns true only for a policy that is present and enabled.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

impl fmt::Display for PolicyState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(policy_state_label(*self))
    }
}

const fn policy_state_label(state: PolicyState) -> &'static str {
    match state {
        PolicyState::Enabled => "enabled",
        PolicyState::Disabled => "disabled",
        PolicyState::MissingFile => "missing file",
        PolicyState::MissingId => "missing id",
        PolicyState::InvalidPolicy => "invalid policy",
        PolicyState::ReadError => "read error",
    }
}

/// Reads one `@id(...)` policy state from a Cedar file.
///
/// Read failures are reported as [`PolicyState`] values so callers can render
/// a row-level status without treating discovery as a hard error.
pub fn read_policy_state(path: &Path, policy_id: &str) -> PolicyState {
    read_policy_states(path, &[policy_id.to_owned()])
        .remove(policy_id)
        .unwrap_or(PolicyState::InvalidPolicy)
}

/// Reads several `@id(...)` policy states from one Cedar file.
///
/// The source is read and parsed once. Each requested id receives either a
/// concrete enabled/disabled state or the most specific read state available
/// for that file.
pub fn read_policy_states(path: &Path, policy_ids: &[String]) -> HashMap<String, PolicyState> {
    let mut states = default_policy_states(policy_ids, PolicyState::InvalidPolicy);

    let cedar = match fs::read_to_string(path) {
        Ok(cedar) => cedar,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return default_policy_states(policy_ids, PolicyState::MissingFile);
        }
        Err(_) => {
            return default_policy_states(policy_ids, PolicyState::ReadError);
        }
    };

    let Ok(blocks) = policy_blocks_by_id(&cedar) else {
        return states;
    };

    let Ok(conditions) = managed_conditions_by_generated_id(&cedar) else {
        return states;
    };

    for policy_id in policy_ids {
        let Some(block) = blocks.get(policy_id) else {
            states.insert(policy_id.clone(), PolicyState::MissingId);
            continue;
        };

        let state = find_managed_condition(&conditions, &block.generated_id)
            .map_or(PolicyState::InvalidPolicy, |condition| {
                policy_state_from_condition(condition.as_ref())
            });
        states.insert(policy_id.clone(), state);
    }

    states
}

fn default_policy_states(
    policy_ids: &[String],
    state: PolicyState,
) -> HashMap<String, PolicyState> {
    policy_ids
        .iter()
        .map(|policy_id| (policy_id.clone(), state))
        .collect()
}

fn policy_state_from_condition(condition: Option<&ManagedCondition>) -> PolicyState {
    if condition
        .copied()
        .is_some_and(ManagedCondition::disables_policy)
    {
        PolicyState::Disabled
    } else {
        PolicyState::Enabled
    }
}

fn policy_blocks_by_id(source: &str) -> Result<HashMap<String, PolicyBlock>, PolicyRewriteError> {
    let (_policy_texts, policy_set) = parser::parse_policyset_and_also_return_policy_text(source)
        .map_err(|error| PolicyRewriteError::ParseSource {
        source: ErrorMessage::capture(error),
    })?;

    let id_annotation = AnyId::from_str(POLICY_ID_ANNOTATION).map_err(|error| {
        PolicyRewriteError::InvalidPolicyAnnotationKey {
            key: POLICY_ID_ANNOTATION.to_string(),
            source: ErrorMessage::capture(error),
        }
    })?;

    let mut blocks = HashMap::new();
    for policy in policy_set.policies() {
        let Some(annotation) = policy.annotation(&id_annotation) else {
            continue;
        };

        let policy_id = annotation.val.as_str().trim();
        if policy_id.is_empty() {
            continue;
        }

        if blocks.contains_key(policy_id) {
            return Err(PolicyRewriteError::DuplicatePolicyId {
                id: policy_id.to_string(),
            });
        }

        blocks.insert(
            policy_id.to_owned(),
            PolicyBlock {
                generated_id: policy.id().clone(),
            },
        );
    }

    Ok(blocks)
}

fn managed_conditions_by_generated_id(
    source: &str,
) -> Result<Vec<(PolicyID, Option<ManagedCondition>)>, PolicyRewriteError> {
    let cst = parser::text_to_cst::parse_policies(source).map_err(|error| {
        PolicyRewriteError::ParseCst {
            source: ErrorMessage::capture(error),
        }
    })?;
    let policies = cst
        .with_generated_policyids()
        .ok_or(PolicyRewriteError::EmptyCst)?;

    let mut conditions = Vec::new();
    for (generated_id, policy_node) in policies {
        let Some(policy) = policy_node.as_inner() else {
            return Err(PolicyRewriteError::MissingCstPolicy {
                id: generated_id.to_string(),
            });
        };

        conditions.push((generated_id, managed_condition(source, policy)));
    }

    Ok(conditions)
}

fn find_managed_condition(
    conditions: &[(PolicyID, Option<ManagedCondition>)],
    generated_id: &PolicyID,
) -> Result<Option<ManagedCondition>, PolicyRewriteError> {
    conditions
        .iter()
        .find_map(|(condition_generated_id, condition)| {
            (condition_generated_id == generated_id).then_some(*condition)
        })
        .ok_or_else(|| PolicyRewriteError::MissingGeneratedPolicy {
            id: generated_id.to_string(),
        })
}

fn managed_condition(source: &str, policy: &cst::Policy) -> Option<ManagedCondition> {
    policy.conds.iter().find_map(|condition_node| {
        let condition = condition_node.as_inner()?;
        if !is_when_condition(condition) {
            return None;
        }

        managed_condition_end_after_condition(source, condition_node.loc.end())?;
        Some(ManagedCondition {
            expression: ManagedConditionExpr::classify(condition),
        })
    })
}

fn managed_condition_end_after_condition(
    source: &str,
    condition_end: usize,
) -> Option<(usize, usize)> {
    let line_end = line_content_end(source, condition_end);
    let trailing = source.get(condition_end..line_end)?;
    let before_semicolon = trailing.len() - trailing.trim_start().len();
    let after_semicolon = trailing.trim_start().strip_prefix(';')?;
    let clause_end = condition_end + before_semicolon + 1;
    (after_semicolon.trim_start() == DISABLE_COMMENT).then_some((clause_end, line_end))
}

fn is_when_condition(condition: &cst::Cond) -> bool {
    matches!(condition.cond.as_inner(), Some(cst::Ident::When))
}

fn line_content_end(source: &str, from: usize) -> usize {
    let newline = source[from..]
        .find('\n')
        .map_or(source.len(), |offset| from + offset);
    if newline > 0 && source.as_bytes().get(newline - 1) == Some(&b'\r') {
        newline - 1
    } else {
        newline
    }
}

struct PolicyBlock {
    generated_id: PolicyID,
}

#[derive(Clone, Copy)]
struct ManagedCondition {
    expression: ManagedConditionExpression,
}

impl ManagedCondition {
    const fn disables_policy(self) -> bool {
        matches!(self.expression, ManagedConditionExpression::False)
    }
}

/// Classification of the managed condition expression.
#[derive(Clone, Copy)]
enum ManagedConditionExpression {
    False,
    Other,
}

/// Classifies the condition expression without string matching the source.
///
/// Only a literal `false` expression disables a policy. Expressions that are
/// semantically false but not the literal are left as operator-authored Cedar.
struct ManagedConditionExpr;

impl ManagedConditionExpr {
    fn classify(condition: &cst::Cond) -> ManagedConditionExpression {
        if condition.expr.as_ref().is_some_and(Self::matches_expr) {
            ManagedConditionExpression::False
        } else {
            ManagedConditionExpression::Other
        }
    }

    fn matches_expr(expression: &parser::Node<Option<cst::Expr>>) -> bool {
        let Some(expression) = expression.as_inner() else {
            return false;
        };

        Self::matches_expr_data(expression.expr.as_ref())
    }

    fn matches_expr_data(expression: &cst::ExprData) -> bool {
        match expression {
            cst::ExprData::Or(or) => Self::matches_or(or),
            cst::ExprData::If(..) => false,
        }
    }

    fn matches_or(or: &parser::Node<Option<cst::Or>>) -> bool {
        let Some(or) = or.as_inner() else {
            return false;
        };

        or.extended.is_empty() && Self::matches_and(&or.initial)
    }

    fn matches_and(and: &parser::Node<Option<cst::And>>) -> bool {
        let Some(and) = and.as_inner() else {
            return false;
        };

        and.extended.is_empty() && Self::matches_relation(&and.initial)
    }

    fn matches_relation(relation: &parser::Node<Option<cst::Relation>>) -> bool {
        let Some(cst::Relation::Common { initial, extended }) = relation.as_inner() else {
            return false;
        };

        extended.is_empty() && Self::matches_add(initial)
    }

    fn matches_add(add: &parser::Node<Option<cst::Add>>) -> bool {
        let Some(add) = add.as_inner() else {
            return false;
        };

        add.extended.is_empty() && Self::matches_mult(&add.initial)
    }

    fn matches_mult(mult: &parser::Node<Option<cst::Mult>>) -> bool {
        let Some(mult) = mult.as_inner() else {
            return false;
        };

        mult.extended.is_empty() && Self::matches_unary(&mult.initial)
    }

    fn matches_unary(unary: &parser::Node<Option<cst::Unary>>) -> bool {
        let Some(unary) = unary.as_inner() else {
            return false;
        };

        unary.op.is_none() && Self::matches_member(&unary.item)
    }

    fn matches_member(member: &parser::Node<Option<cst::Member>>) -> bool {
        let Some(member) = member.as_inner() else {
            return false;
        };

        member.access.is_empty() && Self::matches_primary(&member.item)
    }

    fn matches_primary(primary: &parser::Node<Option<cst::Primary>>) -> bool {
        let Some(cst::Primary::Literal(literal)) = primary.as_inner() else {
            return false;
        };

        matches!(literal.as_inner(), Some(cst::Literal::False))
    }
}
