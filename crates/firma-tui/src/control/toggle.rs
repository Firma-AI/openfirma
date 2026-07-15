//! Cedar source operations for Policy Control.
//!
//! Policies are addressed by their Cedar `@id(...)` annotation. Disabling a
//! policy keeps the source valid by adding one managed `when { false }`
//! condition, and enabling removes only that managed condition.
//!
//! The code edits source spans instead of formatting a `PolicySet` back to
//! Cedar. This keeps comments, ordering, and operator formatting intact while
//! still validating the full candidate before it reaches disk.

use std::{
    collections::{HashMap, HashSet},
    fmt, fs, io,
    io::Write,
    path::Path,
    str::FromStr as _,
};

use cedar_policy::PolicySet;
use cedar_policy_core::{
    ast::{AnyId, PolicyID},
    parser::{self, cst},
};
use tempfile::NamedTempFile;

use crate::control::error::{ErrorMessage, PolicyRewriteError};

// The managed disable condition is split into Cedar syntax and ownership
// marker on purpose. the policy control writes the two pieces together as one
// canonical condition, but reads them separately: the CST tells us which `when`
// condition exists and the trailing marker tells us that the condition is ours
// to normalize or remove. This keeps compact or inline user formatting valid
// while avoiding accidental edits to a user-owned `when { false }` condition.
const DISABLE_CONDITION: &str = "when { false };";
const DISABLE_COMMENT: &str = "// openfirma-control:disabled";

// `@id(...)` is the Cedar-owned identity for a policy row. The TUI deliberately
// does not keep a parallel mapping file, because a second source of truth would
// let the UI and the Authority policy bundle drift.
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

/// Sets one `@id(...)` policy in a Cedar file to the requested state.
///
/// This is a convenience wrapper around [`set_policy_states`]. It still uses
/// the same validated, atomic source rewrite path as a batch request.
///
/// # Errors
///
/// Fails when the requested state is not toggleable, the Cedar file cannot be
/// read, the policy id cannot be resolved, the rewritten candidate does not
/// parse, or the candidate cannot be atomically persisted.
pub fn set_policy_state(
    path: &Path,
    policy_id: &str,
    requested: PolicyState,
) -> Result<(), PolicyRewriteError> {
    set_policy_states(path, &[policy_id.to_owned()], requested)
}

/// Sets several `@id(...)` policies in one Cedar file to the requested state.
///
/// The file is read once, policy source spans are located once, edits are
/// applied from the end of the file back to the front, and the final candidate
/// is parsed before it replaces the original file. Policies already in the
/// requested state are left untouched.
///
/// # Errors
///
/// Fails when the requested state is not toggleable, the Cedar file cannot be
/// read, any policy id cannot be resolved, the rewritten candidate does not
/// parse, or the candidate cannot be atomically persisted.
pub fn set_policy_states(
    path: &Path,
    policy_ids: &[String],
    requested: PolicyState,
) -> Result<(), PolicyRewriteError> {
    validate_rewrite_state(requested)?;
    if policy_ids.is_empty() {
        return Ok(());
    }

    let source = fs::read_to_string(path).map_err(|error| PolicyRewriteError::ReadFile {
        path: path.to_path_buf(),
        source: ErrorMessage::capture(error),
    })?;
    let edits = rewrite_edits_for_policies(&source, policy_ids, requested)?;

    if edits.is_empty() {
        return Ok(());
    }

    let candidate = apply_edits(source, edits);
    validate_cedar(path, &candidate)?;
    write_candidate(path, candidate.as_bytes())?;

    Ok(())
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
    if condition.is_some_and(ManagedCondition::disables_policy) {
        PolicyState::Disabled
    } else {
        PolicyState::Enabled
    }
}

fn rewrite_body_for_state(
    body: &str,
    policy_end: usize,
    state: PolicyState,
    condition: Option<ManagedCondition>,
) -> Result<String, PolicyRewriteError> {
    match state {
        PolicyState::Enabled => remove_managed_condition(body, condition),
        PolicyState::Disabled => write_managed_disable_condition(body, policy_end, condition),
        PolicyState::MissingFile
        | PolicyState::MissingId
        | PolicyState::InvalidPolicy
        | PolicyState::ReadError => Err(PolicyRewriteError::InvalidRequestedState),
    }
}

fn validate_rewrite_state(state: PolicyState) -> Result<(), PolicyRewriteError> {
    match state {
        PolicyState::Enabled | PolicyState::Disabled => Ok(()),
        PolicyState::MissingFile
        | PolicyState::MissingId
        | PolicyState::InvalidPolicy
        | PolicyState::ReadError => Err(PolicyRewriteError::InvalidRequestedState),
    }
}

fn rewrite_edits_for_policies(
    source: &str,
    policy_ids: &[String],
    requested: PolicyState,
) -> Result<Vec<SourceEdit>, PolicyRewriteError> {
    let blocks = find_policy_blocks(source, policy_ids)?;
    let conditions = managed_conditions_by_generated_id(source)?;
    let mut edits = Vec::new();

    for (policy_id, block) in blocks {
        if let Some(edit) =
            rewrite_edit_for_policy(source, &policy_id, &block, &conditions, requested)?
        {
            edits.push(edit);
        }
    }

    Ok(edits)
}

fn rewrite_edit_for_policy(
    source: &str,
    policy_id: &str,
    block: &PolicyBlock,
    conditions: &[(PolicyID, Option<ManagedCondition>)],
    requested: PolicyState,
) -> Result<Option<SourceEdit>, PolicyRewriteError> {
    let condition = find_managed_condition(conditions, &block.generated_id)?;
    let current = policy_state_from_condition(condition.as_ref());

    if !needs_rewrite(current, requested, condition.as_ref()) {
        return Ok(None);
    }

    let body = &source[block.start..block.end];
    let policy_end = block.source_end.checked_sub(block.start).ok_or_else(|| {
        PolicyRewriteError::InvalidPolicySourceSpan {
            id: policy_id.to_string(),
        }
    })?;
    let body_condition = condition
        .map(|condition| {
            condition
                .relative_to(block.start, block.end)
                .ok_or_else(|| PolicyRewriteError::ManagedConditionOutsidePolicy {
                    id: policy_id.to_string(),
                })
        })
        .transpose()?;

    Ok(Some(SourceEdit {
        start: block.start,
        end: block.end,
        replacement: rewrite_body_for_state(body, policy_end, requested, body_condition)?,
    }))
}

fn needs_rewrite(
    current: PolicyState,
    requested: PolicyState,
    condition: Option<&ManagedCondition>,
) -> bool {
    current != requested || matches!(requested, PolicyState::Enabled) && condition.is_some()
}

fn write_managed_disable_condition(
    body: &str,
    policy_end: usize,
    condition: Option<ManagedCondition>,
) -> Result<String, PolicyRewriteError> {
    condition.map_or_else(
        || add_disable_condition(body, policy_end),
        |condition| Ok(normalize_managed_disable_condition(body, condition)),
    )
}

fn add_disable_condition(body: &str, policy_end: usize) -> Result<String, PolicyRewriteError> {
    let terminator = policy_terminator_from_span(body, policy_end)?;
    let condition = managed_disable_condition();

    let mut out = String::with_capacity(body.len() + condition.len() + 1);
    out.push_str(&body[..terminator]);
    out.push(' ');
    out.push_str(&condition);
    out.push_str(&body[policy_end..]);
    Ok(out)
}

fn normalize_managed_disable_condition(body: &str, condition: ManagedCondition) -> String {
    let disable_condition = managed_disable_condition();
    let mut out = String::with_capacity(body.len() + disable_condition.len());
    out.push_str(&body[..condition.clause_start]);
    out.push_str(&disable_condition);
    out.push_str(&body[condition.comment_end..]);
    out
}

fn managed_disable_condition() -> String {
    format!("{DISABLE_CONDITION} {DISABLE_COMMENT}")
}

fn policy_terminator_from_span(body: &str, policy_end: usize) -> Result<usize, PolicyRewriteError> {
    let terminator = policy_end
        .checked_sub(1)
        .ok_or(PolicyRewriteError::EmptyPolicySourceSpan)?;
    if body.as_bytes().get(terminator) != Some(&b';') {
        return Err(PolicyRewriteError::PolicySourceSpanMissingSemicolon);
    }

    Ok(terminator)
}

fn remove_managed_condition(
    body: &str,
    condition: Option<ManagedCondition>,
) -> Result<String, PolicyRewriteError> {
    let Some(condition) = condition else {
        return Ok(body.to_string());
    };

    let remove_start = condition_removal_start(body, condition)?;

    let mut out = String::with_capacity(body.len());
    out.push_str(&body[..remove_start]);
    out.push(';');
    out.push_str(&body[condition.comment_end..]);
    Ok(out)
}

fn condition_removal_start(
    body: &str,
    condition: ManagedCondition,
) -> Result<usize, PolicyRewriteError> {
    standalone_condition_removal_start(body, condition)
        .or_else(|| inline_condition_removal_start(body, condition))
        .ok_or(PolicyRewriteError::UnattachedManagedCondition)
}

fn standalone_condition_removal_start(body: &str, condition: ManagedCondition) -> Option<usize> {
    let remove_start = previous_line_break_start(body, condition.clause_start)?;
    let line_start = line_start_after_break(body, remove_start);
    if !body[line_start..condition.clause_start].trim().is_empty() {
        return None;
    }

    Some(remove_start)
}

fn inline_condition_removal_start(body: &str, condition: ManagedCondition) -> Option<usize> {
    let mut remove_start = condition.clause_start;
    let bytes = body.as_bytes();
    while remove_start > 0 && matches!(bytes.get(remove_start - 1), Some(b' ' | b'\t')) {
        remove_start -= 1;
    }

    if remove_start == condition.clause_start {
        return None;
    }

    let line_start = body[..remove_start]
        .rfind('\n')
        .map_or(0, |offset| offset + 1);

    (!body[line_start..remove_start].trim().is_empty()).then_some(remove_start)
}

fn policy_blocks_by_id(source: &str) -> Result<HashMap<String, PolicyBlock>, PolicyRewriteError> {
    let (policy_texts, policy_set) = parser::parse_policyset_and_also_return_policy_text(source)
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

        let policy_source = policy_texts.get(policy.id()).copied().ok_or_else(|| {
            PolicyRewriteError::MissingSourceSpan {
                id: policy_id.to_string(),
            }
        })?;

        let start = source_offset(source, policy_source)?;
        let source_end = start + policy_source.len();
        let end = extend_end_for_managed_comment(source, source_end);

        blocks.insert(
            policy_id.to_owned(),
            PolicyBlock {
                generated_id: policy.id().clone(),
                start,
                source_end,
                end,
            },
        );
    }

    Ok(blocks)
}

fn find_policy_blocks(
    source: &str,
    policy_ids: &[String],
) -> Result<Vec<(String, PolicyBlock)>, PolicyRewriteError> {
    let requested_ids = requested_id_set(policy_ids)?;
    let mut blocks = policy_blocks_by_id(source)?;
    let mut found = Vec::new();

    for policy_id in policy_ids {
        if !requested_ids.contains(policy_id.as_str()) {
            continue;
        }

        let Some(block) = blocks.remove(policy_id) else {
            return Err(PolicyRewriteError::MissingId {
                id: policy_id.clone(),
            });
        };

        found.push((policy_id.clone(), block));
    }

    Ok(found)
}

fn requested_id_set(policy_ids: &[String]) -> Result<HashSet<&str>, PolicyRewriteError> {
    let mut ids = HashSet::new();
    for policy_id in policy_ids {
        if !ids.insert(policy_id.as_str()) {
            return Err(PolicyRewriteError::DuplicateRequestedId {
                id: policy_id.clone(),
            });
        }
    }

    Ok(ids)
}

fn source_offset(source: &str, slice: &str) -> Result<usize, PolicyRewriteError> {
    let source_start = source.as_ptr() as usize;
    let source_end = source_start + source.len();
    let slice_start = slice.as_ptr() as usize;
    let slice_end = slice_start
        .checked_add(slice.len())
        .ok_or(PolicyRewriteError::SourceSpanOutsideSource)?;

    if slice_start < source_start || slice_end > source_end {
        return Err(PolicyRewriteError::SourceSpanOutsideSource);
    }

    Ok(slice_start - source_start)
}

fn extend_end_for_managed_comment(source: &str, end: usize) -> usize {
    let line_end = line_content_end(source, end);
    let trailing = &source[end..line_end];
    if trailing.trim() == DISABLE_COMMENT {
        line_end
    } else {
        end
    }
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

        let loc = &condition_node.loc;
        let (clause_end, comment_end) = managed_condition_end_after_condition(source, loc.end())?;
        Some(ManagedCondition {
            clause_start: loc.start(),
            clause_end,
            comment_end,
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

fn previous_line_break_start(source: &str, line_start: usize) -> Option<usize> {
    if line_start == 0 {
        return None;
    }
    let prefix = source.get(..line_start)?;
    let newline = prefix.rfind('\n')?;
    if newline > 0 && source.as_bytes().get(newline - 1) == Some(&b'\r') {
        Some(newline - 1)
    } else {
        Some(newline)
    }
}

fn line_start_after_break(source: &str, line_break_start: usize) -> usize {
    if source.as_bytes().get(line_break_start) == Some(&b'\r')
        && source.as_bytes().get(line_break_start + 1) == Some(&b'\n')
    {
        line_break_start + 2
    } else {
        line_break_start + 1
    }
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

fn validate_cedar(path: &Path, candidate: &str) -> Result<(), PolicyRewriteError> {
    candidate.parse::<PolicySet>().map(|_| ()).map_err(|error| {
        PolicyRewriteError::InvalidCandidate {
            path: path.to_path_buf(),
            source: ErrorMessage::capture(error),
        }
    })
}

fn apply_edits(mut source: String, mut edits: Vec<SourceEdit>) -> String {
    edits.sort_by_key(|edit| std::cmp::Reverse(edit.start));
    for edit in edits {
        source.replace_range(edit.start..edit.end, &edit.replacement);
    }
    source
}

fn write_candidate(path: &Path, candidate: &[u8]) -> Result<(), PolicyRewriteError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| PolicyRewriteError::MissingParentDir {
            path: path.to_path_buf(),
        })?;

    let mut temp =
        NamedTempFile::new_in(parent).map_err(|error| PolicyRewriteError::CreateTempFile {
            path: parent.to_path_buf(),
            source: ErrorMessage::capture(error),
        })?;

    temp.write_all(candidate)
        .map_err(|error| PolicyRewriteError::WriteTempFile {
            path: path.to_path_buf(),
            source: ErrorMessage::capture(error),
        })?;

    temp.as_file_mut()
        .sync_all()
        .map_err(|error| PolicyRewriteError::SyncTempFile {
            path: path.to_path_buf(),
            source: ErrorMessage::capture(error),
        })?;

    temp.persist(path).map(|_| ()).map_err(|error| {
        let temp_path = error.file.path().to_path_buf();
        PolicyRewriteError::AtomicReplace {
            path: path.to_path_buf(),
            temp_path,
            source: ErrorMessage::capture(error.error),
        }
    })
}

/// Replacement to apply to the original Cedar source.
///
/// Edits are applied from the highest offset to the lowest offset so earlier
/// replacements cannot invalidate later ranges.
struct SourceEdit {
    start: usize,
    end: usize,
    replacement: String,
}

/// Source span for a policy selected by its `@id(...)` annotation.
///
/// `source_end` is the policy span returned by Cedar. `end` can extend past it
/// to include the managed comment when that comment lives after the policy
/// semicolon.
struct PolicyBlock {
    generated_id: PolicyID,
    start: usize,
    source_end: usize,
    end: usize,
}

/// Managed condition attached to a policy.
///
/// The clause range starts at `when` and ends at the semicolon. The comment
/// range extends through the exact managed marker, allowing removal to include
/// the marker without touching user comments.
#[derive(Clone, Copy)]
struct ManagedCondition {
    clause_start: usize,
    clause_end: usize,
    comment_end: usize,
    expression: ManagedConditionExpression,
}

impl ManagedCondition {
    const fn disables_policy(&self) -> bool {
        matches!(self.expression, ManagedConditionExpression::False)
    }

    const fn relative_to(self, offset: usize, end: usize) -> Option<Self> {
        if self.clause_start < offset
            || self.clause_end < offset
            || self.comment_end < offset
            || self.comment_end > end
        {
            return None;
        }

        Some(Self {
            clause_start: self.clause_start - offset,
            clause_end: self.clause_end - offset,
            comment_end: self.comment_end - offset,
            expression: self.expression,
        })
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
