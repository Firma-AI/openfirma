//! Policy row and rewrite state.

use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
};

use crate::control::{
    error::{ControlError, EditorError, PolicyRewriteError},
    policies::{self, PolicyMapping, PolicyStateReader},
    toggle::PolicyState,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRow {
    pub id: String,
    file: PathBuf,
    state: PolicyState,
    pub status: PolicyRowStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyRowStatus {
    State(PolicyState),
    Queued,
    Writing,
    Error,
}

impl PolicyRowStatus {
    #[must_use]
    const fn rewrite_pending(self) -> bool {
        matches!(self, Self::Queued | Self::Writing)
    }
}

#[derive(Debug)]
pub struct PolicyRewriteRequest {
    pub file: PathBuf,
    pub ids: Vec<String>,
    pub requested: PolicyState,
}

#[derive(Debug)]
pub struct PolicyRewriteStart {
    pub file: PathBuf,
    pub ids: Vec<String>,
}

#[derive(Debug)]
pub struct PolicyRewriteCompletion {
    pub file: PathBuf,
    pub ids: Vec<String>,
    pub requested: PolicyState,
    pub result: Result<(), ControlError>,
}

#[derive(Debug)]
pub struct PoliciesState {
    selected_index: usize,
    health: PolicyHealth,
    dir: Option<PathBuf>,
    rows: Vec<PolicyRow>,
    state_reader: PolicyStateReader,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PolicyHealth {
    Ready,
    Degraded { error: ControlError },
}

impl PolicyHealth {
    fn from_error(error: Option<ControlError>) -> Self {
        error.map_or(Self::Ready, |error| Self::Degraded { error })
    }

    const fn error(&self) -> Option<&ControlError> {
        match self {
            Self::Ready => None,
            Self::Degraded { error } => Some(error),
        }
    }
}

impl PoliciesState {
    #[must_use]
    pub fn new(policy_dir: Option<PathBuf>) -> Self {
        Self::with_state_reader(policy_dir, PolicyStateReader::default())
    }

    #[must_use]
    pub fn with_state_reader(policy_dir: Option<PathBuf>, state_reader: PolicyStateReader) -> Self {
        let loaded = load_rows(policy_dir, &state_reader);
        Self {
            selected_index: 0,
            health: PolicyHealth::from_error(loaded.error),
            dir: loaded.dir,
            rows: loaded.rows,
            state_reader,
        }
    }

    pub fn move_up(&mut self) {
        self.selected_index = self.selected_index.saturating_sub(1);
    }

    pub fn move_down(&mut self) {
        let max_index = self.rows.len().saturating_sub(1);
        self.selected_index = self.selected_index.saturating_add(1).min(max_index);
    }

    pub fn move_first(&mut self) {
        self.selected_index = 0;
    }

    pub fn move_last(&mut self) {
        self.selected_index = self.rows.len().saturating_sub(1);
    }

    #[must_use]
    pub fn selected_index(&self) -> usize {
        self.selected_index
    }

    #[must_use]
    pub fn rows(&self) -> &[PolicyRow] {
        &self.rows
    }

    #[must_use]
    pub fn error(&self) -> Option<&ControlError> {
        self.health.error()
    }

    pub fn set_error(&mut self, error: ControlError) {
        self.health = PolicyHealth::Degraded { error };
    }

    #[must_use]
    pub fn dir(&self) -> Option<&Path> {
        self.dir.as_deref()
    }

    #[must_use]
    pub fn pending_rewrites(&self) -> usize {
        self.rows
            .iter()
            .filter(|policy| policy.status.rewrite_pending())
            .count()
    }

    #[must_use]
    pub fn selected_file(&self) -> Option<&Path> {
        self.rows
            .get(self.selected_index)
            .map(|policy| policy.file.as_path())
    }

    /// Reserves the selected policy source for an editor session.
    ///
    /// Opening the editor while a rewrite is queued or writing would let two
    /// independent writers race on the same Cedar files. The editor request is
    /// therefore rejected until pending rewrites have finished and the rows
    /// have been refreshed from disk.
    pub fn request_edit(&mut self) -> bool {
        if self.any_rewrite_pending() {
            let Some(file) = self.selected_file().map(Path::to_path_buf) else {
                return false;
            };

            self.set_error(ControlError::editor(file, EditorError::PendingRewrite));
            return false;
        }

        self.selected_file().is_some()
    }

    /// Reloads policy rows from the current policy directory.
    ///
    /// Successful reload replaces the discovered row set, clears policy errors,
    /// and clamps selection if the edited source added or removed rows. Failed
    /// reload keeps the previous rows visible and records the new error so the
    /// operator can fix the Cedar file without losing the last usable view.
    pub fn reload(&mut self) {
        match load_rows_from_dir(self.dir.clone(), &self.state_reader) {
            Ok(loaded) => {
                self.health = PolicyHealth::Ready;
                self.dir = loaded.dir;
                self.rows = loaded.rows;
                self.clamp_selected_index();
            }
            Err(error) => {
                self.set_error(error);
            }
        }
    }

    pub fn request_selected_toggle(&mut self) -> Option<PolicyRewriteRequest> {
        self.request_toggle(self.selected_index)
    }

    pub fn request_all_toggle(&mut self) -> Vec<PolicyRewriteRequest> {
        if self.cannot_request_all_toggle() {
            return Vec::new();
        }

        self.queue_all_toggle_batches(self.requested_all_toggle_state())
    }

    pub fn finish_rewrite(&mut self, completion: &PolicyRewriteCompletion) {
        self.refresh_states_for_file(&completion.file, &completion.ids);

        match &completion.result {
            Ok(()) if self.mark_state_mismatches(completion).is_empty() => {
                self.health = PolicyHealth::Ready;
            }
            Ok(()) => {
                self.set_error(policy_state_mismatch_error(completion));
            }
            Err(error) => {
                self.mark_rewrite_error(&completion.file, &completion.ids);
                self.set_error(error.clone());
            }
        }
    }

    pub fn start_rewrite(&mut self, policy: &PolicyRewriteStart) {
        self.set_batch_status(&policy.file, &policy.ids, PolicyRowStatus::Writing);
    }

    fn refresh_states_for_file(&mut self, file: &Path, completed_ids: &[String]) {
        let ids: Vec<String> = self
            .rows
            .iter()
            .filter(|policy| policy.file == file)
            .map(|policy| policy.id.clone())
            .collect();

        let states = self.state_reader.read(file, &ids);
        let completed_ids = id_set(completed_ids);

        for policy in &mut self.rows {
            if policy.file != file {
                continue;
            }

            let completed = completed_ids.contains(policy.id.as_str());
            let preserve_pending = policy.status.rewrite_pending() && !completed;
            policy.state = states
                .get(&policy.id)
                .copied()
                .unwrap_or(PolicyState::InvalidPolicy);

            if !preserve_pending {
                policy.status = PolicyRowStatus::State(policy.state);
            }
        }
    }

    fn mark_state_mismatches(&mut self, completion: &PolicyRewriteCompletion) -> Vec<String> {
        let ids = id_set(&completion.ids);
        let mut mismatches = Vec::new();
        for policy in &mut self.rows {
            if policy.file != completion.file || !ids.contains(policy.id.as_str()) {
                continue;
            }

            if policy.state != completion.requested {
                policy.status = PolicyRowStatus::Error;
                mismatches.push(policy.id.clone());
            }
        }

        mismatches
    }

    fn mark_rewrite_error(&mut self, file: &Path, ids: &[String]) {
        self.set_batch_status(file, ids, PolicyRowStatus::Error);
    }

    fn set_batch_status(&mut self, file: &Path, ids: &[String], status: PolicyRowStatus) {
        let ids = id_set(ids);
        for policy in &mut self.rows {
            if policy.file == file && ids.contains(policy.id.as_str()) {
                policy.status = status;
            }
        }
    }

    fn cannot_request_all_toggle(&self) -> bool {
        self.rows.is_empty() || self.any_rewrite_pending()
    }

    fn requested_all_toggle_state(&self) -> PolicyState {
        if self.rows.iter().all(|policy| policy.state.is_enabled()) {
            PolicyState::Disabled
        } else {
            PolicyState::Enabled
        }
    }

    fn queue_all_toggle_batches(&mut self, requested: PolicyState) -> Vec<PolicyRewriteRequest> {
        let mut batches = BTreeMap::<PathBuf, Vec<String>>::new();
        for policy in &mut self.rows {
            queue_policy_batch(policy, requested, &mut batches);
        }

        rewrite_requests_from_batches(batches, requested)
    }

    fn any_rewrite_pending(&self) -> bool {
        self.rows
            .iter()
            .any(|policy| policy.status.rewrite_pending())
    }

    fn clamp_selected_index(&mut self) {
        self.selected_index = self.selected_index.min(self.rows.len().saturating_sub(1));
    }

    fn request_toggle(&mut self, index: usize) -> Option<PolicyRewriteRequest> {
        let policy = self.rows.get_mut(index)?;
        if policy.status.rewrite_pending() {
            return None;
        }

        let requested = if policy.state.is_enabled() {
            PolicyState::Disabled
        } else {
            PolicyState::Enabled
        };

        policy.status = PolicyRowStatus::Queued;

        Some(PolicyRewriteRequest {
            file: policy.file.clone(),
            ids: vec![policy.id.clone()],
            requested,
        })
    }
}

impl Default for PoliciesState {
    fn default() -> Self {
        Self::new(None)
    }
}

struct LoadedRows {
    rows: Vec<PolicyRow>,
    dir: Option<PathBuf>,
    error: Option<ControlError>,
}

fn load_rows(policy_dir: Option<PathBuf>, state_reader: &PolicyStateReader) -> LoadedRows {
    match load_rows_from_dir(policy_dir, state_reader) {
        Ok(loaded) => loaded,
        Err(error) => LoadedRows {
            rows: Vec::new(),
            dir: None,
            error: Some(error),
        },
    }
}

fn load_rows_from_dir(
    policy_dir: Option<PathBuf>,
    state_reader: &PolicyStateReader,
) -> Result<LoadedRows, ControlError> {
    let Some(policy_dir) = policy_dir else {
        return Ok(LoadedRows {
            rows: Vec::new(),
            dir: None,
            error: None,
        });
    };

    let catalog = policies::discover(&policy_dir, state_reader)
        .map_err(|error| ControlError::policy_discovery(&policy_dir, error))?;

    let rows = catalog.policies().iter().map(policy_row).collect();
    Ok(LoadedRows {
        rows,
        dir: Some(catalog.policy_dir().to_path_buf()),
        error: None,
    })
}

fn policy_row(mapping: &PolicyMapping) -> PolicyRow {
    PolicyRow {
        id: mapping.id.clone(),
        file: mapping.file.clone(),
        state: mapping.state,
        status: PolicyRowStatus::State(mapping.state),
    }
}

fn queue_policy_batch(
    policy: &mut PolicyRow,
    requested: PolicyState,
    batches: &mut BTreeMap<PathBuf, Vec<String>>,
) {
    if policy.state == requested {
        return;
    }

    policy.status = PolicyRowStatus::Queued;
    batches
        .entry(policy.file.clone())
        .or_default()
        .push(policy.id.clone());
}

fn rewrite_requests_from_batches(
    batches: BTreeMap<PathBuf, Vec<String>>,
    requested: PolicyState,
) -> Vec<PolicyRewriteRequest> {
    batches
        .into_iter()
        .map(|(file, ids)| PolicyRewriteRequest {
            file,
            ids,
            requested,
        })
        .collect()
}

fn id_set(ids: &[String]) -> HashSet<&str> {
    ids.iter().map(String::as_str).collect()
}

fn policy_state_mismatch_error(completion: &PolicyRewriteCompletion) -> ControlError {
    ControlError::policy_rewrite(
        &completion.file,
        completion.ids.clone(),
        PolicyRewriteError::StateMismatch {
            requested: completion.requested,
        },
    )
}
