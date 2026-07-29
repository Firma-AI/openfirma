//! Policy row and rewrite state.

use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
};

use crate::control::{
    error::{ControlError, PolicyRewriteError},
    policies::{self, PolicyMapping, PolicyStateReader},
    toggle::PolicyState,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRow {
    pub id: String,
    pub file: PathBuf,
    pub state: PolicyState,
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
    pub const fn rewrite_pending(self) -> bool {
        matches!(self, Self::Queued | Self::Writing)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyKey {
    pub id: String,
    pub file: PathBuf,
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
    error: Option<ControlError>,
    last_error: Option<ControlError>,
    dir: Option<PathBuf>,
    rows: Vec<PolicyRow>,
    state_reader: PolicyStateReader,
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
            error: loaded.error.clone(),
            last_error: loaded.error,
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
        self.error.as_ref()
    }

    #[must_use]
    pub fn last_error(&self) -> Option<&ControlError> {
        self.last_error.as_ref()
    }

    pub fn set_error(&mut self, error: ControlError) {
        self.error = Some(error);
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

    pub fn request_selected_toggle(&mut self) -> Option<PolicyRewriteRequest> {
        self.request_toggle(self.selected_index)
    }

    pub fn request_all_toggle(&mut self) -> Vec<PolicyRewriteRequest> {
        if self.cannot_request_all_toggle() {
            return Vec::new();
        }

        let requested = self.requested_all_toggle_state();
        self.queue_all_toggle_batches(requested)
    }

    pub fn finish_rewrite(&mut self, completion: &PolicyRewriteCompletion) {
        let previous_error = self.error.clone();

        self.refresh_states_for_file(&completion.file, &completion.ids);

        match &completion.result {
            Ok(()) => {
                let mismatched_ids = self.mark_state_mismatches(
                    &completion.file,
                    &completion.ids,
                    completion.requested,
                );
                if mismatched_ids.is_empty() {
                    self.error = None;
                } else {
                    let error = policy_state_mismatch_error(
                        &completion.file,
                        mismatched_ids,
                        completion.requested,
                    );
                    self.set_error(error);
                }
            }
            Err(error) => {
                self.mark_rewrite_error(&completion.file, &completion.ids);
                self.set_error(error.clone());
            }
        }

        if self.error.is_none() {
            self.last_error = previous_error;
        }
    }

    pub fn start_rewrite(&mut self, policy: &PolicyRewriteStart) {
        self.set_batch_status(&policy.file, &policy.ids, PolicyRowStatus::Writing);
    }

    fn refresh_states_for_file(&mut self, file: &Path, completed_ids: &[String]) {
        let ids: Vec<String> = self
            .rows
            .iter()
            .filter(|row| row.file == file)
            .map(|row| row.id.clone())
            .collect();

        let states = self.state_reader.read(file, &ids);
        let completed_ids = id_set(completed_ids);

        for row in self.rows.iter_mut().filter(|row| row.file == file) {
            row.state = states
                .get(&row.id)
                .copied()
                .unwrap_or(PolicyState::InvalidPolicy);
            if completed_ids.contains(row.id.as_str()) || !row.status.rewrite_pending() {
                row.status = PolicyRowStatus::State(row.state);
            }
        }
    }

    fn mark_state_mismatches(
        &mut self,
        file: &Path,
        ids: &[String],
        requested: PolicyState,
    ) -> Vec<String> {
        let ids = id_set(ids);
        let mut mismatched_ids = Vec::new();

        for row in self
            .rows
            .iter_mut()
            .filter(|row| row.file == file && ids.contains(row.id.as_str()))
        {
            if row.state != requested {
                row.status = PolicyRowStatus::Error;
                mismatched_ids.push(row.id.clone());
            }
        }

        mismatched_ids
    }

    fn mark_rewrite_error(&mut self, file: &Path, ids: &[String]) {
        let ids = id_set(ids);
        for row in self
            .rows
            .iter_mut()
            .filter(|row| row.file == file && ids.contains(row.id.as_str()))
        {
            row.status = PolicyRowStatus::Error;
        }
    }

    fn set_batch_status(&mut self, file: &Path, ids: &[String], status: PolicyRowStatus) {
        let ids = id_set(ids);
        for row in self
            .rows
            .iter_mut()
            .filter(|row| row.file == file && ids.contains(row.id.as_str()))
        {
            row.status = status;
        }
    }

    fn cannot_request_all_toggle(&self) -> bool {
        self.rows.is_empty() || self.any_rewrite_pending()
    }

    fn requested_all_toggle_state(&self) -> PolicyState {
        if self
            .rows
            .iter()
            .all(|policy| policy.state == PolicyState::Enabled)
        {
            PolicyState::Disabled
        } else {
            PolicyState::Enabled
        }
    }

    fn queue_all_toggle_batches(&mut self, requested: PolicyState) -> Vec<PolicyRewriteRequest> {
        let mut batches = BTreeMap::<PathBuf, Vec<String>>::new();
        for policy in self
            .rows
            .iter_mut()
            .filter(|policy| policy.state != requested)
        {
            policy.status = PolicyRowStatus::Queued;
            batches
                .entry(policy.file.clone())
                .or_default()
                .push(policy.id.clone());
        }

        rewrite_requests_from_batches(batches, requested)
    }

    fn any_rewrite_pending(&self) -> bool {
        self.rows.iter().any(|row| row.status.rewrite_pending())
    }

    fn request_toggle(&mut self, index: usize) -> Option<PolicyRewriteRequest> {
        let policy = self.rows.get_mut(index)?;
        if policy.status.rewrite_pending() {
            return None;
        }

        let requested = match policy.state {
            PolicyState::Enabled => PolicyState::Disabled,
            PolicyState::Disabled => PolicyState::Enabled,
            PolicyState::MissingFile
            | PolicyState::MissingId
            | PolicyState::InvalidPolicy
            | PolicyState::ReadError => return None,
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

fn policy_state_mismatch_error(
    file: &Path,
    ids: Vec<String>,
    requested: PolicyState,
) -> ControlError {
    ControlError::policy_rewrite(file, ids, PolicyRewriteError::StateMismatch { requested })
}
