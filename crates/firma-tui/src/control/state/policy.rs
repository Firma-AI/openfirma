//! Policy row and rewrite state.

use std::path::{Path, PathBuf};

use crate::control::{
    error::ControlError,
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

#[derive(Debug)]
pub struct PoliciesState {
    selected_index: usize,
    error: Option<ControlError>,
    last_error: Option<ControlError>,
    dir: Option<PathBuf>,
    rows: Vec<PolicyRow>,
}

impl PoliciesState {
    #[must_use]
    pub fn new(policy_dir: Option<PathBuf>) -> Self {
        Self::with_state_reader(policy_dir, &PolicyStateReader::default())
    }

    #[must_use]
    pub fn with_state_reader(
        policy_dir: Option<PathBuf>,
        state_reader: &PolicyStateReader,
    ) -> Self {
        let loaded = load_rows(policy_dir, state_reader);
        Self {
            selected_index: 0,
            error: loaded.error.clone(),
            last_error: loaded.error,
            dir: loaded.dir,
            rows: loaded.rows,
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
