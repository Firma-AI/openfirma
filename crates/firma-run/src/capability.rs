use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::config::{CapabilityLeaseConfig, CapabilitySource};
use crate::error::RunError;

/// Runtime capability lease manager.
///
/// V1 source implementation supports file-backed capability material with
/// periodic refresh for long-running agents.
pub struct CapabilityLeaseManager {
    token: Arc<RwLock<Option<String>>>,
    stop_tx: Option<mpsc::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl CapabilityLeaseManager {
    /// Create a new lease manager for the resolved capability config.
    ///
    /// # Errors
    ///
    /// Returns an error when capability source initialization fails (for
    /// example, unreadable capability files or refresh thread startup failure).
    pub fn new(config: &CapabilityLeaseConfig) -> Result<Self, RunError> {
        match &config.source {
            CapabilitySource::Disabled => Ok(Self {
                token: Arc::new(RwLock::new(None)),
                stop_tx: None,
                task: None,
            }),
            CapabilitySource::File { path } => Self::from_file(path.clone()),
        }
    }

    fn from_file(path: PathBuf) -> Result<Self, RunError> {
        let initial = read_token(&path)?;
        let token = Arc::new(RwLock::new(Some(initial)));

        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let token_clone = Arc::clone(&token);

        let task = thread::Builder::new()
            .name("firma-run-capability-refresh".to_string())
            .spawn(move || {
                loop {
                    if stop_rx.recv_timeout(Duration::from_secs(5)).is_ok() {
                        break;
                    }

                    if let Ok(next_token) = read_token(&path)
                        && let Ok(mut writer) = token_clone.write()
                    {
                        *writer = Some(next_token);
                    }
                }
            })
            .map_err(|error| RunError::Capability(error.to_string()))?;

        Ok(Self {
            token,
            stop_tx: Some(stop_tx),
            task: Some(task),
        })
    }

    /// Returns the currently active capability token, if any.
    #[must_use]
    pub fn token(&self) -> Option<String> {
        self.token.read().ok().and_then(|guard| guard.clone())
    }
}

impl Drop for CapabilityLeaseManager {
    fn drop(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }

        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}

fn read_token(path: &Path) -> Result<String, RunError> {
    let value = std::fs::read_to_string(path)
        .map_err(|error| RunError::Capability(format!("{}: {error}", path.display())))?;

    let token = value.trim().to_string();
    if token.is_empty() {
        return Err(RunError::Capability(format!(
            "capability file {} is empty",
            path.display()
        )));
    }

    Ok(token)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::config::{CapabilityLeaseConfig, CapabilitySource};

    use super::CapabilityLeaseManager;

    #[test]
    fn disabled_source_has_no_token() {
        let manager = CapabilityLeaseManager::new(&CapabilityLeaseConfig {
            source: CapabilitySource::Disabled,
            refresh_ratio: 0.60,
            grace_seconds: 30,
        })
        .unwrap_or_else(|e| panic!("{e}"));

        assert!(manager.token().is_none());
    }

    #[test]
    fn file_source_loads_initial_token() {
        let tempdir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let token_path = tempdir.path().join("token.txt");
        fs::write(&token_path, "token-v1\n").unwrap_or_else(|e| panic!("{e}"));

        let manager = CapabilityLeaseManager::new(&CapabilityLeaseConfig {
            source: CapabilitySource::File { path: token_path },
            refresh_ratio: 0.60,
            grace_seconds: 30,
        })
        .unwrap_or_else(|e| panic!("{e}"));

        assert_eq!(manager.token(), Some("token-v1".to_string()));
    }
}
