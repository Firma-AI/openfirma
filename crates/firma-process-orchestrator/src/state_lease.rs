//! Generation-scoped authority over mutable stack runtime state.
//!
//! [`StateTransaction`] serializes cross-process state mutation, while
//! [`StateLease`] proves which startup generation may remove the resulting
//! files. The capabilities are deliberately separate: a stop can release
//! serialization while terminating processes, then use its lease to reject
//! cleanup if another generation has claimed the directory.

use std::io::Write as _;
use std::path::Path;

use crate::error::OrchestratorError;
use fs2::FileExt as _;

/// File containing the current [`StackGeneration`].
const LOCK_FILE: &str = "stack.lock";
/// Persistent coordination file locked by each [`StateTransaction`].
const TRANSACTION_FILE: &str = ".stack-state.lock";

/// Exclusive cross-process authority to mutate stack runtime state.
///
/// Startup holds this capability from generation claim through complete-state
/// publication or rollback. [`crate::stop::stop_components`] holds one while taking its
/// process snapshot, and cleanup reacquires one before deleting state. The
/// operating system releases the advisory lock if its process exits, preventing
/// a crashed mutator from permanently blocking recovery.
pub struct StateTransaction {
    _file: std::fs::File,
}

impl StateTransaction {
    /// Block until this process exclusively owns runtime-state mutation.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the coordination file cannot be opened or
    /// exclusively locked.
    pub(crate) fn acquire(state_dir: &Path) -> Result<Self, OrchestratorError> {
        let file = open_transaction_file(state_dir)?;
        file.lock_exclusive()?;
        Ok(Self { _file: file })
    }

    /// Attempt to acquire runtime-state mutation authority without blocking.
    ///
    /// An absent result means another process currently owns the transaction.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the coordination file cannot be opened or the
    /// lock attempt fails for a reason other than contention.
    pub(crate) fn try_acquire(state_dir: &Path) -> Result<Option<Self>, OrchestratorError> {
        let file = open_transaction_file(state_dir)?;
        match file.try_lock_exclusive() {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(error) if is_lock_contended(&error) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

/// Return whether a failed [`StateTransaction::try_acquire`] observed contention.
fn is_lock_contended(error: &std::io::Error) -> bool {
    let contended = fs2::lock_contended_error();
    contended.raw_os_error().map_or_else(
        || error.kind() == contended.kind(),
        |code| error.raw_os_error() == Some(code),
    )
}

/// Unforgeable identity shared by one launcher and stack generation.
///
/// Unlike a process ID, this value is not reused by the operating system and
/// does not imply that any process is alive. It exists only to distinguish one
/// startup attempt and its runtime-state files from predecessors and successors.
/// Detached startup creates the identity before spawning its supervisor, which
/// lets both processes fence rollback to the same attempt. A [`StateLease`] is
/// the capability that proves this identity was successfully claimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackGeneration(uuid::Uuid);

impl StackGeneration {
    /// Create a fresh identity before a launcher or local startup claims state.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    /// Parse an identity persisted in [`LOCK_FILE`].
    fn parse(value: &str) -> Result<Self, OrchestratorError> {
        uuid::Uuid::parse_str(value.trim())
            .map(Self)
            .map_err(|source| OrchestratorError::InvalidStackGeneration { source })
    }

    /// Return the canonical text stored in [`LOCK_FILE`].
    fn as_hyphenated(self) -> uuid::fmt::Hyphenated {
        self.0.hyphenated()
    }
}

impl Default for StackGeneration {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for StackGeneration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::str::FromStr for StackGeneration {
    type Err = OrchestratorError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Capability authorizing cleanup of one generation's runtime-state files.
///
/// A lease permits deletion only while [`Self::is_current`] confirms that its
/// generation still matches [`LOCK_FILE`]. It does not serialize mutation and
/// does not authorize process signalling; those responsibilities remain with
/// [`StateTransaction`] and [`crate::component::OwnedComponent`] respectively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateLease {
    generation: StackGeneration,
}

impl StateLease {
    /// Atomically claim an unlocked runtime-state directory.
    ///
    /// The fully written temporary file is published without replacing an
    /// existing lock, so readers can never observe a partial generation.
    /// An absent result means another generation already owns [`LOCK_FILE`].
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the generation cannot be written or published.
    pub(crate) fn try_claim(
        state_dir: &Path,
        generation: StackGeneration,
    ) -> Result<Option<Self>, OrchestratorError> {
        let lease = Self { generation };
        let temp = write_generation_temp(state_dir, lease)?;
        match temp.persist_noclobber(state_dir.join(LOCK_FILE)) {
            Ok(_) => Ok(Some(lease)),
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
            Err(error) => Err(error.error.into()),
        }
    }

    /// Atomically replace the current generation for race-test scaffolding.
    ///
    /// Production generation changes always use [`Self::try_claim`] after stale
    /// state is removed; this operation exists only to reproduce a delayed old
    /// owner observing replacement state.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the replacement cannot be published.
    #[cfg(feature = "test-support")]
    pub(crate) fn replace_for_test(state_dir: &Path) -> Result<Self, OrchestratorError> {
        let lease = Self {
            generation: StackGeneration::new(),
        };
        let temp = write_generation_temp(state_dir, lease)?;
        temp.persist(state_dir.join(LOCK_FILE))
            .map_err(|error| error.error)?;
        Ok(lease)
    }

    /// Load the generation currently recorded in a runtime-state directory.
    ///
    /// An absent result represents a missing [`LOCK_FILE`] or an empty file
    /// created by an older version. Legacy state remains stoppable but does not
    /// gain a lease token.
    ///
    /// # Errors
    ///
    /// Returns an I/O error other than absence, or an error for malformed state.
    pub(crate) fn load(state_dir: &Path) -> Result<Option<Self>, OrchestratorError> {
        match std::fs::read_to_string(state_dir.join(LOCK_FILE)) {
            Ok(value) if value.trim().is_empty() => Ok(None),
            Ok(value) => Ok(Some(Self {
                generation: StackGeneration::parse(&value)?,
            })),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Return whether this lease still names the directory's current generation.
    ///
    /// # Errors
    ///
    /// Returns runtime-state read or parse errors instead of authorizing cleanup
    /// when ownership cannot be established.
    pub(crate) fn is_current(self, state_dir: &Path) -> Result<bool, OrchestratorError> {
        Ok(Self::load(state_dir)? == Some(self))
    }

    /// Return whether this lease belongs to an expected [`StackGeneration`].
    pub(crate) fn belongs_to(self, generation: StackGeneration) -> bool {
        self.generation == generation
    }
}

/// Write and flush a complete generation beside [`LOCK_FILE`] for atomic publication.
fn write_generation_temp(
    state_dir: &Path,
    lease: StateLease,
) -> Result<tempfile::NamedTempFile, OrchestratorError> {
    let mut temp = tempfile::NamedTempFile::new_in(state_dir)?;
    writeln!(temp, "{}", lease.generation.as_hyphenated())?;
    temp.as_file().sync_all()?;
    Ok(temp)
}

/// Open [`TRANSACTION_FILE`] for a [`StateTransaction`] lock attempt.
fn open_transaction_file(state_dir: &Path) -> Result<std::fs::File, OrchestratorError> {
    Ok(std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(state_dir.join(TRANSACTION_FILE))?)
}
