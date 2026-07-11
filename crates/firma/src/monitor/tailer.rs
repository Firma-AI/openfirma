//! Poll-on-EOF tailer with rotation detection.

use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::time::{Duration, SystemTime};

use tracing::{debug, trace};

/// Internal source tag attached to each emitted line.
///
/// Mirrors the user-facing [`crate::args::monitor::Source`] but only carries
/// the three concrete source kinds; `All` is decomposed into per-source
/// tailer threads before reaching this layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Sidecar audit log (`audit.jsonl`).
    Audit,
    /// Authority component stdout/stderr log.
    Authority,
    /// Sidecar component stdout/stderr log.
    Sidecar,
}

/// One line emitted by a tailer thread onto the renderer channel.
#[derive(Debug, Clone)]
pub struct Line {
    /// Which file this line came from.
    pub source: Source,
    /// Raw line content with trailing CR/LF stripped.
    pub raw: String,
}

pub fn tail(
    path: PathBuf,
    source: Source,
    backfill_since: Option<SystemTime>,
    follow: bool,
    tx: Sender<Line>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    tail_inner(path, source, backfill_since, follow, tx, stop, None);
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "tailers run in spawned threads and intentionally own these handles"
)]
/// Implementation shared by production tailers and deterministic follow-mode
/// tests.
///
/// The optional `ready` channel is test-only coordination: we notify after each
/// successful open and initial seek, including reopens after rotation, so tests
/// can append only once the tailer is definitely watching the intended file.
fn tail_inner(
    path: PathBuf,
    source: Source,
    backfill_since: Option<SystemTime>,
    follow: bool,
    tx: Sender<Line>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ready: Option<Sender<()>>,
) {
    use std::sync::atomic::Ordering;

    debug!(?source, path = %path.display(), follow, "tailer thread started");
    loop {
        if stop.load(Ordering::SeqCst) {
            debug!(?source, "tailer stop signal received");
            return;
        }
        let Ok(file) = File::open(&path) else {
            if !follow {
                return;
            }
            trace!(path = %path.display(), "file missing; retrying");
            std::thread::sleep(Duration::from_millis(200));
            continue;
        };
        // Capture identity from the file we actually opened. The EOF loop below
        // compares the current path target against this snapshot to distinguish
        // "nothing new yet" from "the path now points at a different file".
        let initial_id = initial_file_id(&path, &file);
        let mut reader = BufReader::new(file);
        // Seek to EOF only when following without a backfill window: that mode
        // shows new events as they arrive. A one-shot read (`--no-follow`) must
        // dump what is already there, otherwise it always reports nothing.
        if backfill_since.is_some() || !follow {
            trace!(?source, "reading from start");
            let _ = reader.seek(SeekFrom::Start(0));
        } else {
            trace!(?source, "seeking to EOF");
            let _ = reader.seek(SeekFrom::End(0));
        }
        // Tests wait on this signal instead of racing the tailer thread with a
        // fixed sleep. Reopens reuse the same hook so rotation tests can wait
        // for the replacement file to be actively tailed.
        if let Some(ready_tx) = ready.as_ref() {
            let _ = ready_tx.send(());
        }

        let mut buffer = String::new();
        loop {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            buffer.clear();
            match reader.read_line(&mut buffer) {
                Ok(0) => {
                    if !path_still_matches_file(&path, initial_id.as_ref()) {
                        // The path was replaced or renamed underneath us. Break
                        // to the outer loop so we reopen and apply the normal
                        // initial seek rules to the replacement file.
                        debug!(?source, "file rotated; reopening");
                        break;
                    }
                    if !follow {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Ok(_) => {
                    if !line_passes_since(&buffer, backfill_since) {
                        continue;
                    }
                    if tx
                        .send(Line {
                            source,
                            raw: buffer.trim_end().to_string(),
                        })
                        .is_err()
                    {
                        return;
                    }
                }
                Err(_) => std::thread::sleep(Duration::from_millis(100)),
            }
        }
    }
}

fn line_passes_since(line: &str, since: Option<SystemTime>) -> bool {
    let Some(since) = since else {
        return true;
    };
    let Some(timestamp) = parse_leading_timestamp(line) else {
        return true;
    };
    timestamp >= since
}

fn parse_leading_timestamp(line: &str) -> Option<SystemTime> {
    let first = line.split_whitespace().next()?;
    let dt = chrono::DateTime::parse_from_rfc3339(first).ok()?;
    Some(SystemTime::from(dt))
}

#[cfg(unix)]
fn initial_file_id(path: &Path, _file: &File) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::metadata(path).ok()?;
    Some((metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
fn initial_file_id(_path: &Path, file: &File) -> Option<same_file::Handle> {
    // On Windows, metadata like file length changes on append and cannot be
    // used as a stable identity. Snapshot the opened file handle instead.
    same_file::Handle::from_file(file.try_clone().ok()?).ok()
}

#[cfg(unix)]
fn path_still_matches_file(path: &Path, initial_id: Option<&(u64, u64)>) -> bool {
    use std::os::unix::fs::MetadataExt;

    let current_id = std::fs::metadata(path)
        .ok()
        .map(|metadata| (metadata.dev(), metadata.ino()));
    current_id.as_ref() == initial_id
}

#[cfg(windows)]
fn path_still_matches_file(path: &Path, initial_id: Option<&same_file::Handle>) -> bool {
    let current_id = same_file::Handle::from_path(path).ok();
    current_id.as_ref() == initial_id
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc::channel;

    use super::*;

    #[test]
    fn follows_appended_lines() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, "").expect("seed");
        let (tx, rx) = channel::<Line>();
        let (ready_tx, ready_rx) = channel::<()>();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let path_thread = path.clone();
        let handle = std::thread::spawn(move || {
            tail_inner(
                path_thread,
                Source::Audit,
                None,
                true,
                tx,
                stop_thread,
                Some(ready_tx),
            );
        });

        // Wait until the tailer has opened the file and performed its initial
        // seek-to-EOF, otherwise a fast append can happen before follow mode is
        // actually watching for new data.
        ready_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("ready");
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open");
        writeln!(file, "hello").expect("write");
        let got = rx.recv_timeout(Duration::from_secs(2)).expect("line");
        assert_eq!(got.raw, "hello");
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        handle.join().ok();
    }

    #[test]
    fn one_shot_reads_existing_lines_from_start() {
        // `firma monitor --no-follow` (one-shot, no `--since`) must dump the
        // records already in the file. Previously it seeked to EOF and showed
        // nothing even when the audit log was full (FIR-193).
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, "first\nsecond\n").expect("seed");
        let (tx, rx) = channel::<Line>();
        let stop = Arc::new(AtomicBool::new(false));
        // follow = false, backfill_since = None.
        tail(path, Source::Audit, None, false, tx, stop);

        let lines: Vec<String> = rx.iter().map(|l| l.raw).collect();
        assert_eq!(lines, vec!["first".to_string(), "second".to_string()]);
    }

    #[test]
    fn follows_lines_after_rotation() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("audit.jsonl");
        let rotated = dir.path().join("audit.1.jsonl");
        std::fs::write(&path, "").expect("seed");
        let (tx, rx) = channel::<Line>();
        let (ready_tx, ready_rx) = channel::<()>();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let path_thread = path.clone();
        let handle = std::thread::spawn(move || {
            tail_inner(
                path_thread,
                Source::Audit,
                None,
                true,
                tx,
                stop_thread,
                Some(ready_tx),
            );
        });

        // First signal: initial open/seek on the original file.
        ready_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("initial ready");
        std::fs::rename(&path, &rotated).expect("rotate");
        std::fs::write(&path, "").expect("recreate");
        // Second signal: the tailer noticed rotation, reopened, and is now
        // following the replacement file at the original path.
        ready_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("reopen ready");

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open replacement");
        writeln!(file, "after-rotate").expect("write replacement");

        let got = rx.recv_timeout(Duration::from_secs(2)).expect("line");
        assert_eq!(got.raw, "after-rotate");

        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        handle.join().ok();
    }
}
