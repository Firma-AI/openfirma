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

#[allow(
    clippy::needless_pass_by_value,
    reason = "tailers run in spawned threads and intentionally own these handles"
)]
pub fn tail(
    path: PathBuf,
    source: Source,
    backfill_since: Option<SystemTime>,
    follow: bool,
    tx: Sender<Line>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
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
        let initial_id = file_id(&path);
        let mut reader = BufReader::new(file);
        if backfill_since.is_some() {
            trace!(?source, "seeking to start for backfill");
            let _ = reader.seek(SeekFrom::Start(0));
        } else {
            trace!(?source, "seeking to EOF");
            let _ = reader.seek(SeekFrom::End(0));
        }

        let mut buffer = String::new();
        loop {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            buffer.clear();
            match reader.read_line(&mut buffer) {
                Ok(0) => {
                    if file_id(&path) != initial_id {
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
fn file_id(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path).ok()?;
    Some((metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
fn file_id(path: &Path) -> Option<u64> {
    let metadata = std::fs::metadata(path).ok()?;
    Some(metadata.len())
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
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let path_thread = path.clone();
        let handle = std::thread::spawn(move || {
            tail(path_thread, Source::Audit, None, true, tx, stop_thread)
        });

        std::thread::sleep(Duration::from_millis(200));
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
}
