//! Wire `firma monitor` CLI args to the tailer and renderer.

use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;

use tracing::{debug, info};

use crate::args::monitor::{Args, Decision, Format, Source as ArgSource};
use crate::monitor::follow::resolve_follow;
use crate::monitor::since;
use crate::monitor::tailer::{self, Source as TailSource};

pub fn run(args: Args) -> ExitCode {
    let decision_filter = if args.only_deny {
        Some(Decision::Deny)
    } else {
        args.decision
    };
    let format = if args.json { Format::Json } else { args.format };
    let follow = resolve_follow(args.tail, args.no_follow, io::stdout().is_terminal());

    info!(
        source = ?args.source,
        format = ?format,
        follow,
        decision = ?decision_filter,
        action_class = ?args.action_class,
        agent = ?args.agent,
        since = ?args.since,
        "firma monitor starting"
    );
    let state_dir = match crate::services::stack::resolve_state_dir(args.state_dir) {
        Ok(path) => path,
        Err(error) => {
            eprintln!("firma monitor: {error}");
            return ExitCode::from(2);
        }
    };

    let backfill = match args.since.as_deref() {
        Some(value) => match since::parse(value) {
            Ok(time) => {
                debug!(?time, "parsed --since cutoff");
                Some(time)
            }
            Err(error) => {
                eprintln!("firma monitor: --since: {error}");
                return ExitCode::from(2);
            }
        },
        None => None,
    };

    let (tx, rx) = channel::<tailer::Line>();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_handler = Arc::clone(&stop);
    let _ = ctrlc::set_handler(move || {
        stop_handler.store(true, Ordering::SeqCst);
    });

    let sources: Vec<(PathBuf, TailSource)> = match args.source {
        ArgSource::Audit => vec![(state_dir.join("audit.jsonl"), TailSource::Audit)],
        ArgSource::Authority => vec![(state_dir.join("authority.log"), TailSource::Authority)],
        ArgSource::Sidecar => vec![(state_dir.join("sidecar.log"), TailSource::Sidecar)],
        ArgSource::All => vec![
            (state_dir.join("audit.jsonl"), TailSource::Audit),
            (state_dir.join("authority.log"), TailSource::Authority),
            (state_dir.join("sidecar.log"), TailSource::Sidecar),
        ],
    };

    let mut handles = Vec::new();
    for (path, source) in sources {
        debug!(?source, path = %path.display(), "starting tailer thread");
        let tx = tx.clone();
        let stop = Arc::clone(&stop);
        handles.push(std::thread::spawn(move || {
            tailer::tail(path, source, backfill, follow, tx, stop);
        }));
    }
    drop(tx);

    let stdout = io::stdout();
    let mut out = stdout.lock();
    while let Ok(line) = rx.recv() {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        if let Err(error) = crate::monitor::render::render(
            &line,
            format,
            decision_filter,
            args.action_class.as_deref(),
            args.agent.as_deref(),
            &mut out,
        ) {
            if error.kind() == io::ErrorKind::BrokenPipe {
                break;
            }
            eprintln!("firma monitor: render: {error}");
            return ExitCode::from(2);
        }
        let _ = out.flush();
    }

    stop.store(true, Ordering::SeqCst);
    info!("monitor stopping; joining tailers");
    for handle in handles {
        let _ = handle.join();
    }
    info!("monitor exited");
    ExitCode::SUCCESS
}
