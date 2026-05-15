//! Feed a canned four-line ready sequence through the scraper and
//! assert the listen_addr is captured and `Ready` is signalled.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::io::Cursor;
use std::sync::mpsc;

use firma_run::authority::supervisor::testing::{ScrapeResult, run_scraper};

#[test]
fn ready_signalled_with_listen_addr_capture() {
    let stderr = b"\
2026-05-14T12:00:00Z  INFO firma_authority: config loaded policy_dir=\"/tmp\" listen_addr=\"[::1]:50051\"\n\
2026-05-14T12:00:00Z  INFO firma_authority: policy bundle loaded policies=1\n\
2026-05-14T12:00:00Z  INFO firma_authority: listening addr=\"[::1]:50051\"\n\
2026-05-14T12:00:00Z  INFO firma_authority: ready\n\
";
    let reader = Cursor::new(stderr.to_vec());
    let log: Vec<u8> = Vec::new();
    let (tx, rx) = mpsc::sync_channel(1);

    std::thread::spawn(move || run_scraper(reader, log, tx))
        .join()
        .expect("scraper thread");

    let result = rx.try_recv().expect("ready sent");
    match result {
        ScrapeResult::Ready(c) => assert_eq!(c.listen_addr, "[::1]:50051"),
        other => panic!("expected Ready, got {other:?}"),
    }
}

#[test]
fn eof_before_ready_signals_eof() {
    let stderr = b"some early line without listening or ready\n";
    let reader = Cursor::new(stderr.to_vec());
    let log: Vec<u8> = Vec::new();
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || run_scraper(reader, log, tx))
        .join()
        .expect("scraper thread");
    assert!(matches!(rx.try_recv().unwrap(), ScrapeResult::Eof));
}
