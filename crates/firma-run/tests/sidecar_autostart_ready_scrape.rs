//! Unit tests for the stderr scraper used by `SidecarSupervisor`.
//!
//! Feeds canned tracing-fmt-style lines through `run_scraper` and asserts
//! that the seven-line ready contract is detected, that the version and
//! authority endpoint are captured from lines 3 and 4, and that the tee
//! continues to drain after `ready`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics acceptable on test failure"
)]

use std::io::Cursor;
use std::sync::mpsc;

use firma_run::sidecar::supervisor::testing::{ReadyCapture, ScrapeResult, run_scraper};

const FULL: &str = "\
2026-05-13T10:00:00Z  INFO firma_sidecar::startup::log_contract: config loaded path=\"/tmp/firma_sidecar.toml\"\n\
2026-05-13T10:00:00Z  INFO firma_sidecar::startup::log_contract: mapping table loaded rules=44\n\
2026-05-13T10:00:00Z  INFO firma_sidecar::startup::log_contract: policy bundle loaded version=\"ab12cd34\" policies=3\n\
2026-05-13T10:00:00Z  INFO firma_sidecar::startup::log_contract: authority stream connected endpoint=\"(disabled)\"\n\
2026-05-13T10:00:00Z  INFO firma_sidecar::startup::log_contract: connector registry built hosts=12 default_timeout_ms=5000\n\
2026-05-13T10:00:00Z  INFO firma_sidecar::startup::log_contract: interceptor listening addr=\"/run/firma/abc/sidecar.sock\"\n\
2026-05-13T10:00:00Z  INFO firma_sidecar::startup::log_contract: ready\n\
2026-05-13T10:00:01Z  INFO firma_sidecar::pipeline: serving request id=42\n";

#[test]
fn captures_version_and_disabled_authority_then_returns_ready() {
    let (tx, rx) = mpsc::sync_channel(1);
    let mut sink = Vec::<u8>::new();
    run_scraper(Cursor::new(FULL), &mut sink, tx);

    let result = rx.try_recv().expect("scraper sent result");
    let capture = match result {
        ScrapeResult::Ready(c) => c,
        other => panic!("expected Ready, got {other:?}"),
    };
    assert_eq!(
        capture,
        ReadyCapture {
            policy_bundle_version: "ab12cd34".into(),
            authority_url: String::new(),
        }
    );

    // Tee drained everything including the post-ready line.
    let drained = String::from_utf8(sink).expect("utf8");
    assert!(drained.contains("serving request id=42"));
    assert!(drained.contains("ready"));
}

#[test]
fn captures_explicit_authority_endpoint() {
    let lines = "\
INFO firma_sidecar::startup::log_contract: config loaded path=\"/etc/firma.toml\"\n\
INFO firma_sidecar::startup::log_contract: mapping table loaded rules=44\n\
INFO firma_sidecar::startup::log_contract: policy bundle loaded version=\"deadbeef\" policies=2\n\
INFO firma_sidecar::startup::log_contract: authority stream connected endpoint=\"https://authority.example:8443\"\n\
INFO firma_sidecar::startup::log_contract: connector registry built hosts=5 default_timeout_ms=5000\n\
INFO firma_sidecar::startup::log_contract: interceptor listening addr=\"127.0.0.1:8080\"\n\
INFO firma_sidecar::startup::log_contract: ready\n";

    let (tx, rx) = mpsc::sync_channel(1);
    let mut sink = Vec::<u8>::new();
    run_scraper(Cursor::new(lines), &mut sink, tx);

    let capture = match rx.recv().expect("result") {
        ScrapeResult::Ready(c) => c,
        other => panic!("expected Ready, got {other:?}"),
    };
    assert_eq!(capture.policy_bundle_version, "deadbeef");
    assert_eq!(capture.authority_url, "https://authority.example:8443");
}

#[test]
fn eof_before_ready_signals_eof() {
    let truncated = "\
INFO firma_sidecar::startup::log_contract: config loaded path=\"/tmp.toml\"\n\
INFO firma_sidecar::startup::log_contract: mapping table loaded rules=1\n";
    let (tx, rx) = mpsc::sync_channel(1);
    let mut sink = Vec::<u8>::new();
    run_scraper(Cursor::new(truncated), &mut sink, tx);

    match rx.recv().expect("result") {
        ScrapeResult::Eof => {}
        other => panic!("expected Eof, got {other:?}"),
    }
}

#[test]
fn ready_line_detected_through_ansi_escapes() {
    // tracing-subscriber may emit ANSI colour codes even when stderr is
    // piped. The scraper must ignore them. Lines below mirror the exact
    // shape observed from a live `firma sidecar` child.
    let ansi = "\u{1b}[2m2026-05-13T11:52:25.306017Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2mfirma_sidecar::startup::log_contract\u{1b}[0m\u{1b}[2m:\u{1b}[0m \u{1b}[2m54:\u{1b}[0m config loaded \u{1b}[3mpath\u{1b}[0m\u{1b}[2m=\u{1b}[0m/tmp/firma_sidecar.toml\n\
\u{1b}[2m2026-05-13T11:52:25.306025Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2mfirma_sidecar::startup::log_contract\u{1b}[0m\u{1b}[2m:\u{1b}[0m \u{1b}[2m55:\u{1b}[0m mapping table loaded \u{1b}[3mrules\u{1b}[0m\u{1b}[2m=\u{1b}[0m1\n\
\u{1b}[2m2026-05-13T11:52:25.306030Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2mfirma_sidecar::startup::log_contract\u{1b}[0m\u{1b}[2m:\u{1b}[0m \u{1b}[2m56:\u{1b}[0m policy bundle loaded \u{1b}[3mversion\u{1b}[0m\u{1b}[2m=\u{1b}[0me3b0c442 \u{1b}[3mpolicies\u{1b}[0m\u{1b}[2m=\u{1b}[0m0\n\
\u{1b}[2m2026-05-13T11:52:25.306036Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2mfirma_sidecar::startup::log_contract\u{1b}[0m\u{1b}[2m:\u{1b}[0m \u{1b}[2m61:\u{1b}[0m authority stream connected \u{1b}[3mendpoint\u{1b}[0m\u{1b}[2m=\u{1b}[0mhttp://127.0.0.1:50051\n\
\u{1b}[2m2026-05-13T11:52:25.306041Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2mfirma_sidecar::startup::log_contract\u{1b}[0m\u{1b}[2m:\u{1b}[0m \u{1b}[2m62:\u{1b}[0m connector registry built \u{1b}[3mhosts\u{1b}[0m\u{1b}[2m=\u{1b}[0m0 \u{1b}[3mdefault_timeout_ms\u{1b}[0m\u{1b}[2m=\u{1b}[0m30000\n\
\u{1b}[2m2026-05-13T11:52:25.306046Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2mfirma_sidecar::startup::log_contract\u{1b}[0m\u{1b}[2m:\u{1b}[0m \u{1b}[2m67:\u{1b}[0m interceptor listening \u{1b}[3maddr\u{1b}[0m\u{1b}[2m=\u{1b}[0m/tmp/firma-501/sidecar.sock\n\
\u{1b}[2m2026-05-13T11:52:25.306051Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2mfirma_sidecar::startup::log_contract\u{1b}[0m\u{1b}[2m:\u{1b}[0m \u{1b}[2m68:\u{1b}[0m ready\n";

    let (tx, rx) = mpsc::sync_channel(1);
    let mut sink = Vec::<u8>::new();
    run_scraper(Cursor::new(ansi), &mut sink, tx);

    let capture = match rx.recv().expect("result") {
        ScrapeResult::Ready(c) => c,
        other => panic!("expected Ready, got {other:?}"),
    };
    assert_eq!(capture.policy_bundle_version, "e3b0c442");
    assert_eq!(capture.authority_url, "http://127.0.0.1:50051");

    // The tee preserves the raw bytes including escapes.
    let drained = String::from_utf8(sink).expect("utf8");
    assert!(drained.contains("\u{1b}["));
}

#[test]
fn ready_substring_inside_earlier_field_does_not_trip_match() {
    // Earlier lines must not be mistaken for the final `ready` line even
    // if they contain the substring within a structured field.
    let mixed = "\
INFO firma_sidecar::startup::log_contract: config loaded path=\"/tmp.toml\" note=\"ready soon\"\n\
INFO firma_sidecar::startup::log_contract: mapping table loaded rules=1\n\
INFO firma_sidecar::startup::log_contract: policy bundle loaded version=\"v1\" policies=0\n\
INFO firma_sidecar::startup::log_contract: authority stream connected endpoint=\"(disabled)\"\n\
INFO firma_sidecar::startup::log_contract: connector registry built hosts=0 default_timeout_ms=5000\n\
INFO firma_sidecar::startup::log_contract: interceptor listening addr=\"127.0.0.1:8080\"\n\
INFO firma_sidecar::startup::log_contract: ready\n";

    let (tx, rx) = mpsc::sync_channel(1);
    let mut sink = Vec::<u8>::new();
    run_scraper(Cursor::new(mixed), &mut sink, tx);

    match rx.recv().expect("result") {
        ScrapeResult::Ready(_) => {}
        other => panic!("expected Ready, got {other:?}"),
    }
}
