//! The approval-wait policy: delay scheduling, deadline handling, wire
//! decoding, and failure classification — all pure, no network, no real
//! time.

use std::time::Duration;

use chrono::{DateTime, Utc};
use firma_protobuf::v1::get_approval_outcome_response::Outcome;
use firma_protobuf::v1::{
    CapabilityToken, DeniedApproval, ExpiredApproval, GetApprovalOutcomeResponse, GrantedApproval,
    PendingApproval,
};
use firma_run::capability::approval_wait::{
    ApprovalWaitPolicy, BackoffSample, FailureClass, FailureKind, MAX_POLL_DELAY, MIN_POLL_DELAY,
    OutcomeDecodeError, OutcomeMessage, PollError, RawToken, RpcFailure, SleepOutcome, WaitError,
    drive_wait,
};
use pretty_assertions::assert_eq;

#[expect(
    clippy::expect_used,
    reason = "test helper over constant inputs; clippy's in-tests allowance \
              covers #[test] functions but not free helpers"
)]
fn t(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(secs, 0).expect("timestamp in range")
}

fn policy(poll_secs: u64) -> ApprovalWaitPolicy {
    ApprovalWaitPolicy {
        poll_interval: Duration::from_secs(poll_secs),
        max_wait: None,
    }
}

#[test]
fn server_advisory_wins_over_the_poll_interval() {
    let delay = policy(5).next_delay(
        Some(Duration::from_secs(7)),
        BackoffSample::new(0, 0.0),
        t(0),
        t(600),
    );
    assert_eq!(delay, Some(Duration::from_secs(7)));
}

#[test]
fn poll_interval_is_the_fallback_without_an_advisory() {
    let delay = policy(5).next_delay(None, BackoffSample::new(0, 0.0), t(0), t(600));
    assert_eq!(delay, Some(Duration::from_secs(5)));
}

#[test]
fn jitter_is_deterministic_from_the_injected_unit() {
    // Same unit, same delay; the amplitude is ±20% of the candidate.
    let up = policy(10).next_delay(None, BackoffSample::new(0, 1.0), t(0), t(600));
    let down = policy(10).next_delay(None, BackoffSample::new(0, -1.0), t(0), t(600));
    assert_eq!(up, Some(Duration::from_secs(12)));
    assert_eq!(down, Some(Duration::from_secs(8)));
    assert_eq!(
        up,
        policy(10).next_delay(None, BackoffSample::new(0, 1.0), t(0), t(600))
    );
}

#[test]
fn clamp_applies_after_the_jitter() {
    // 30s + positive jitter would exceed the cap: the clamp wins.
    let capped = policy(5).next_delay(
        Some(MAX_POLL_DELAY),
        BackoffSample::new(0, 1.0),
        t(0),
        t(600),
    );
    assert_eq!(capped, Some(MAX_POLL_DELAY));
    // 1s with negative jitter would undercut the floor: the clamp wins.
    let floored = policy(5).next_delay(
        Some(MIN_POLL_DELAY),
        BackoffSample::new(0, -1.0),
        t(0),
        t(600),
    );
    assert_eq!(floored, Some(MIN_POLL_DELAY));
    // A non-finite sample cannot poison the schedule.
    let nan = policy(5).next_delay(None, BackoffSample::new(0, f64::NAN), t(0), t(600));
    assert_eq!(nan, Some(Duration::from_secs(5)));
}

#[test]
fn hostile_advisory_near_duration_max_cannot_panic_the_schedule() {
    // Regression: retry_after up to i64::MAX seconds arrives from the wire;
    // with a throttle step the old code overflowed `mul_f64` and panicked.
    // The candidate is bounded before the jitter, so this must clamp.
    let huge = Duration::from_secs(u64::MAX / 2);
    let delay = policy(5).next_delay(Some(huge), BackoffSample::new(1, 1.0), t(0), t(600));
    assert_eq!(delay, Some(MAX_POLL_DELAY));
}

#[test]
fn throttling_doubles_the_delay_and_still_respects_the_cap() {
    let doubled = policy(5).next_delay(None, BackoffSample::new(1, 0.0), t(0), t(600));
    assert_eq!(doubled, Some(Duration::from_secs(10)));
    let quadrupled = policy(5).next_delay(None, BackoffSample::new(2, 0.0), t(0), t(600));
    assert_eq!(quadrupled, Some(Duration::from_secs(20)));
    // Past the cap the clamp holds, however large the exponent grows.
    let capped = policy(5).next_delay(None, BackoffSample::new(30, 0.0), t(0), t(600));
    assert_eq!(capped, Some(MAX_POLL_DELAY));
}

#[test]
fn no_delay_is_scheduled_on_or_past_the_deadline() {
    // Exactly on the deadline: the poll would land too late.
    assert_eq!(
        policy(5).next_delay(None, BackoffSample::new(0, 0.0), t(0), t(5)),
        None
    );
    // Past it, same answer.
    assert_eq!(
        policy(5).next_delay(None, BackoffSample::new(0, 0.0), t(10), t(5)),
        None
    );
    // One second of room is enough to schedule.
    assert_eq!(
        policy(5).next_delay(None, BackoffSample::new(0, 0.0), t(0), t(6)),
        Some(Duration::from_secs(5))
    );
}

#[test]
fn deadline_is_the_earlier_of_expiry_and_max_wait() {
    let unbounded = policy(5);
    assert_eq!(unbounded.deadline(t(0), t(600)), t(600));

    let bounded = ApprovalWaitPolicy {
        poll_interval: Duration::from_secs(5),
        max_wait: Some(Duration::from_mins(2)),
    };
    // The local cap shortens the wait...
    assert_eq!(bounded.deadline(t(0), t(600)), t(120));
    // ...but never extends past the server-side expiry.
    assert_eq!(bounded.deadline(t(0), t(60)), t(60));
}

#[test]
fn every_listed_failure_kind_has_its_class() {
    let expectations = [
        (FailureKind::Transport, FailureClass::Transient),
        (FailureKind::Unavailable, FailureClass::Transient),
        (FailureKind::DeadlineExceeded, FailureClass::Transient),
        (FailureKind::Cancelled, FailureClass::Transient),
        (FailureKind::ResourceExhausted, FailureClass::Throttled),
        (FailureKind::NotFound, FailureClass::Permanent),
        (FailureKind::InvalidArgument, FailureClass::Permanent),
        (FailureKind::Unauthenticated, FailureClass::Permanent),
        (FailureKind::FailedPrecondition, FailureClass::Permanent),
        (FailureKind::Internal, FailureClass::Permanent),
        (FailureKind::Unimplemented, FailureClass::Permanent),
        (FailureKind::Other, FailureClass::Permanent),
    ];
    for (kind, class) in expectations {
        assert_eq!(kind.class(), class, "{kind:?}");
    }
}

#[test]
fn unknown_status_codes_fail_closed_as_permanent() {
    // A code the policy never listed (here: ABORTED) must never keep the
    // loop alive.
    let failure = RpcFailure::from(tonic::Status::aborted("some future condition"));
    assert_eq!(failure.kind, FailureKind::Other);
    assert_eq!(failure.kind.class(), FailureClass::Permanent);
}

#[test]
fn status_codes_map_onto_owned_kinds() {
    let cases = [
        (tonic::Status::unavailable("x"), FailureKind::Unavailable),
        (
            tonic::Status::deadline_exceeded("x"),
            FailureKind::DeadlineExceeded,
        ),
        (tonic::Status::cancelled("x"), FailureKind::Cancelled),
        (
            tonic::Status::resource_exhausted("x"),
            FailureKind::ResourceExhausted,
        ),
        (tonic::Status::not_found("x"), FailureKind::NotFound),
        (
            tonic::Status::invalid_argument("x"),
            FailureKind::InvalidArgument,
        ),
        (
            tonic::Status::unauthenticated("x"),
            FailureKind::Unauthenticated,
        ),
        (
            tonic::Status::failed_precondition("x"),
            FailureKind::FailedPrecondition,
        ),
        (tonic::Status::internal("x"), FailureKind::Internal),
        (
            tonic::Status::unimplemented("x"),
            FailureKind::Unimplemented,
        ),
    ];
    for (status, kind) in cases {
        assert_eq!(RpcFailure::from(status).kind, kind);
    }
}

fn response(outcome: Outcome) -> GetApprovalOutcomeResponse {
    GetApprovalOutcomeResponse {
        outcome: Some(outcome),
    }
}

#[test]
fn pending_timestamp_with_negative_nanos_is_dropped_not_reinterpreted() {
    let message = OutcomeMessage::try_from(response(Outcome::Pending(PendingApproval {
        expires_at: Some(prost_types::Timestamp {
            seconds: 600,
            nanos: -1,
        }),
        retry_after: None,
    })))
    .unwrap();
    assert_eq!(
        message,
        OutcomeMessage::Pending {
            expires_at: None,
            retry_after: None,
        }
    );
}

#[test]
fn pending_outcome_decodes_deadline_and_advisory() {
    let message = OutcomeMessage::try_from(response(Outcome::Pending(PendingApproval {
        expires_at: Some(prost_types::Timestamp {
            seconds: 600,
            nanos: 0,
        }),
        retry_after: Some(prost_types::Duration {
            seconds: 5,
            nanos: 0,
        }),
    })))
    .unwrap();
    assert_eq!(
        message,
        OutcomeMessage::Pending {
            expires_at: Some(t(600)),
            retry_after: Some(Duration::from_secs(5)),
        }
    );
}

#[test]
fn granted_outcome_carries_the_raw_token() {
    let message = OutcomeMessage::try_from(response(Outcome::Granted(Box::new(GrantedApproval {
        token: Some(CapabilityToken {
            signature: b"v4.public.tokenbytes".to_vec(),
            ..Default::default()
        }),
    }))))
    .unwrap();
    assert_eq!(
        message,
        OutcomeMessage::Granted {
            raw_token: RawToken::new("v4.public.tokenbytes".to_string()),
        }
    );
}

#[test]
fn raw_token_debug_never_prints_the_bearer() {
    let token = RawToken::new("v4.public.supersecret".to_string());
    let rendered = format!("{token:?}");
    assert_eq!(rendered, "RawToken(<redacted>)");
    assert!(!rendered.contains("supersecret"));
    // The bearer is still releasable, once, by consuming the wrapper.
    assert_eq!(token.into_inner(), "v4.public.supersecret");
}

#[test]
fn terminal_outcomes_decode_without_payload() {
    assert_eq!(
        OutcomeMessage::try_from(response(Outcome::Denied(DeniedApproval {}))).unwrap(),
        OutcomeMessage::Denied
    );
    assert_eq!(
        OutcomeMessage::try_from(response(Outcome::Expired(ExpiredApproval {}))).unwrap(),
        OutcomeMessage::Expired
    );
}

#[test]
fn malformed_responses_fail_closed_with_a_typed_error() {
    // No outcome at all.
    let missing = OutcomeMessage::try_from(GetApprovalOutcomeResponse { outcome: None });
    assert_eq!(missing.unwrap_err(), OutcomeDecodeError::MissingOutcome);

    // Granted without a token.
    let tokenless =
        OutcomeMessage::try_from(response(Outcome::Granted(Box::new(GrantedApproval {
            token: None,
        }))));
    assert_eq!(tokenless.unwrap_err(), OutcomeDecodeError::MissingToken);

    // Granted with non-UTF-8 token bytes.
    let garbled = OutcomeMessage::try_from(response(Outcome::Granted(Box::new(GrantedApproval {
        token: Some(CapabilityToken {
            signature: vec![0xff, 0xfe, 0xfd],
            ..Default::default()
        }),
    }))));
    assert_eq!(garbled.unwrap_err(), OutcomeDecodeError::TokenNotUtf8);
}

/// Test harness for [`drive_wait`]: scripted polls, recorded sleeps, a
/// manually advanced clock, zero jitter.
struct Loop {
    responses: std::collections::VecDeque<Result<OutcomeMessage, PollError>>,
    slept: Vec<Duration>,
    clock: DateTime<Utc>,
    stop_after_sleeps: Option<usize>,
}

impl Loop {
    fn new(responses: Vec<Result<OutcomeMessage, PollError>>) -> Self {
        Self {
            responses: responses.into(),
            slept: Vec::new(),
            clock: t(0),
            stop_after_sleeps: None,
        }
    }

    fn run(
        &mut self,
        policy: &ApprovalWaitPolicy,
        deadline: DateTime<Utc>,
    ) -> Result<RawToken, WaitError> {
        use std::cell::{Cell, RefCell};

        let mut responses = std::mem::take(&mut self.responses);
        let slept: RefCell<Vec<Duration>> = RefCell::new(Vec::new());
        let clock = Cell::new(self.clock);
        let stop_after = self.stop_after_sleeps;
        let result = {
            let mut poll = || {
                responses.pop_front().unwrap_or_else(|| {
                    Err(PollError::Rpc(RpcFailure::transport("script exhausted")))
                })
            };
            let mut sleep = |delay: Duration| {
                slept.borrow_mut().push(delay);
                // The fake clock advances by exactly the slept delay.
                clock.set(clock.get() + chrono::Duration::from_std(delay).unwrap_or_default());
                if stop_after.is_some_and(|n| slept.borrow().len() >= n) {
                    SleepOutcome::Stopped
                } else {
                    SleepOutcome::Slept
                }
            };
            let mut now = || clock.get();
            let mut jitter = || 0.0;
            drive_wait(
                policy,
                deadline,
                &mut poll,
                &mut sleep,
                &mut now,
                &mut jitter,
            )
        };
        self.slept = slept.into_inner();
        self.clock = clock.get();
        result
    }
}

fn pending(retry_secs: u64) -> OutcomeMessage {
    OutcomeMessage::Pending {
        expires_at: None,
        retry_after: Some(Duration::from_secs(retry_secs)),
    }
}

fn granted(token: &str) -> OutcomeMessage {
    OutcomeMessage::Granted {
        raw_token: RawToken::new(token.to_string()),
    }
}

fn failure(kind_status: tonic::Status) -> Result<OutcomeMessage, PollError> {
    Err(PollError::Rpc(RpcFailure::from(kind_status)))
}

#[test]
fn loop_waits_through_pending_and_returns_the_grant() {
    let mut harness = Loop::new(vec![
        Ok(pending(2)),
        Ok(pending(2)),
        Ok(granted("v4.public.tok")),
    ]);
    let token = harness.run(&policy(5), t(600)).expect("granted");
    assert_eq!(token, RawToken::new("v4.public.tok".to_string()));
    assert_eq!(harness.slept, vec![Duration::from_secs(2); 2]);
}

#[test]
fn loop_tightens_deadline_from_a_pending_expiry() {
    // The server answers pending with an expiry 3s away; the local deadline
    // was 600s. The 5s advisory would sleep past the tightened deadline, so
    // the wait ends immediately, without even sleeping.
    let mut harness = Loop::new(vec![Ok(OutcomeMessage::Pending {
        expires_at: Some(t(3)),
        retry_after: Some(Duration::from_secs(5)),
    })]);
    let error = harness.run(&policy(5), t(600)).unwrap_err();
    assert!(matches!(error, WaitError::DeadlineReached));
    assert!(harness.slept.is_empty());
}

#[test]
fn loop_retries_transient_failures_with_growing_backoff() {
    let mut harness = Loop::new(vec![
        failure(tonic::Status::unavailable("down")),
        failure(tonic::Status::unavailable("down")),
        Ok(granted("v4.public.tok")),
    ]);
    harness
        .run(&policy(2), t(600))
        .expect("granted after retries");
    // Backoff doubles per consecutive failure: 2s*2, then 2s*4.
    assert_eq!(
        harness.slept,
        vec![Duration::from_secs(4), Duration::from_secs(8)]
    );
}

#[test]
fn loop_doubles_the_delay_when_throttled() {
    let mut harness = Loop::new(vec![
        failure(tonic::Status::resource_exhausted("slow down")),
        Ok(granted("v4.public.tok")),
    ]);
    harness.run(&policy(5), t(600)).expect("granted");
    assert_eq!(harness.slept, vec![Duration::from_secs(10)]);
}

#[test]
fn loop_stops_at_once_on_a_permanent_failure() {
    let mut harness = Loop::new(vec![failure(tonic::Status::not_found("nope"))]);
    let err = harness
        .run(&policy(5), t(600))
        .expect_err("permanent stops");
    assert!(matches!(
        err,
        WaitError::Failure(RpcFailure {
            kind: FailureKind::NotFound,
            ..
        })
    ));
    assert!(
        harness.slept.is_empty(),
        "no sleep after a permanent failure"
    );
}

#[test]
fn loop_enforces_the_local_deadline_even_if_the_server_keeps_pending() {
    // Defense in depth: the server answers pending forever; the local clock
    // must end the wait on its own.
    let mut harness = Loop::new((0..100).map(|_| Ok(pending(30))).collect());
    let err = harness
        .run(&policy(5), t(70))
        .expect_err("deadline must win");
    assert_eq!(err, WaitError::DeadlineReached);
    assert!(
        harness.slept.len() < 5,
        "the wait must stop within the deadline budget, slept {:?}",
        harness.slept
    );
}

#[test]
fn loop_reports_cancellation_from_the_sleeper() {
    let mut harness = Loop::new(vec![
        Ok(pending(2)),
        Ok(pending(2)),
        Ok(granted("v4.public.tok")),
    ]);
    harness.stop_after_sleeps = Some(1);
    let err = harness.run(&policy(5), t(600)).expect_err("stopped");
    assert_eq!(err, WaitError::Stopped);
}

#[test]
fn loop_treats_undecodable_responses_as_terminal() {
    let mut harness = Loop::new(vec![Err(PollError::Decode(
        OutcomeDecodeError::MissingOutcome,
    ))]);
    let err = harness.run(&policy(5), t(600)).expect_err("decode stops");
    assert_eq!(err, WaitError::Decode(OutcomeDecodeError::MissingOutcome));
}
