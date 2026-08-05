//! Sans-I/O coverage for teardown decisions that are impractical to force
//! reliably through operating-system process APIs.

use firma_stack::test_support::teardown_policy::{
    GraceDecision, HardObservation, Harness, Presence, SettlementDecision,
};

const FIRST_ERROR: u8 = 1;
const SECOND_ERROR: u8 = 2;

/// A healthy graceful phase keeps polling while any target remains.
#[test]
fn graceful_teardown_polls_while_targets_remain() {
    let policy = Harness::new();

    assert_eq!(policy.decide_grace(false, false), GraceDecision::Poll);
}

/// Proven target absence authorizes cleanup before the graceful deadline.
#[test]
fn graceful_teardown_completes_when_targets_are_absent() {
    let policy = Harness::new();

    assert_eq!(policy.decide_grace(true, false), GraceDecision::Complete);
}

/// The graceful deadline forces escalation before another collection/probe pass.
#[test]
fn graceful_deadline_escalates_before_another_poll() {
    let policy = Harness::new();

    assert_eq!(policy.decide_grace(false, true), GraceDecision::Escalate);
}

/// Probe uncertainty is treated as possible presence and its first error is
/// retained through forced settlement.
#[test]
fn unknown_presence_escalates_and_retains_the_first_probe_error() {
    let mut policy = Harness::new();

    assert!(policy.target_may_exist(Presence::Unknown(FIRST_ERROR)));
    assert!(policy.target_may_exist(Presence::Unknown(SECOND_ERROR)));
    assert_eq!(policy.decide_grace(false, false), GraceDecision::Escalate);
    assert_eq!(
        policy.decide_settlement(true, false),
        SettlementDecision::Fail(FIRST_ERROR)
    );
}

/// Definite presence and absence do not manufacture teardown errors.
#[test]
fn known_presence_is_classified_without_changing_the_outcome() {
    let mut policy = Harness::new();

    assert!(policy.target_may_exist(Presence::Present));
    assert!(!policy.target_may_exist(Presence::Absent));
    assert_eq!(
        policy.decide_settlement(true, false),
        SettlementDecision::Complete { forced: false }
    );
}

/// An accepted hard request is reported when every target subsequently exits.
#[test]
fn accepted_hard_termination_marks_the_outcome_as_forced() {
    let mut policy = Harness::new();
    policy.observe_hard(HardObservation::Accepted);

    assert_eq!(
        policy.decide_settlement(true, false),
        SettlementDecision::Complete { forced: true }
    );
}

/// A hard-signal error is harmless when a follow-up probe proves the target
/// disappeared despite the delivery result.
#[test]
fn hard_termination_error_is_suppressed_after_confirmed_absence() {
    let mut policy = Harness::new();
    policy.observe_hard(HardObservation::FailedThenAbsent(FIRST_ERROR));

    assert_eq!(
        policy.decide_settlement(true, false),
        SettlementDecision::Complete { forced: false }
    );
}

/// An unsuppressed hard-signal error does not end settlement early, but it wins
/// once the settlement deadline expires.
#[test]
fn hard_termination_error_is_reported_only_after_settlement_expires() {
    let mut policy = Harness::new();
    policy.observe_hard(HardObservation::FailedStillPresent(FIRST_ERROR));

    assert_eq!(
        policy.decide_settlement(false, false),
        SettlementDecision::Poll
    );
    assert_eq!(
        policy.decide_settlement(false, true),
        SettlementDecision::Fail(FIRST_ERROR)
    );
}

/// A collection or probe error prevents eventual cleanup, but settlement still
/// runs until the target disappears or its deadline expires.
#[test]
fn teardown_error_does_not_end_settlement_before_the_deadline() {
    let mut policy = Harness::new();
    policy.observe_collection(Err(FIRST_ERROR));

    assert_eq!(
        policy.decide_settlement(false, false),
        SettlementDecision::Poll
    );
    assert_eq!(
        policy.decide_settlement(false, true),
        SettlementDecision::Fail(FIRST_ERROR)
    );
}

/// Aggregate absence proven at the settlement boundary suppresses an earlier
/// hard-signal failure while preserving an accepted forced request.
#[test]
fn absence_at_settlement_deadline_completes_and_ignores_hard_error() {
    let mut policy = Harness::new();
    policy.observe_hard(HardObservation::Accepted);
    policy.observe_hard(HardObservation::FailedStillPresent(FIRST_ERROR));

    assert_eq!(
        policy.decide_settlement(false, false),
        SettlementDecision::Poll
    );
    assert_eq!(
        policy.decide_settlement(true, true),
        SettlementDecision::Complete { forced: true }
    );
}

/// Collection and probe uncertainty share one first-error slot regardless of
/// which observation source fails first.
#[test]
fn first_teardown_error_wins_across_collection_and_probe_sources() {
    let mut collection_first = Harness::new();
    collection_first.observe_collection(Err(FIRST_ERROR));
    assert!(collection_first.target_may_exist(Presence::Unknown(SECOND_ERROR)));
    assert_eq!(
        collection_first.decide_settlement(false, true),
        SettlementDecision::Fail(FIRST_ERROR)
    );

    let mut probe_first = Harness::new();
    assert!(probe_first.target_may_exist(Presence::Unknown(FIRST_ERROR)));
    probe_first.observe_collection(Err(SECOND_ERROR));
    assert_eq!(
        probe_first.decide_settlement(false, true),
        SettlementDecision::Fail(FIRST_ERROR)
    );
}

/// Collection and probe errors take precedence over hard-signal errors because
/// they prevent teardown from proving that direct children were collected.
#[test]
fn collection_error_precedes_hard_termination_error() {
    let mut policy = Harness::new();
    policy.observe_hard(HardObservation::FailedStillPresent(SECOND_ERROR));
    policy.observe_collection(Err(FIRST_ERROR));

    assert_eq!(
        policy.decide_settlement(false, true),
        SettlementDecision::Fail(FIRST_ERROR)
    );
}

/// Expiry without a more specific teardown failure reports the bounded
/// settlement timeout.
#[test]
fn settlement_expiry_reports_timeout_without_an_earlier_error() {
    let mut policy = Harness::new();

    assert_eq!(
        policy.decide_settlement(false, true),
        SettlementDecision::Fail(Harness::TIMEOUT_ERROR)
    );
}
