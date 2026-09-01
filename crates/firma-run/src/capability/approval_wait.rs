//! Pure waiting policy for a capability issuance gated on human approval.
//!
//! When the Authority answers `PENDING_APPROVAL`, `firma run` polls
//! `GetApprovalOutcome` until the request is granted, denied, or expired.
//! This module owns every decision that polling loop has to make — how long
//! to wait, when to give up, how to read an outcome, how to classify a
//! failure — as pure functions over plain values, so all of it is testable
//! without a network or real time. The gRPC layer stays a humble mover of
//! messages: it converts wire values into the types below at the boundary
//! ([`OutcomeMessage`], [`RpcFailure`]) and nothing tonic- or prost-shaped
//! crosses past that point.
//!
//! Fail closed throughout: an unknown outcome, an unknown status code, or a
//! deadline reached all stop the wait without a token.

use std::time::Duration;

use chrono::{DateTime, Utc};
use firma_protobuf::v1::{GetApprovalOutcomeResponse, get_approval_outcome_response::Outcome};

/// Smallest delay the loop ever sleeps between polls.
///
/// Guards against a server advisory (or a jittered candidate) so short that
/// the loop would hammer the Authority.
pub const MIN_POLL_DELAY: Duration = Duration::from_secs(1);

/// Largest delay the loop ever sleeps between polls.
///
/// Bounds how stale the local view of the outcome can get, whatever the
/// server suggests or the backoff has grown to.
pub const MAX_POLL_DELAY: Duration = Duration::from_secs(30);

/// Default delay between polls when the server sends no advisory.
///
/// Mirrors the Authority's own default `retry_after` advisory, so an
/// unconfigured client polls at the pace the server would suggest anyway.
/// Lives here with [`MIN_POLL_DELAY`]/[`MAX_POLL_DELAY`] so the whole
/// delay family shares one home.
pub(crate) const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Fraction of the candidate delay used as the jitter amplitude (±20%).
const JITTER_AMPLITUDE: f64 = 0.2;

/// How long to keep polling for an approval outcome.
#[derive(Debug, Clone, Copy)]
pub struct ApprovalWaitPolicy {
    /// Delay between polls when the server sends no advisory `retry_after`.
    pub poll_interval: Duration,
    /// Optional local cap on the total wait. `None` waits until the
    /// server-side approval deadline; the deadline is always the earlier of
    /// the two (see [`ApprovalWaitPolicy::deadline`]).
    pub max_wait: Option<Duration>,
}

impl Default for ApprovalWaitPolicy {
    /// The unconfigured wait: server-paced polling, no local cap.
    fn default() -> Self {
        Self {
            poll_interval: DEFAULT_POLL_INTERVAL,
            max_wait: None,
        }
    }
}

impl ApprovalWaitPolicy {
    /// Resolves the effective wall-clock instant after which the wait stops.
    ///
    /// The server-side `approval_expiry` always bounds the wait; a
    /// configured `max_wait` can only shorten it, never extend past it.
    #[must_use]
    pub fn deadline(&self, now: DateTime<Utc>, approval_expiry: DateTime<Utc>) -> DateTime<Utc> {
        self.max_wait
            .and_then(|w| chrono::Duration::from_std(w).ok())
            .map_or(approval_expiry, |max_wait| {
                approval_expiry.min(now + max_wait)
            })
    }
}

/// The per-iteration randomness and backoff state fed into the schedule.
///
/// Sampled by the caller so the schedule itself stays deterministic. The
/// constructor sanitizes both fields, so a sample in hand is always valid:
/// the jitter unit is finite and within `[-1.0, 1.0]`, and the throttle
/// exponent counts consecutive `RESOURCE_EXHAUSTED` answers.
#[derive(Debug, Clone, Copy)]
pub struct BackoffSample {
    throttle_exponent: u32,
    jitter_unit: f64,
}

impl BackoffSample {
    /// Builds a sanitized sample.
    ///
    /// A non-finite `jitter_unit` becomes `0.0`; an out-of-range one is
    /// clamped into `[-1.0, 1.0]`. No further validation is ever needed
    /// downstream.
    #[must_use]
    pub fn new(throttle_exponent: u32, jitter_unit: f64) -> Self {
        let jitter_unit = if jitter_unit.is_finite() {
            jitter_unit.clamp(-1.0, 1.0)
        } else {
            0.0
        };
        Self {
            throttle_exponent,
            jitter_unit,
        }
    }
}

impl ApprovalWaitPolicy {
    /// Computes the next poll delay, or `None` when the wait must stop.
    ///
    /// The candidate is the server's advisory `retry_after` when present,
    /// this policy's `poll_interval` otherwise. It is then doubled once per
    /// unit of the sample's throttle exponent, spread by ±20% jitter, and
    /// clamped into [`MIN_POLL_DELAY`]..[`MAX_POLL_DELAY`] — the clamp
    /// applies after the jitter, so the bounds are hard.
    ///
    /// Returns `None` when the delay would land on or past `deadline`: the
    /// loop must not schedule a poll it already knows to be too late (fail
    /// closed — the caller reports the expiry instead of sleeping through
    /// it).
    #[must_use]
    pub fn next_delay(
        &self,
        server_retry_after: Option<Duration>,
        sample: BackoffSample,
        now: DateTime<Utc>,
        deadline: DateTime<Utc>,
    ) -> Option<Duration> {
        let base = server_retry_after.unwrap_or(self.poll_interval);
        // Saturating shift: a runaway exponent pins the candidate high and
        // the clamp below brings it back to MAX_POLL_DELAY. The extra `min`
        // bounds the candidate before the float jitter: a hostile advisory
        // near `Duration::MAX` would otherwise overflow `mul_f64` and
        // panic, and this module must never turn wire input into a crash.
        let doubled = base
            .saturating_mul(
                1_u32
                    .checked_shl(sample.throttle_exponent)
                    .unwrap_or(u32::MAX),
            )
            .min(MAX_POLL_DELAY.saturating_mul(2));
        let jittered = doubled.mul_f64(JITTER_AMPLITUDE.mul_add(sample.jitter_unit, 1.0));
        let delay = jittered.clamp(MIN_POLL_DELAY, MAX_POLL_DELAY);

        let delay_chrono = chrono::Duration::from_std(delay).ok()?;
        if now + delay_chrono >= deadline {
            return None;
        }
        Some(delay)
    }
}

/// A bearer token exactly as the Authority released it, not yet verified.
///
/// A newtype so the secret cannot leak through `Debug`: logging a decoded
/// outcome (or a failed assertion printing one) must never print the
/// credential. The inner string is released once, by consuming the wrapper.
#[derive(Clone, PartialEq, Eq)]
pub struct RawToken(String);

impl RawToken {
    /// Wraps a raw bearer token.
    #[must_use]
    pub fn new(token: String) -> Self {
        Self(token)
    }

    /// Consumes the wrapper, releasing the bearer for local verification.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl std::fmt::Debug for RawToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RawToken(<redacted>)")
    }
}

/// One step of the polling loop, as decided by the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollStep {
    /// Sleep this long, then poll again.
    Wait(Duration),
    /// The approval was granted; the raw PASETO token still needs local
    /// verification before anything touches disk.
    Granted {
        /// The bearer token exactly as the Authority released it.
        raw_token: RawToken,
    },
    /// An operator denied the request. Terminal, no token.
    Denied,
    /// The request expired before a decision. Terminal, no token.
    Expired,
}

/// An approval outcome, decoded from the wire into plain values.
///
/// The one place the generated protobuf response is interpreted; everything
/// past this type works on plain Rust values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutcomeMessage {
    /// Still waiting for a decision.
    Pending {
        /// Server-side deadline for the approval, when the server sent one.
        expires_at: Option<DateTime<Utc>>,
        /// Advisory poll delay suggested by the server.
        retry_after: Option<Duration>,
    },
    /// Granted: carries the raw bearer token, not yet verified.
    Granted {
        /// The bearer token exactly as the Authority released it.
        raw_token: RawToken,
    },
    /// Denied by an operator. Terminal.
    Denied,
    /// Expired before a decision. Terminal.
    Expired,
}

/// Reason a wire response could not be decoded into an [`OutcomeMessage`].
///
/// Every variant is terminal for the wait: a response this malformed means
/// the server and client disagree on the contract, and polling on would
/// only repeat the disagreement.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum OutcomeDecodeError {
    /// The response carried no outcome at all.
    #[error("approval outcome response carried no outcome")]
    MissingOutcome,
    /// A granted outcome carried no token.
    #[error("granted approval outcome carried no token")]
    MissingToken,
    /// The token bytes are not valid UTF-8.
    #[error("granted approval token is not valid UTF-8")]
    TokenNotUtf8,
}

impl TryFrom<GetApprovalOutcomeResponse> for OutcomeMessage {
    type Error = OutcomeDecodeError;

    fn try_from(response: GetApprovalOutcomeResponse) -> Result<Self, Self::Error> {
        let outcome = response.outcome.ok_or(OutcomeDecodeError::MissingOutcome)?;
        match outcome {
            Outcome::Pending(pending) => Ok(Self::Pending {
                // Negative nanos are malformed; drop the timestamp instead
                // of reinterpreting it as a different instant.
                expires_at: pending.expires_at.and_then(|t| {
                    u32::try_from(t.nanos)
                        .ok()
                        .and_then(|nanos| DateTime::from_timestamp(t.seconds, nanos))
                }),
                retry_after: pending.retry_after.and_then(|d| Duration::try_from(d).ok()),
            }),
            Outcome::Granted(granted) => {
                let token = granted.token.ok_or(OutcomeDecodeError::MissingToken)?;
                let raw_token = super::paseto_from_wire_token(token)
                    .map_err(|_| OutcomeDecodeError::TokenNotUtf8)?;
                Ok(Self::Granted {
                    raw_token: RawToken::new(raw_token),
                })
            }
            Outcome::Denied(_) => Ok(Self::Denied),
            Outcome::Expired(_) => Ok(Self::Expired),
        }
    }
}

/// A failed `GetApprovalOutcome` call, mirrored out of `tonic::Status` so
/// the policy never handles transport types directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcFailure {
    /// The status code, mirrored into an owned enumeration.
    pub kind: FailureKind,
    /// The status message, kept for diagnostics only — classification never
    /// depends on it.
    pub(crate) message: String,
}

impl RpcFailure {
    /// Wraps a transport-level failure (connect, TLS, timeout before any
    /// status arrived) that carries no gRPC status code.
    #[must_use]
    pub fn transport(message: impl Into<String>) -> Self {
        Self {
            kind: FailureKind::Transport,
            message: message.into(),
        }
    }
}

impl From<tonic::Status> for RpcFailure {
    fn from(status: tonic::Status) -> Self {
        let kind = match status.code() {
            tonic::Code::Unavailable => FailureKind::Unavailable,
            tonic::Code::DeadlineExceeded => FailureKind::DeadlineExceeded,
            tonic::Code::Cancelled => FailureKind::Cancelled,
            tonic::Code::ResourceExhausted => FailureKind::ResourceExhausted,
            tonic::Code::NotFound => FailureKind::NotFound,
            tonic::Code::InvalidArgument => FailureKind::InvalidArgument,
            tonic::Code::Unauthenticated => FailureKind::Unauthenticated,
            tonic::Code::FailedPrecondition => FailureKind::FailedPrecondition,
            tonic::Code::Internal => FailureKind::Internal,
            tonic::Code::Unimplemented => FailureKind::Unimplemented,
            _ => FailureKind::Other,
        };
        Self {
            kind,
            message: status.message().to_string(),
        }
    }
}

/// Status codes the waiting policy distinguishes, owned by this module.
///
/// `Other` absorbs every code not listed; [`FailureKind::class`] treats it as
/// permanent, so a code added to the protocol later fails closed here until
/// someone classifies it deliberately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FailureKind {
    /// Connect/TLS/timeout failure with no status code at all.
    Transport,
    /// `UNAVAILABLE`: the server or the path to it is down.
    Unavailable,
    /// `DEADLINE_EXCEEDED` of the single call, not of the approval.
    DeadlineExceeded,
    /// `CANCELLED` of the single call.
    Cancelled,
    /// `RESOURCE_EXHAUSTED`: rate limited; retry with a doubled delay.
    ResourceExhausted,
    /// `NOT_FOUND`: no approval for this identity — absence and binding
    /// mismatch are deliberately indistinguishable on the server.
    NotFound,
    /// `INVALID_ARGUMENT`: the request itself is malformed.
    InvalidArgument,
    /// `UNAUTHENTICATED`: the sidecar credentials were rejected.
    Unauthenticated,
    /// `FAILED_PRECONDITION`: the capability expired, was revoked, or its
    /// workspace went inactive.
    FailedPrecondition,
    /// `INTERNAL`: the server failed; retrying will not help this run.
    Internal,
    /// `UNIMPLEMENTED`: the Authority does not serve approval retrieval —
    /// an old server, or the Mini Authority.
    Unimplemented,
    /// Any status code not listed above.
    Other,
}

/// How the polling loop must react to a failed call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    /// Retry within the deadline with the regular backoff.
    Transient,
    /// Retry within the deadline, doubling the delay: the server is
    /// shedding load and asked for more room.
    Throttled,
    /// Stop immediately, no token. Includes every unknown code: a status
    /// this module has never heard of must never keep a wait loop alive.
    Permanent,
}

impl FailureKind {
    /// Classifies this failure into the loop's reaction.
    ///
    /// The match is exhaustive over [`FailureKind`] on purpose — adding a
    /// kind forces whoever adds it (in this crate; external matches need a
    /// wildcard, the enum being non-exhaustive) to decide its class here,
    /// instead of inheriting a silent default.
    #[must_use]
    pub fn class(self) -> FailureClass {
        match self {
            Self::Transport | Self::Unavailable | Self::DeadlineExceeded | Self::Cancelled => {
                FailureClass::Transient
            }
            Self::ResourceExhausted => FailureClass::Throttled,
            Self::NotFound
            | Self::InvalidArgument
            | Self::Unauthenticated
            | Self::FailedPrecondition
            | Self::Internal
            | Self::Unimplemented
            | Self::Other => FailureClass::Permanent,
        }
    }
}
