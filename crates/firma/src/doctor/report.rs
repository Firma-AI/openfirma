//! Report data model for `firma doctor`.

use std::collections::BTreeMap;

use serde::Serialize;

/// Severity of a single check.
///
/// `Ord` puts `Ok < Warn < Fail` so a `Report` can compute its worst-case
/// status by `iter().max()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Check passed.
    Ok,
    /// Check produced a non-fatal warning.
    Warn,
    /// Check failed.
    Fail,
}

/// Single check result.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    /// Human-readable category label (e.g. `"firma binary"`).
    pub category: &'static str,
    /// Status.
    pub status: Status,
    /// One-line reason / value.
    pub reason: String,
    /// Optional structured detail for the JSON output. Sorted by key.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub detail: BTreeMap<String, String>,
}

impl Check {
    /// Create a check with [`Status::Ok`].
    #[must_use]
    pub fn ok(category: &'static str, reason: impl Into<String>) -> Self {
        Self::new(category, Status::Ok, reason)
    }

    /// Create a check with [`Status::Warn`].
    #[must_use]
    pub fn warn(category: &'static str, reason: impl Into<String>) -> Self {
        Self::new(category, Status::Warn, reason)
    }

    /// Create a check with [`Status::Fail`].
    #[must_use]
    pub fn fail(category: &'static str, reason: impl Into<String>) -> Self {
        Self::new(category, Status::Fail, reason)
    }

    fn new(category: &'static str, status: Status, reason: impl Into<String>) -> Self {
        Self {
            category,
            status,
            reason: reason.into(),
            detail: BTreeMap::new(),
        }
    }

    /// Attach a structured detail entry. Entries are stored in `BTreeMap`
    /// order (sorted by key).
    #[must_use]
    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.detail.insert(key.into(), value.into());
        self
    }
}

/// Aggregate doctor report.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Report {
    /// All checks collected during the diagnostic run.
    pub checks: Vec<Check>,
}

impl Report {
    /// Append one check.
    pub fn push(&mut self, check: Check) {
        self.checks.push(check);
    }

    /// Append many checks.
    pub fn extend(&mut self, checks: impl IntoIterator<Item = Check>) {
        self.checks.extend(checks);
    }

    /// Worst status across all checks. Returns `None` when the report is empty.
    #[must_use]
    pub fn worst(&self) -> Option<Status> {
        self.checks.iter().map(|c| c.status).max()
    }

    /// Process exit code: `0` if all checks are `Ok` or `Warn`, `1` if any
    /// check is `Fail`.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self.worst() {
            Some(Status::Fail) => 1,
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_orders_ok_before_warn_before_fail() {
        assert!(Status::Ok < Status::Warn);
        assert!(Status::Warn < Status::Fail);
    }

    #[test]
    fn check_new_ok_sets_status_and_reason() {
        let c = Check::ok("firma binary", "/usr/local/bin/firma (v0.1.0)");
        assert_eq!(c.category, "firma binary");
        assert_eq!(c.status, Status::Ok);
        assert_eq!(c.reason, "/usr/local/bin/firma (v0.1.0)");
        assert!(c.detail.is_empty());
    }

    #[test]
    fn check_with_detail_records_key_value() {
        let c = Check::ok("authority reachable", "127.0.0.1:50051")
            .with_detail("address", "127.0.0.1:50051")
            .with_detail("latency_us", "1200");
        assert_eq!(
            c.detail.get("address").map(String::as_str),
            Some("127.0.0.1:50051")
        );
        assert_eq!(c.detail.get("latency_us").map(String::as_str), Some("1200"));
    }

    #[test]
    fn report_classify_returns_zero_when_all_ok_or_warn() {
        let r = Report {
            checks: vec![Check::ok("a", "fine"), Check::warn("b", "not configured")],
        };
        assert_eq!(r.exit_code(), 0);
    }

    #[test]
    fn report_classify_returns_one_on_any_fail() {
        let r = Report {
            checks: vec![Check::ok("a", "fine"), Check::fail("b", "boom")],
        };
        assert_eq!(r.exit_code(), 1);
    }
}
