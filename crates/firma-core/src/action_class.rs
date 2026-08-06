//! Canonical action-class identifiers.
//!
//! Every `intent.action_class` in an `ExecutionEnvelope`, every capability
//! token `action_set` entry, and every Cedar action UID resolves to one of
//! these identifiers. The wire/config/PASETO surfaces are all string-based,
//! so [`ActionClass`] exists to give callers that construct those strings a
//! single, typo-proof source of truth via [`ActionClass::as_str`].
//!
//! The set mirrors the sidecar's runtime `ActionClassRegistry`; a drift test
//! there asserts the two stay in lockstep.

use std::str::FromStr;

/// Declares the [`ActionClass`] enum, its `ALL` slice, `as_str`, and
/// `FromStr` from one identifier↔string table so they cannot drift.
macro_rules! action_classes {
    ($($variant:ident => $name:literal),+ $(,)?) => {
        /// A canonical action class. Convert to its wire identifier with
        /// [`ActionClass::as_str`]; parse from one with `str::parse`.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum ActionClass {
            $(
                #[doc = concat!("`", $name, "`")]
                $variant,
            )+
        }

        impl ActionClass {
            /// Every canonical action class.
            pub const ALL: &'static [ActionClass] = &[$(ActionClass::$variant),+];

            /// The canonical string identifier (e.g. `communication.external.send`).
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(ActionClass::$variant => $name),+
                }
            }
        }

        impl Ord for ActionClass {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                self.as_str().cmp(other.as_str())
            }
        }

        impl PartialOrd for ActionClass {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl FromStr for ActionClass {
            type Err = UnknownActionClass;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($name => Ok(ActionClass::$variant),)+
                    other => Err(UnknownActionClass(other.to_string())),
                }
            }
        }
    };
}

/// Error returned when a string does not name a canonical [`ActionClass`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown action class: {0}")]
pub struct UnknownActionClass(pub String);

impl std::fmt::Display for ActionClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

action_classes! {
    AccountPermissionChange => "account.permission.change",
    BrowserPurchase => "browser.purchase",
    CalendarCreate => "calendar.create",
    CalendarDelete => "calendar.delete",
    CalendarRead => "calendar.read",
    CalendarUpdate => "calendar.update",
    CodeDestructive => "code.destructive",
    CodeMerge => "code.merge",
    CodeRead => "code.read",
    CodeReviewRead => "code.review.read",
    CodeReviewSubmit => "code.review.submit",
    CodeWrite => "code.write",
    CommunicationExternalDelete => "communication.external.delete",
    CommunicationExternalDraft => "communication.external.draft",
    CommunicationExternalFilter => "communication.external.filter",
    CommunicationExternalManage => "communication.external.manage",
    CommunicationExternalRead => "communication.external.read",
    CommunicationExternalSend => "communication.external.send",
    CommunicationInternalSend => "communication.internal.send",
    CredentialRead => "credential.read",
    CredentialWrite => "credential.write",
    CustomerRead => "customer.read",
    CustomerWrite => "customer.write",
    FilesystemDelete => "filesystem.delete",
    FilesystemRead => "filesystem.read",
    FilesystemWrite => "filesystem.write",
    IssueRead => "issue.read",
    IssueWrite => "issue.write",
    MemoryCrossNamespaceRead => "memory.cross_namespace.read",
    MemoryCrossNamespaceWrite => "memory.cross_namespace.write",
    NotificationManage => "notification.manage",
    PaymentCancel => "payment.cancel",
    PaymentCatalogWrite => "payment.catalog.write",
    PaymentDispute => "payment.dispute",
    PaymentMethodManage => "payment.method.manage",
    PaymentMethodSetup => "payment.method.setup",
    PaymentPayout => "payment.payout",
    PaymentPurchase => "payment.purchase",
    PaymentRead => "payment.read",
    PaymentRefund => "payment.refund",
    PaymentSubscription => "payment.subscription",
    PaymentTax => "payment.tax",
    PaymentTransfer => "payment.transfer",
    RepoAdmin => "repo.admin",
    RepoLifecycle => "repo.lifecycle",
    SecurityAlertRead => "security.alert.read",
    SystemExecute => "system.execute",
    SystemInstall => "system.install",
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_str_round_trips_through_from_str() {
        for class in ActionClass::ALL {
            let parsed: ActionClass = class.as_str().parse().expect("canonical name parses");
            assert_eq!(parsed, *class);
        }
    }

    #[test]
    fn unknown_string_is_rejected() {
        let err = "not.a.class".parse::<ActionClass>().unwrap_err();
        assert_eq!(err.to_string(), "unknown action class: not.a.class");
    }

    #[test]
    fn display_matches_as_str() {
        assert_eq!(
            ActionClass::CommunicationInternalSend.to_string(),
            "communication.internal.send"
        );
    }
}
