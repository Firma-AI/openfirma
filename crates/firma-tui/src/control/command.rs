//! Commands and side effects for Policy Control.

use crate::control::{announcement::ControlAnnouncement, app::App};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlCommand {
    Quit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlEffect {
    Announce(ControlAnnouncement),
}

impl ControlCommand {
    #[must_use]
    pub fn apply(self, _app: &mut App) -> Vec<ControlEffect> {
        match self {
            Self::Quit => vec![ControlEffect::Announce(
                ControlAnnouncement::ShutdownRequested,
            )],
        }
    }
}
