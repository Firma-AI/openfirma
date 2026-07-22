//! Runtime announcements for the control surface.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlAnnouncement {
    ShutdownRequested,
}
