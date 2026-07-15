//! Modal overlay state for Policy Control.
//!
//! Only one overlay is visible at a time. The app uses this state to decide
//! which key context and renderer are active, while the overlay renderers keep
//! their own layout details. Closing an overlay only affects the matching
//! overlay, so an unrelated close command cannot accidentally clear a newer
//! visible view.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Overlay {
    About,
    AuditInspect,
    Help,
}

#[derive(Debug, Default)]
pub struct OverlayState {
    visible: Option<Overlay>,
}

impl OverlayState {
    pub fn toggle_help(&mut self) {
        self.toggle(Overlay::Help);
    }

    pub fn close_help(&mut self) {
        self.close(Overlay::Help);
    }

    #[must_use]
    pub fn help_visible(&self) -> bool {
        self.visible == Some(Overlay::Help)
    }

    pub fn toggle_about(&mut self) {
        self.toggle(Overlay::About);
    }

    pub fn close_about(&mut self) {
        self.close(Overlay::About);
    }

    #[must_use]
    pub fn about_visible(&self) -> bool {
        self.visible == Some(Overlay::About)
    }

    pub fn open_audit_inspect(&mut self) {
        self.visible = Some(Overlay::AuditInspect);
    }

    pub fn close_audit_inspect(&mut self) {
        self.close(Overlay::AuditInspect);
    }

    #[must_use]
    pub fn audit_inspect_visible(&self) -> bool {
        self.visible == Some(Overlay::AuditInspect)
    }

    fn toggle(&mut self, overlay: Overlay) {
        self.visible = if self.visible == Some(overlay) {
            None
        } else {
            Some(overlay)
        };
    }

    fn close(&mut self, overlay: Overlay) {
        if self.visible == Some(overlay) {
            self.visible = None;
        }
    }
}
