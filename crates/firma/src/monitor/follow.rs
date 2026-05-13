//! Pure follow-mode resolver for `firma monitor`.
//!
//! The CLI exposes two override flags (`--tail`, `--no-follow`) and an
//! auto behavior that follows the file when stdout is a TTY and reads
//! once when stdout is piped. This module keeps the decision logic in
//! a pure function so the service layer remains a thin shell that
//! reads `std::io::stdout().is_terminal()` once.

/// Decide whether the tailer should follow the file after EOF.
///
/// Precedence:
/// 1. `--tail` always wins (force-follow, useful when piping into
///    `tee` while still wanting to follow).
/// 2. `--no-follow` forces a one-shot read.
/// 3. Otherwise: auto-tail when stdout is a TTY.
#[must_use]
pub fn resolve_follow(tail: bool, no_follow: bool, is_tty: bool) -> bool {
    match (tail, no_follow) {
        (true, _) => true,
        (false, true) => false,
        (false, false) => is_tty,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_flag_forces_follow_regardless_of_tty() {
        assert!(resolve_follow(true, false, false));
        assert!(resolve_follow(true, false, true));
    }

    #[test]
    fn no_follow_flag_forces_one_shot_regardless_of_tty() {
        assert!(!resolve_follow(false, true, false));
        assert!(!resolve_follow(false, true, true));
    }

    #[test]
    fn auto_follows_when_tty() {
        assert!(resolve_follow(false, false, true));
    }

    #[test]
    fn auto_one_shot_when_piped() {
        assert!(!resolve_follow(false, false, false));
    }
}
