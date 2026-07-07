mod error;
mod files;
mod result;

#[cfg(test)]
mod tests;

pub use error::{GuestResultError, GuestResultResult};
pub use files::{
    GUEST_HEARTBEAT_FILE, GUEST_RESULT_FILE, GUEST_STDERR_FILE, GUEST_STDIN_FILE, GUEST_STDOUT_FILE,
};
pub use result::GuestResult;
