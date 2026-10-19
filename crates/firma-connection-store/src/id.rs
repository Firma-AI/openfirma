//! The id that names a saved connection's native credential.

use std::fmt;

use crate::StoreError;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// A random 128-bit connection id, written as 32 lowercase hex digits. It
/// names the native credential of one saved connection.
pub struct ConnectionId(String);

impl ConnectionId {
    /// A new random id.
    pub fn generate() -> Result<Self, StoreError> {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|error| StoreError::Randomness(Box::new(error)))?;
        let mut id = String::with_capacity(32);
        for byte in bytes {
            id.push(char::from(HEX[usize::from(byte >> 4)]));
            id.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Ok(Self(id))
    }

    pub fn parse(value: String) -> Option<Self> {
        (value.len() == 32
            && value
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')))
        .then_some(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}
