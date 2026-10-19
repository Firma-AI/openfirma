//! Version 1 of `connection.json`.
//!
//! Decoding reports where a file is invalid but never what it contains, and
//! reads a file secret straight into a [`SecretString`], which is wiped on
//! drop whether or not the rest of the record is valid.

use std::io;
use std::path::Path;

use firma_identifiers::{MembershipId, WorkspaceId};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

use crate::id::ConnectionId;
use crate::{Connection, OriginMode, StoreError};

const VERSION: u32 = 1;
/// Bounds memory used for a malformed or unexpectedly large record.
pub const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;

/// Counts serialized bytes without retaining a copy of the secret.
#[derive(Default)]
struct RecordSize {
    len: usize,
    exceeded: bool,
}

impl io::Write for RecordSize {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // Reserve one byte for the trailing newline.
        let Some(len) = self
            .len
            .checked_add(bytes.len())
            .filter(|len| *len < MAX_RECORD_BYTES)
        else {
            self.exceeded = true;
            return Err(io::Error::other("connection record size limit"));
        };
        self.len = len;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Writes into a fixed-size, zeroizing buffer without ever reallocating a
/// buffer that could already hold a secret.
struct RecordBuffer {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}

impl RecordBuffer {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Zeroizing::new(Vec::with_capacity(limit)),
            limit,
        }
    }
}

impl io::Write for RecordBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit - self.bytes.len() {
            return Err(io::Error::other(
                "connection record changed during encoding",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Where a decoded record keeps its secret.
pub enum StoredSecret {
    None,
    Native,
    File(SecretString),
}

/// A validated version 1 record.
pub struct Record {
    pub id: ConnectionId,
    pub connection: Connection,
    pub secret: StoredSecret,
}

/// The secret field as written; a file secret is borrowed only while the
/// record is serialized.
#[derive(Clone, Copy, Serialize)]
#[serde(tag = "backend", rename_all = "lowercase")]
pub enum SecretField<'a> {
    None,
    Native,
    File { value: &'a str },
}

#[derive(Serialize)]
struct RecordOut<'a> {
    version: u32,
    connection_id: &'a str,
    origin: &'a str,
    development_loopback: bool,
    workspace_id: &'a WorkspaceId,
    membership_id: &'a MembershipId,
    secret: SecretField<'a>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordIn {
    version: u32,
    connection_id: String,
    origin: String,
    development_loopback: bool,
    workspace_id: WorkspaceId,
    membership_id: MembershipId,
    secret: SecretFieldIn,
}

#[derive(Deserialize)]
#[serde(tag = "backend", rename_all = "lowercase", deny_unknown_fields)]
enum SecretFieldIn {
    None,
    Native,
    File { value: SecretString },
}

/// Serializes a record into a buffer that is wiped on drop.
pub fn encode(
    id: &ConnectionId,
    connection: &Connection,
    secret: SecretField<'_>,
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let record = RecordOut {
        version: VERSION,
        connection_id: id.as_str(),
        origin: connection.origin.as_str(),
        development_loopback: connection.origin_mode == OriginMode::DevelopmentLoopback,
        workspace_id: &connection.workspace_id,
        membership_id: &connection.membership_id,
        secret,
    };
    let mut size = RecordSize::default();
    if let Err(error) = serde_json::to_writer_pretty(&mut size, &record) {
        return if size.exceeded {
            Err(StoreError::RecordTooLarge)
        } else {
            Err(StoreError::Encode(Box::new(error)))
        };
    }
    let mut buffer = RecordBuffer::new(size.len + 1);
    serde_json::to_writer_pretty(&mut buffer, &record)
        .map_err(|error| StoreError::Encode(Box::new(error)))?;
    buffer.bytes.push(b'\n');
    Ok(buffer.bytes)
}

/// Parses and validates a version 1 record read from `path`.
pub fn decode(path: &Path, bytes: &[u8]) -> Result<Record, StoreError> {
    // serde_json errors can quote the offending value; report only where.
    let record: RecordIn = serde_json::from_slice(bytes).map_err(|error| {
        corrupt(
            path,
            format!(
                "invalid JSON at line {}, column {}",
                error.line(),
                error.column()
            ),
        )
    })?;
    validate(path, record)
}

fn corrupt(path: &Path, reason: String) -> StoreError {
    StoreError::CorruptConnection {
        path: path.to_path_buf(),
        reason,
    }
}

/// Validates parsed fields only after serde has accepted the record shape.
fn validate(path: &Path, record: RecordIn) -> Result<Record, StoreError> {
    if record.version != VERSION {
        return Err(corrupt(
            path,
            format!("unsupported version {}", record.version),
        ));
    }
    let secret = decode_secret(record.secret)?;
    let id = ConnectionId::parse(record.connection_id)
        .ok_or_else(|| corrupt(path, "invalid connection id".to_owned()))?;
    let origin =
        Url::parse(&record.origin).map_err(|_| corrupt(path, "invalid origin".to_owned()))?;
    Ok(Record {
        id,
        connection: Connection {
            origin,
            origin_mode: if record.development_loopback {
                OriginMode::DevelopmentLoopback
            } else {
                OriginMode::Production
            },
            workspace_id: record.workspace_id,
            membership_id: record.membership_id,
        },
        secret,
    })
}

fn decode_secret(secret: SecretFieldIn) -> Result<StoredSecret, StoreError> {
    let secret = match secret {
        SecretFieldIn::None => StoredSecret::None,
        SecretFieldIn::Native => StoredSecret::Native,
        SecretFieldIn::File { value } if cfg!(unix) => StoredSecret::File(value),
        SecretFieldIn::File { .. } => return Err(StoreError::PlaintextFileUnsupported),
    };
    Ok(secret)
}
