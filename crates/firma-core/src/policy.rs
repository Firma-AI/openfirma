/// Policy bundle containing Cedar policies and entity schema.
///
/// Created by the Authority when loading policies from disk, and distributed
/// to Sidecars via `WatchPolicyBundle` streaming. The `version` field is a
/// hex-encoded SHA-256 hash of the concatenated policy + schema bytes,
/// enabling cheap equality checks for deduplication.
#[derive(Debug, Clone)]
pub struct PolicyBundle {
    /// Bundle version identifier (hex SHA-256 of policies + schema).
    pub version: String,
    /// Raw Cedar policy source (concatenated `.cedar` files).
    pub policies: Vec<u8>,
    /// Raw Cedar entity schema bytes.
    pub entity_schema: Vec<u8>,
    /// Time-to-live in seconds. Sidecars enter fail-closed when stale.
    pub ttl_seconds: u32,
}

impl PolicyBundle {
    /// Create a new `PolicyBundle`.
    #[must_use]
    pub fn new(
        version: String,
        policies: Vec<u8>,
        entity_schema: Vec<u8>,
        ttl_seconds: u32,
    ) -> Self {
        Self {
            version,
            policies,
            entity_schema,
            ttl_seconds,
        }
    }
}
