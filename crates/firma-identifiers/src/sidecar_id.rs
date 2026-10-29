firma_type_id!(
    /// A Firma Team identifier for the one Sidecar of a run.
    ///
    /// Its canonical representation is an `sc` `TypeID` backed by an RFC 9562
    /// UUID v7.
    /// Team intentionally retains a separate identifier for its UUID-storage
    /// and convenience APIs, with the same wire format.
    SidecarId,
    SidecarIdType,
    SidecarIdParseError,
    "sc",
    "sidecar id",
    SortRand,
    type_safe_id::TypeSafeId::new()
);
