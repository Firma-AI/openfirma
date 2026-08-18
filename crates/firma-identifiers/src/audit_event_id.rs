firma_type_id!(
    /// A time-ordered identifier assigned to one emitted audit event.
    ///
    /// Its canonical representation is an `aevt` `TypeID` backed by an RFC
    /// 9562 UUID v7.
    AuditEventId,
    AuditEventIdType,
    AuditEventIdParseError,
    "aevt",
    "audit event id",
    SortRand,
    type_safe_id::TypeSafeId::new()
);
