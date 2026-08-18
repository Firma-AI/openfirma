firma_type_id!(
    /// An opaque identifier assigned to one human-approval request.
    ///
    /// Its canonical representation is an `atok` `TypeID` backed by an RFC
    /// 9562 UUID v4.
    ApprovalTokenId,
    ApprovalTokenIdType,
    ApprovalTokenIdParseError,
    "atok",
    "approval token id",
    Random,
    type_safe_id::TypeSafeId::from_uuid(uuid::Uuid::new_v4())
);
