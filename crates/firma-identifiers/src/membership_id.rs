firma_type_id!(
    /// A Firma-generated identifier for one Workspace Membership.
    ///
    /// Its canonical representation is a `mem` `TypeID` backed by an RFC 9562
    /// UUID v7, the same wire form the Firma Authority uses.
    MembershipId,
    MembershipIdType,
    MembershipIdParseError,
    "mem",
    "membership id",
    SortRand,
    type_safe_id::TypeSafeId::new()
);
